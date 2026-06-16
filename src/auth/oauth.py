"""OAuth flow scaffolding for model provider subscriptions.

Phase 4: so users don't need raw API keys, we support OAuth login
to Claude / ChatGPT / Gemini and use their consumer subscription. The PKCE
flow runs out-of-band: gateway redirects, browser authorizes, gateway
exchanges the code for a token, token is encrypted-at-rest in Postgres.

This is scaffolding — the provider-specific endpoints are placeholders. Each
provider's real OAuth URLs/scopes will be wired in when integrating against
their actual SDKs.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Literal

Provider = Literal["anthropic", "openai", "google"]


@dataclass
class ProviderConfig:
    """OAuth endpoints + scopes per provider.

    Real URLs depend on each provider's published OAuth product (which differ
    from their API auth). Treat the values here as placeholders — wire the
    real ones during integration. The shape of the flow doesn't change.
    """
    authorize_url: str
    token_url: str
    scopes: list[str]
    client_id_env: str


PROVIDERS: dict[Provider, ProviderConfig] = {
    "anthropic": ProviderConfig(
        authorize_url="https://auth.anthropic.com/oauth/authorize",
        token_url="https://auth.anthropic.com/oauth/token",
        scopes=["claude.messages"],
        client_id_env="ANTHROPIC_OAUTH_CLIENT_ID",
    ),
    "openai": ProviderConfig(
        authorize_url="https://auth.openai.com/oauth/authorize",
        token_url="https://auth.openai.com/oauth/token",
        scopes=["chatgpt.messages"],
        client_id_env="OPENAI_OAUTH_CLIENT_ID",
    ),
    "google": ProviderConfig(
        authorize_url="https://accounts.google.com/o/oauth2/v2/auth",
        token_url="https://oauth2.googleapis.com/token",
        scopes=["https://www.googleapis.com/auth/generative-language"],
        client_id_env="GOOGLE_OAUTH_CLIENT_ID",
    ),
}


@dataclass
class AuthorizationRequest:
    url: str
    state: str
    code_verifier: str


def _pkce_pair() -> tuple[str, str]:
    """Return `(verifier, challenge)` for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def build_authorization_url(
    provider: Provider,
    redirect_uri: str,
) -> AuthorizationRequest:
    """Build the URL the user opens in a browser to authorize.

    Returns the URL plus the `state` and `code_verifier` the gateway needs to
    remember (in Redis) to validate the callback and exchange the code.
    """
    cfg = PROVIDERS[provider]
    client_id = os.environ.get(cfg.client_id_env)
    if not client_id:
        raise RuntimeError(f"missing {cfg.client_id_env} in env")

    state = secrets.token_urlsafe(24)
    verifier, challenge = _pkce_pair()

    from urllib.parse import urlencode
    params = urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(cfg.scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })
    return AuthorizationRequest(
        url=f"{cfg.authorize_url}?{params}",
        state=state,
        code_verifier=verifier,
    )


async def exchange_code_for_token(
    provider: Provider,
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> dict:
    """Trade the authorization code for an access/refresh token."""
    import httpx

    cfg = PROVIDERS[provider]
    client_id = os.environ.get(cfg.client_id_env)
    if not client_id:
        raise RuntimeError(f"missing {cfg.client_id_env}")

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            cfg.token_url,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": code_verifier,
            },
        )
    resp.raise_for_status()
    return resp.json()


async def refresh_access_token(
    provider: Provider,
    refresh_token: str,
) -> dict:
    """Use a refresh token to mint a new access token."""
    import httpx

    cfg = PROVIDERS[provider]
    client_id = os.environ.get(cfg.client_id_env)
    if not client_id:
        raise RuntimeError(f"missing {cfg.client_id_env}")

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            cfg.token_url,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            },
        )
    resp.raise_for_status()
    return resp.json()
