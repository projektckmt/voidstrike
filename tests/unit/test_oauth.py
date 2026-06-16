"""OAuth scaffolding tests."""

from __future__ import annotations

import os

import pytest

from src.auth.oauth import _pkce_pair, build_authorization_url


def test_pkce_pair_shape() -> None:
    verifier, challenge = _pkce_pair()
    # 43 chars per RFC 7636 with 32 bytes of randomness, base64url no-padding.
    assert len(verifier) == 43
    assert len(challenge) == 43


def test_build_authorization_url(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_OAUTH_CLIENT_ID", "test-client")
    req = build_authorization_url("anthropic", "http://localhost:8000/callback")
    assert "code_challenge=" in req.url
    assert "client_id=test-client" in req.url
    assert req.state
    assert req.code_verifier


def test_missing_client_id_raises(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_OAUTH_CLIENT_ID", raising=False)
    with pytest.raises(RuntimeError):
        build_authorization_url("anthropic", "http://x/cb")
