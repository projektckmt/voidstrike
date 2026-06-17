"""HackTheBox API v4 client — machine spawn / reset / teardown / flag submit.

Used by the challenge runner ([`src/agent/challenge.py`](.)) to provision a target
before an engagement and tear it down after, so a run (or a benchmark sweep) is
unattended end-to-end instead of requiring a human to spawn/reset boxes in the
HTB panel.

ENDPOINTS ARE NOT YET VERIFIED against the official doc
(https://documenter.getpostman.com/view/13129365/TVeqbmeq) — they're the
documented v4 routes to the best of our knowledge. All of them are isolated in
the `_EP` table and the per-class spawn/reset/terminate adapters below, so
correcting a path or body is a one-place change. The lifecycle logic and tests
do not depend on the exact strings.

Auth: an HTB **App Token** (account settings → "App Tokens"), passed as
`Authorization: Bearer <token>`. HTB rejects requests without a real
`User-Agent`, so we always set one.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from typing import Any

import httpx

# Base URL — HTB migrated to labs.hackthebox.com/api/v4 (older: www.hackthebox.com).
# Override with HTB_API_BASE if the doc says otherwise.
_DEFAULT_BASE = "https://labs.hackthebox.com/api/v4"

# HTB 403s a missing/blank User-Agent. Any plausible UA works.
_USER_AGENT = "voidstrike/0.1 (+https://github.com)"

# Endpoint table. Most live under the v4 base; a few have moved to v5 (HTB
# removed v4/machine/own). `_OWN_API_VERSION` overrides the version for `own`.
_EP = {
    "machine_profile": "/machine/profile/{name}",   # GET — resolve name -> id/type
    "active": "/machine/active",                     # GET — currently-spawned machine + IP
    "spawn": "/vm/spawn",                            # POST {machine_id}
    "reset": "/vm/reset",                            # POST {machine_id}
    "terminate": "/vm/terminate",                    # POST {machine_id}
    "own": "/machine/own",                           # POST {id, flag, difficulty} — v5 only
}

# HTB removed /api/v4/machine/own; flag submission must hit v5.
_OWN_API_VERSION = 5


class HtbError(RuntimeError):
    """An HTB API call failed. `status` is the HTTP code (0 for transport errors);
    `message` is HTB's own message where we could extract one."""

    def __init__(self, message: str, *, status: int = 0, payload: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.payload = payload


@dataclass
class Machine:
    """Resolved machine identity."""
    id: int
    name: str
    # active | retired | release | starting_point | unknown — picks the spawn adapter.
    kind: str = "active"
    ip: str | None = None


def _extract_message(body: Any, default: str) -> str:
    """HTB error bodies vary: {"message": ...} | {"error": ...} | plain text."""
    if isinstance(body, dict):
        for k in ("message", "error", "detail"):
            v = body.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
    if isinstance(body, str) and body.strip():
        return body.strip()[:300]
    return default


class HtbClient:
    """Thin async HTB API client. Construct with a token (or `HTB_TOKEN` env).

    Inject `client=` (an `httpx.AsyncClient`) in tests; otherwise one is built
    lazily and closed by `aclose()` / the async context manager.
    """

    def __init__(
        self,
        token: str | None = None,
        *,
        base_url: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._token = token or os.environ.get("HTB_TOKEN", "")
        if not self._token:
            raise HtbError("no HTB token — set HTB_TOKEN or pass token=")
        self._base = (base_url or os.environ.get("HTB_API_BASE") or _DEFAULT_BASE).rstrip("/")
        self._timeout = timeout
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> HtbClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    def _base_for(self, version: int | None) -> str:
        """The API base, optionally pinned to a different `/api/vN` (e.g. `own`
        moved to v5). Falls back to the configured base if there's no version
        segment to swap."""
        if version is None:
            return self._base
        swapped = re.sub(r"/api/v\d+", f"/api/v{version}", self._base)
        return swapped if swapped != self._base else self._base

    async def _request(self, method: str, path: str, *, version: int | None = None, **kw: Any) -> Any:
        url = f"{self._base_for(version)}{path}"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "User-Agent": _USER_AGENT,
            "Accept": "application/json",
        }
        try:
            resp = await self._http().request(method, url, headers=headers, **kw)
        except httpx.HTTPError as exc:  # transport-level
            raise HtbError(f"HTB request failed: {exc}", status=0) from exc
        # Decode body (HTB usually returns JSON; tolerate text).
        try:
            body: Any = resp.json()
        except ValueError:
            body = resp.text
        if resp.status_code == 429:
            raise HtbError(
                _extract_message(body, "rate limited by HTB (cooldown active)"),
                status=429, payload=body,
            )
        if resp.status_code >= 400:
            raise HtbError(
                _extract_message(body, f"HTB returned {resp.status_code}"),
                status=resp.status_code, payload=body,
            )
        return body

    # --- machine identity ---------------------------------------------------

    async def resolve_machine(self, name_or_id: str | int) -> Machine:
        """Resolve a machine name (or id) to a `Machine` (id + kind).

        The profile endpoint accepts a name or id; we read id, name, and the
        retired/release flags to pick the right spawn adapter."""
        body = await self._request("GET", _EP["machine_profile"].format(name=name_or_id))
        info = body.get("info", body) if isinstance(body, dict) else {}
        if not isinstance(info, dict) or "id" not in info:
            raise HtbError(f"could not resolve HTB machine {name_or_id!r}", payload=body)
        return Machine(
            id=int(info["id"]),
            name=str(info.get("name", name_or_id)),
            kind=_classify(info),
            ip=info.get("ip"),
        )

    async def active_machine(self) -> Machine | None:
        """The machine currently spawned on your account, if any (with its IP
        once provisioning finishes)."""
        body = await self._request("GET", _EP["active"])
        info = body.get("info") if isinstance(body, dict) else None
        if not info:
            return None
        return Machine(
            id=int(info["id"]),
            name=str(info.get("name", "")),
            kind=_classify(info),
            ip=info.get("ip"),
        )

    # --- lifecycle ops ------------------------------------------------------

    async def spawn(self, machine: Machine) -> None:
        """Request a spawn. The IP is NOT ready immediately — call
        `wait_for_ip()` after. Spawn endpoint/body can differ by machine class
        (`_spawn_path`)."""
        path, payload = _spawn_request(machine)
        await self._request("POST", path, json=payload)

    async def reset(self, machine: Machine) -> None:
        await self._request("POST", _EP["reset"], json={"machine_id": machine.id})

    async def terminate(self, machine: Machine) -> None:
        await self._request("POST", _EP["terminate"], json={"machine_id": machine.id})

    async def submit_flag(self, machine: Machine, flag: str, *, difficulty: int = 5) -> Any:
        """Submit a captured flag (`own`). `difficulty` is 1..10 (HTB requires a
        rating). Returns HTB's response (e.g. confirmation message)."""
        return await self._request(
            "POST", _EP["own"],
            json={"id": machine.id, "flag": flag, "difficulty": difficulty},
            version=_OWN_API_VERSION,  # v4/machine/own was removed
        )

    async def wait_for_ip(
        self, machine: Machine, *, timeout_s: float = 180.0, interval_s: float = 6.0
    ) -> str:
        """Poll the active-machine endpoint until the target has an IP, or raise
        on timeout. Returns the IP (also stored on `machine.ip`)."""
        deadline = asyncio.get_event_loop().time() + timeout_s
        while True:
            active = await self.active_machine()
            if active and active.id == machine.id and active.ip:
                machine.ip = active.ip
                return active.ip
            if asyncio.get_event_loop().time() >= deadline:
                raise HtbError(
                    f"machine {machine.name!r} did not get an IP within {int(timeout_s)}s",
                    payload={"active": active.__dict__ if active else None},
                )
            await asyncio.sleep(interval_s)


def _classify(info: dict[str, Any]) -> str:
    """Best-effort machine-class detection from a profile/active payload.

    Drives which spawn endpoint to use. VERIFY the flag names against the doc —
    HTB has used `retired`, `release` / `is_release`, `sp_flag` (starting point)."""
    if info.get("retired"):
        return "retired"
    if info.get("is_release") or info.get("release"):
        return "release"
    if info.get("sp_flag") or info.get("starting_point"):
        return "starting_point"
    return "active"


def _spawn_request(machine: Machine) -> tuple[str, dict[str, Any]]:
    """Return (path, json_body) for spawning, per machine class.

    Currently every class routes through `/vm/spawn {machine_id}`; the release
    arena / starting point may use a different route — split here when confirmed
    against the doc, without touching the lifecycle code."""
    return _EP["spawn"], {"machine_id": machine.id}
