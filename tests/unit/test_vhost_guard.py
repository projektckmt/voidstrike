"""Tests for the vhost-enumeration guard.

Reproduces the debug9 failure: the front page is a static decoy, the box is a
wildcard responder (every unknown Host returns the same page), and the surface
agent re-ran `surface__vhost_enum` 5× with ever-larger DNS wordlists getting
only empty/wildcard results. The guard must cut that loop after a couple of
unproductive results and tell the agent to pivot to context-derived Host probes.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from src.agent.middleware.vhost_guard import _host_of, _is_unproductive, vhost_guard


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name: str, args: dict, call_id: str = "c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": args, "id": call_id},
    )


def _handler(payload: dict):
    calls: list[dict] = []

    async def handler(request):
        calls.append(request.tool_call["args"])
        return SimpleNamespace(
            content=json.dumps(payload), name=request.tool.name, status="success"
        )

    return handler, calls


# Exact shapes from the debug9 run.
EMPTY = {"ok": True, "results": [], "total_matches": 0, "truncated": False,
         "hint": "No vhost responded differently from the wildcard. ..."}
REAL = {"ok": True, "results": [{"fuzz": "ftp", "url": "http://ftp.t.htb/", "status": 200}],
        "total_matches": 1}


# --- helpers ---------------------------------------------------------------

def test_host_of_groups_by_netloc() -> None:
    assert _host_of("http://wingdata.htb/") == "wingdata.htb"
    assert _host_of("http://10.0.0.1/") == "10.0.0.1"


def test_is_unproductive_detects_empty_and_wildcard() -> None:
    assert _is_unproductive(json.dumps(EMPTY)) is True
    assert _is_unproductive(json.dumps({"ok": True, "results": [], "hint": ""})) is True
    assert _is_unproductive(json.dumps(REAL)) is False


# --- middleware behaviour --------------------------------------------------

def test_guard_blocks_after_two_unproductive_results() -> None:
    guard = vhost_guard(max_unproductive=2)
    handler, calls = _handler(EMPTY)
    req = _request("surface__vhost_enum", {"base_url": "http://wingdata.htb/"})

    # First two empties reach the handler and accrue the count.
    for _ in range(2):
        res = _run(guard.awrap_tool_call(req, handler))
        assert res.status == "success"
    assert len(calls) == 2

    # The third is blocked BEFORE the handler — directive, not a real run.
    blocked = _run(guard.awrap_tool_call(req, handler))
    assert len(calls) == 2  # handler not called again
    assert blocked.status == "error"
    assert "VHOST_ENUM_UNPRODUCTIVE" in blocked.content
    assert "ftp.wingdata.htb" in blocked.content  # context-pivot suggestion


def test_guard_does_not_block_on_real_finds() -> None:
    guard = vhost_guard(max_unproductive=2)
    handler, calls = _handler(REAL)
    req = _request("surface__vhost_enum", {"base_url": "http://wingdata.htb/"})
    for _ in range(5):
        res = _run(guard.awrap_tool_call(req, handler))
        assert res.status == "success"
    assert len(calls) == 5  # productive results never accumulate → never blocked


def test_guard_ignores_other_tools() -> None:
    guard = vhost_guard(max_unproductive=1)
    handler, calls = _handler(EMPTY)
    req = _request("surface__ffuf", {"url": "http://wingdata.htb/FUZZ"})
    for _ in range(3):
        _run(guard.awrap_tool_call(req, handler))
    assert len(calls) == 3  # ffuf is fuzz_guard's job, not this one
