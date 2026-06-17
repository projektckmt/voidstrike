"""Tests for the HTB API client (mocked transport — no live calls).

Pins request shapes (method/path/body/auth header), response parsing, error
mapping (429 cooldown, 4xx), and the spawn IP-polling loop. The exact endpoint
paths are isolated in `htb._EP`; these tests assert behaviour, so correcting a
path later won't churn them.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from src.integrations.htb import HtbClient, HtbError, Machine


def _run(coro):
    return asyncio.run(coro)


def _client(handler) -> HtbClient:
    transport = httpx.MockTransport(handler)
    return HtbClient(token="tok", client=httpx.AsyncClient(transport=transport))


def test_requires_token(monkeypatch):
    monkeypatch.delenv("HTB_TOKEN", raising=False)
    with pytest.raises(HtbError):
        HtbClient(token="")


def test_resolve_machine_and_auth_header():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["auth"] = req.headers.get("authorization")
        seen["ua"] = req.headers.get("user-agent")
        seen["path"] = req.url.path
        return httpx.Response(200, json={"info": {"id": 543, "name": "Support", "retired": True}})

    m = _run(_client(handler).resolve_machine("Support"))
    assert m.id == 543 and m.name == "Support" and m.kind == "retired"
    assert seen["auth"] == "Bearer tok"
    assert seen["ua"]                       # a non-empty UA is always sent
    assert seen["path"].endswith("/Support")


def test_active_machine_none_when_empty():
    def handler(req):
        return httpx.Response(200, json={"info": None})
    assert _run(_client(handler).active_machine()) is None


def test_spawn_posts_machine_id():
    seen = {}

    def handler(req):
        seen["method"] = req.method
        seen["path"] = req.url.path
        seen["body"] = req.read().decode()
        return httpx.Response(200, json={"message": "spawning"})

    _run(_client(handler).spawn(Machine(id=99, name="X")))
    assert seen["method"] == "POST"
    assert "/spawn" in seen["path"]
    assert json.loads(seen["body"]) == {"machine_id": 99}


def test_submit_flag_body_and_uses_v5():
    seen = {}

    def handler(req):
        seen["body"] = req.read().decode()
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"message": "owned"})

    _run(_client(handler).submit_flag(Machine(id=7, name="X"), "abc123", difficulty=4))
    assert json.loads(seen["body"]) == {"id": 7, "flag": "abc123", "difficulty": 4}
    # HTB removed v4/machine/own — submission must hit v5.
    assert "/api/v5/machine/own" in seen["url"]


def test_other_endpoints_stay_on_v4():
    seen = {}

    def handler(req):
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"message": "ok"})

    _run(_client(handler).reset(Machine(id=1, name="X")))
    assert "/api/v4/vm/reset" in seen["url"]


def test_429_maps_to_cooldown_error():
    def handler(req):
        return httpx.Response(429, json={"message": "You can reset in 5 minutes"})
    with pytest.raises(HtbError) as ei:
        _run(_client(handler).reset(Machine(id=1, name="X")))
    assert ei.value.status == 429
    assert "5 minutes" in str(ei.value)


def test_4xx_extracts_htb_message():
    def handler(req):
        return httpx.Response(401, json={"message": "Unauthenticated."})
    with pytest.raises(HtbError) as ei:
        _run(_client(handler).active_machine())
    assert ei.value.status == 401
    assert "Unauthenticated" in str(ei.value)


def test_transport_error_wrapped():
    def handler(req):
        raise httpx.ConnectError("boom")
    with pytest.raises(HtbError) as ei:
        _run(_client(handler).active_machine())
    assert ei.value.status == 0


def test_wait_for_ip_polls_until_ready():
    calls = {"n": 0}

    def handler(req):
        # /machine/active returns no IP on the first poll, an IP on the second.
        calls["n"] += 1
        ip = None if calls["n"] < 2 else "10.10.10.5"
        return httpx.Response(200, json={"info": {"id": 42, "name": "X", "ip": ip}})

    m = Machine(id=42, name="X")
    ip = _run(_client(handler).wait_for_ip(m, timeout_s=5, interval_s=0))
    assert ip == "10.10.10.5"
    assert m.ip == "10.10.10.5"
    assert calls["n"] >= 2


def test_wait_for_ip_times_out():
    def handler(req):
        return httpx.Response(200, json={"info": {"id": 42, "name": "X", "ip": None}})
    with pytest.raises(HtbError):
        _run(_client(handler).wait_for_ip(Machine(id=42, name="X"), timeout_s=0.01, interval_s=0))
