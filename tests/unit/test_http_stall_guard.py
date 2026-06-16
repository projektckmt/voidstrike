"""Tests for capping repeated semantic HTTP stalls."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from src.agent.middleware.http_stall_guard import (
    _http_outcome_signature,
    http_stall_guard,
)


def _run(coro):
    return asyncio.run(coro)


def _request(args: dict, call_id: str = "c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name="shell__http_json_request"),
        tool_call={"args": args, "id": call_id},
    )


def test_signature_groups_same_path_status_and_body() -> None:
    args = {"method": "POST", "url": "http://host/api/v1/auth/login?x=1"}
    payload = {
        "ok": True,
        "status_code": 500,
        "body": '{"message":"SQLITE_BUSY: database is locked"}',
    }

    sig = _http_outcome_signature(args, payload)

    assert sig is not None
    assert "POST /api/v1/auth/login::500" in sig


def test_signature_ignores_successful_http_results() -> None:
    args = {"method": "POST", "url": "http://host/api/v1/auth/login"}
    payload = {"ok": True, "status_code": 200, "body": '{"token":"ok"}'}
    assert _http_outcome_signature(args, payload) is None


def test_http_stall_guard_blocks_repeated_same_error_result() -> None:
    guard = http_stall_guard(max_repeats=2)
    calls = 0

    async def handler(request):
        nonlocal calls
        calls += 1
        return SimpleNamespace(
            content=json.dumps({
                "ok": True,
                "status_code": 500,
                "body": '{"message":"SQLITE_BUSY: database is locked"}',
            }),
            name=request.tool.name,
            status="success",
        )

    args = {"method": "POST", "url": "http://host/api/v1/auth/login"}

    assert _run(guard.awrap_tool_call(_request(args), handler)).status == "success"
    assert _run(guard.awrap_tool_call(_request(args), handler)).status == "success"
    blocked = _run(guard.awrap_tool_call(_request(args, call_id="c3"), handler))

    assert calls == 3
    assert blocked.status == "error"
    assert blocked.tool_call_id == "c3"
    assert "HTTP_STALL_BLOCKED" in blocked.content
    assert "blocked_on" in blocked.content


def test_http_stall_guard_resets_after_success() -> None:
    guard = http_stall_guard(max_repeats=1)
    results = [
        {"ok": True, "status_code": 500, "body": "busy"},
        {"ok": True, "status_code": 200, "body": "ok"},
        {"ok": True, "status_code": 500, "body": "busy"},
    ]

    async def handler(request):
        return SimpleNamespace(
            content=json.dumps(results.pop(0)),
            name=request.tool.name,
            status="success",
        )

    args = {"method": "POST", "url": "http://host/api/v1/auth/login"}

    assert _run(guard.awrap_tool_call(_request(args), handler)).status == "success"
    assert _run(guard.awrap_tool_call(_request(args), handler)).status == "success"
    # If the success did not reset, this repeated 500 would be blocked.
    assert _run(guard.awrap_tool_call(_request(args), handler)).status == "success"

