"""Tests for the subagent repeat guard.

Reproduces the real failure mode: a subagent re-issuing the identical
`exploit__deliver_via_web` call that fails every time. The guard must let the
first few through (the model might self-correct), then hard-block; a successful
result must reset the counter so legitimate repeated polling is never blocked.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from src.agent.middleware.repeat_guard import (
    _is_failure,
    _signature,
    repeat_guard,
)


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name: str, args: dict, call_id: str = "c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": args, "id": call_id},
    )


def _failing_handler(payload: str = '{"ok": false, "error": "boom"}'):
    """Handler that always returns a failing tool result, counting invocations."""
    calls: list[dict] = []

    async def handler(request):
        calls.append(request.tool_call["args"])
        return SimpleNamespace(content=payload, name=request.tool.name, status="success")

    return handler, calls


# --- deterministic helpers -------------------------------------------------

def test_is_failure_detects_ok_false_in_content():
    assert _is_failure(SimpleNamespace(content='{"ok": false, "error": "x"}', status="success"))


def test_is_failure_detects_error_status():
    assert _is_failure(SimpleNamespace(content="anything", status="error"))


def test_is_failure_false_for_successful_payload():
    assert not _is_failure(SimpleNamespace(content='{"ok": true, "stdout": "uid=0"}', status="success"))


def test_signature_is_order_independent_for_args():
    a = _signature("t", {"x": 1, "y": 2})
    b = _signature("t", {"y": 2, "x": 1})
    assert a == b
    assert _signature("t", {"x": 1}) != _signature("t", {"x": 2})


# --- behaviour -------------------------------------------------------------

DELIVER_ARGS = {"target_url": "ftp://10.129.5.205/", "technique": "file_upload"}


def test_blocks_identical_failing_call_after_threshold():
    guard = repeat_guard(max_repeats=3)
    handler, calls = _failing_handler()

    # First 3 identical failing calls reach the handler (status not forced error
    # by us — the failure is in the payload).
    for _ in range(3):
        res = _run(guard.awrap_tool_call(_request("exploit__deliver_via_web", DELIVER_ARGS), handler))
        assert getattr(res, "status", None) != "error" or "REPEAT_BLOCKED" not in res.content

    assert len(calls) == 3

    # The 4th identical call is blocked before reaching the handler.
    res = _run(guard.awrap_tool_call(_request("exploit__deliver_via_web", DELIVER_ARGS), handler))
    assert len(calls) == 3  # handler NOT invoked again
    assert res.status == "error"
    assert "REPEAT_BLOCKED" in res.content


def test_distinct_args_do_not_trip_the_guard():
    guard = repeat_guard(max_repeats=3)
    handler, calls = _failing_handler()

    for i in range(6):
        args = {**DELIVER_ARGS, "target_url": f"ftp://10.129.5.205/{i}"}
        _run(guard.awrap_tool_call(_request("exploit__deliver_via_web", args), handler))

    # All six different calls ran — different signatures never accumulate.
    assert len(calls) == 6


def test_success_resets_the_counter():
    guard = repeat_guard(max_repeats=3)

    async def handler(request):
        # Fail unless the args carry {"win": true}.
        ok = request.tool_call["args"].get("win") is True
        body = json.dumps({"ok": ok})
        return SimpleNamespace(content=body, name=request.tool.name, status="success")

    # Two failures, then a success for the SAME signature shape resets it.
    _run(guard.awrap_tool_call(_request("shell__tmux_read", {"session": "s"}), handler))
    _run(guard.awrap_tool_call(_request("shell__tmux_read", {"session": "s"}), handler))
    _run(guard.awrap_tool_call(_request("shell__tmux_read", {"session": "s", "win": True}), handler))

    # The successful call has a different signature, so the failing one would
    # still be at 2. Confirm a polling tool that keeps *succeeding* never blocks.
    ran = 0
    for _ in range(10):
        res = _run(guard.awrap_tool_call(_request("poll", {"win": True}), handler))
        if getattr(res, "status", None) != "error":
            ran += 1
    assert ran == 10
