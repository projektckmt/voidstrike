"""Tests for the flag-completion gate.

Verifies the deterministic handoff: once `expected_flags` distinct flags are
recorded, the gate refuses any `task` delegation except to the analyst, and
leaves everything alone before completion.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from src.agent.middleware.flag_completion import flag_completion_gate


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name: str, args: dict, call_id: str = "c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": args, "id": call_id},
    )


def _make_handler():
    """A handler that records what it was actually allowed to run."""
    ran: list[str] = []

    async def handler(request):
        ran.append(request.tool.name)
        return SimpleNamespace(content="ok", name=request.tool.name)

    return handler, ran


def test_passes_through_before_completion():
    gate = flag_completion_gate(2)
    handler, ran = _make_handler()
    # One flag recorded — not yet complete; delegations still allowed.
    _run(gate.awrap_tool_call(_request("record_flag", {"flag": "user-flag", "engagement_id": "e"}), handler))
    res = _run(gate.awrap_tool_call(_request("task", {"subagent_type": "postex"}), handler))
    assert "task" in ran
    assert getattr(res, "status", None) != "error"


def test_blocks_non_analyst_after_completion():
    gate = flag_completion_gate(2)
    handler, ran = _make_handler()
    _run(gate.awrap_tool_call(_request("record_flag", {"flag": "user-flag"}), handler))
    _run(gate.awrap_tool_call(_request("record_flag", {"flag": "root-flag"}), handler))

    res = _run(gate.awrap_tool_call(_request("task", {"subagent_type": "postex"}), handler))
    # The postex delegation must be refused (not forwarded to the handler).
    assert "task" not in ran
    assert res.status == "error"
    assert "analyst" in res.content


def test_allows_analyst_after_completion():
    gate = flag_completion_gate(2)
    handler, ran = _make_handler()
    _run(gate.awrap_tool_call(_request("record_flag", {"flag": "user-flag"}), handler))
    _run(gate.awrap_tool_call(_request("record_flag", {"flag": "root-flag"}), handler))

    _run(gate.awrap_tool_call(_request("task", {"subagent_type": "analyst"}), handler))
    # The analyst delegation is forwarded to the handler (not blocked).
    assert ran[-1] == "task"


def test_duplicate_flags_do_not_count_twice():
    gate = flag_completion_gate(2)
    handler, ran = _make_handler()
    # Same flag recorded twice -> only one distinct flag -> not complete.
    _run(gate.awrap_tool_call(_request("record_flag", {"flag": "user-flag"}), handler))
    _run(gate.awrap_tool_call(_request("record_flag", {"flag": "user-flag"}), handler))

    res = _run(gate.awrap_tool_call(_request("task", {"subagent_type": "postex"}), handler))
    assert getattr(res, "status", None) != "error"
    assert ran.count("task") == 1
