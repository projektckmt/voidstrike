"""Tests for the per-invocation step budget.

Caps tool steps in one subagent invocation so a long shell-driving loop can't
run up O(N²) token cost (the 930-step subagent that was 73% of a run). Past the
cap it forces a handback; wrap-up logging tools stay allowed so the subagent can
record progress and return. Count is stateless (from request.state.messages),
so a re-tasked invocation starts fresh.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from langchain_core.messages import AIMessage, ToolMessage

from src.agent.middleware.step_budget import step_budget


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name, state_messages, call_id="c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": {}, "id": call_id},
        state={"messages": state_messages},
    )


def _history(n):
    """A transcript with `n` completed tool steps."""
    msgs = []
    for i in range(n):
        msgs.append(AIMessage(content="", tool_calls=[{"name": "shell__tmux_send", "args": {}, "id": f"t{i}"}]))
        msgs.append(ToolMessage(content="ok", tool_call_id=f"t{i}", name="shell__tmux_send"))
    return msgs


async def _ok(request):
    return SimpleNamespace(content="ran", name=request.tool.name, status="success")


def test_allows_under_budget():
    g = step_budget(max_steps=120)
    res = _run(g.awrap_tool_call(_request("shell__tmux_send", _history(50)), _ok))
    assert res.content == "ran"


def test_blocks_at_budget_with_handback_directive():
    g = step_budget(max_steps=120)
    res = _run(g.awrap_tool_call(_request("shell__tmux_read", _history(120)), _ok))
    assert res.status == "error"
    assert "STEP_BUDGET_EXHAUSTED" in res.content
    assert "120" in res.content
    assert "re-task" in res.content.lower()


def test_wrapup_logging_always_allowed():
    # Past the cap, the subagent must still be able to record progress + return.
    g = step_budget(max_steps=10)
    hist = _history(50)
    for name in ("episodes__write_episode", "episodes__write_finding"):
        res = _run(g.awrap_tool_call(_request(name, hist), _ok))
        assert res.content == "ran", name


def test_stateless_per_invocation():
    # A fresh re-task (empty history) is never blocked, regardless of prior runs.
    g = step_budget(max_steps=2)
    res = _run(g.awrap_tool_call(_request("shell__tmux_send", []), _ok))
    assert res.content == "ran"


def test_preserves_call_id():
    g = step_budget(max_steps=1)
    res = _run(g.awrap_tool_call(_request("shell__tmux_send", _history(3), call_id="zz"), _ok))
    assert res.status == "error"
    assert res.tool_call_id == "zz"
