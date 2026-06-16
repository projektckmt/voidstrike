"""Tests for serialize_tasks — one subagent delegation per orchestrator turn.

A multi-`task` assistant turn runs subagents concurrently (shared tmux state)
and blocks the orchestrator on a join until all return; a dead-end branch then
stalls the whole engagement (see logs/debug_reactor3.jsonl). This middleware
lets the first `task` run and defers the rest with a directive ToolMessage.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from langchain_core.messages import AIMessage, ToolMessage

from src.agent.middleware.serialize_tasks import serialize_tasks


def _run(coro):
    return asyncio.run(coro)


async def _ok(request):
    """Stand-in for the real handler — proves the call was actually executed."""
    return SimpleNamespace(content="ran", name=request.tool.name, status="success")


def _request(tool_name, call_id, state_messages):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"name": tool_name, "args": {}, "id": call_id},
        state={"messages": state_messages},
    )


def _turn(*task_ids, other=()):
    """An AIMessage emitting `task` calls with the given ids (plus optional
    non-task calls), as the triggering assistant turn."""
    calls = [{"name": "task", "args": {}, "id": tid} for tid in task_ids]
    calls += [{"name": n, "args": {}, "id": cid} for n, cid in other]
    return AIMessage(content="", tool_calls=calls)


# --- single dispatch: always runs ------------------------------------------

def test_lone_task_runs():
    g = serialize_tasks()
    msgs = [_turn("a")]
    res = _run(g.awrap_tool_call(_request("task", "a", msgs), _ok))
    assert res.content == "ran"


def test_non_task_tool_passes_through():
    g = serialize_tasks()
    # a normal orchestrator tool call, never gated even alongside a task
    msgs = [_turn("a", other=[("write_objective", "w")])]
    res = _run(g.awrap_tool_call(_request("write_objective", "w", msgs), _ok))
    assert res.content == "ran"


# --- parallel dispatch: first wins, rest deferred --------------------------

def test_parallel_first_task_runs():
    g = serialize_tasks()
    msgs = [_turn("a", "b")]
    res = _run(g.awrap_tool_call(_request("task", "a", msgs), _ok))
    assert res.content == "ran"


def test_parallel_second_task_blocked():
    g = serialize_tasks()
    msgs = [_turn("a", "b")]
    res = _run(g.awrap_tool_call(_request("task", "b", msgs), _ok))
    assert res.status == "error"
    assert "PARALLEL_DISPATCH_BLOCKED" in res.content
    assert res.tool_call_id == "b"


def test_parallel_third_task_also_blocked():
    g = serialize_tasks()
    msgs = [_turn("a", "b", "c")]
    res = _run(g.awrap_tool_call(_request("task", "c", msgs), _ok))
    assert res.status == "error"


def test_blocked_message_does_not_run_handler():
    """The deferred task must NOT execute the subagent."""
    g = serialize_tasks()
    ran = {"flag": False}

    async def _track(request):
        ran["flag"] = True
        return SimpleNamespace(content="ran", name="task", status="success")

    msgs = [_turn("a", "b")]
    _run(g.awrap_tool_call(_request("task", "b", msgs), _track))
    assert ran["flag"] is False


# --- robustness ------------------------------------------------------------

def test_finds_triggering_turn_not_just_last_message():
    """The first task may already have produced a ToolMessage by the time the
    sibling's wrap runs — resolve siblings from the AIMessage, not messages[-1]."""
    g = serialize_tasks()
    msgs = [
        _turn("a", "b"),
        ToolMessage(content="surface done", tool_call_id="a", name="task"),
    ]
    res = _run(g.awrap_tool_call(_request("task", "b", msgs), _ok))
    assert res.status == "error"


def test_unknown_call_id_runs():
    """If we can't resolve the triggering turn, fail open (run) rather than
    wedge the orchestrator."""
    g = serialize_tasks()
    msgs = [_turn("a", "b")]
    res = _run(g.awrap_tool_call(_request("task", "zzz", msgs), _ok))
    assert res.content == "ran"


def test_two_separate_turns_each_run():
    """Serial dispatches across turns are both allowed — only same-turn batches
    are gated."""
    g = serialize_tasks()
    first = [_turn("a")]
    second = [_turn("a"), ToolMessage(content="done", tool_call_id="a", name="task"), _turn("b")]
    assert _run(g.awrap_tool_call(_request("task", "a", first), _ok)).content == "ran"
    assert _run(g.awrap_tool_call(_request("task", "b", second), _ok)).content == "ran"
