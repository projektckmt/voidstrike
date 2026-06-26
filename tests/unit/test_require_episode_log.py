"""Tests for the require-episode-log gate.

The gate blocks a subagent's structured response until it has logged an episode:
on the finalizing turn (the structured ToolMessage is last), if no successful
`episodes__write_episode` is in the transcript it injects a nudge and jumps back
to the model — bounded by `max_nudges`, and stateless (everything derived from
the message list, so it resets per subagent invocation).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from src.agent.middleware.require_episode_log import (
    _NUDGE_TAG,
    require_episode_log,
    structured_tool_name,
)

RESP_TOOL = "SurfaceFindings"


def _run(coro):
    return asyncio.run(coro)


def _struct_msg():
    return ToolMessage(content="Returning structured response: ...", tool_call_id="s1", name=RESP_TOOL)


def _episode_msg(status="success"):
    return ToolMessage(
        content='{"ok": true, "episode_id": 5}',
        tool_call_id="e1",
        name="episodes__write_episode",
        status=status,
    )


def _call(gate, messages):
    return _run(gate.aafter_model({"messages": messages}, None))


# --- structured_tool_name helper ------------------------------------------

def test_structured_tool_name_from_toolstrategy_like():
    rf = SimpleNamespace(schema_specs=[SimpleNamespace(name="SurfaceFindings")])
    assert structured_tool_name(rf) == "SurfaceFindings"


def test_structured_tool_name_none_for_plain_schema():
    assert structured_tool_name(object()) is None
    assert structured_tool_name(None) is None


# --- gate behaviour --------------------------------------------------------

def test_no_action_when_not_finalizing_turn():
    gate = require_episode_log(RESP_TOOL)
    # Mid-loop: last message is an AIMessage with a real tool call, not the
    # structured ToolMessage.
    msgs = [HumanMessage(content="go"), AIMessage(content="scanning", tool_calls=[])]
    assert _call(gate, msgs) is None


def test_blocks_and_jumps_when_findings_returned_without_logging():
    gate = require_episode_log(RESP_TOOL)
    msgs = [HumanMessage(content="Engagement id: e1. Recon."), AIMessage(content=""), _struct_msg()]
    out = _call(gate, msgs)
    assert out is not None
    assert out["jump_to"] == "model"
    assert len(out["messages"]) == 1
    assert _NUDGE_TAG in out["messages"][0].content
    assert "episodes__write_episode" in out["messages"][0].content


def test_passes_through_when_episode_was_logged():
    gate = require_episode_log(RESP_TOOL)
    msgs = [
        HumanMessage(content="recon"),
        AIMessage(content=""),
        _episode_msg(),          # logged earlier in this invocation
        AIMessage(content=""),
        _struct_msg(),           # now finalizing
    ]
    assert _call(gate, msgs) is None


def test_errored_episode_write_does_not_count_as_logged():
    gate = require_episode_log(RESP_TOOL)
    msgs = [_episode_msg(status="error"), AIMessage(content=""), _struct_msg()]
    out = _call(gate, msgs)
    assert out is not None and out["jump_to"] == "model"


def test_degrades_when_backend_persistently_errors():
    # Two errored episode writes = the backend is down, not the model skipping
    # its log step. Stop nudging and let the structured response through, rather
    # than forcing a pointless re-emission loop while the DB is unreachable.
    gate = require_episode_log(RESP_TOOL)
    msgs = [
        _episode_msg(status="error"),
        AIMessage(content=""),
        _episode_msg(status="error"),
        AIMessage(content=""),
        _struct_msg(),
    ]
    assert _call(gate, msgs) is None


def test_bounded_gives_up_after_max_nudges():
    gate = require_episode_log(RESP_TOOL, max_nudges=2)
    # Two prior nudges already in the transcript -> must not nudge a third time.
    msgs = [
        HumanMessage(content=f"{_NUDGE_TAG} log first"),
        AIMessage(content=""),
        HumanMessage(content=f"{_NUDGE_TAG} log first"),
        AIMessage(content=""),
        _struct_msg(),
    ]
    assert _call(gate, msgs) is None


def test_after_model_declares_can_jump_to_model():
    gate = require_episode_log(RESP_TOOL)
    # The conditional edge is only created if can_jump_to advertises "model".
    assert getattr(type(gate).aafter_model, "__can_jump_to__", None) == ["model"]
