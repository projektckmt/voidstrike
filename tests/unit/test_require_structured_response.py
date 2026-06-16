"""Tests for the require-structured-response gate.

The gate forces a ToolStrategy subagent to actually call its response tool: if
the model ends a turn with a plain/empty AIMessage (no tool calls) and the
response tool was never emitted, it injects a directive and jumps back to the
model — bounded, stateless (derived from the message list). This is the inverse
of require_episode_log and fixes the researcher's empty-output failure.
"""

from __future__ import annotations

import asyncio

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from src.agent.middleware.require_structured_response import (
    _NUDGE_TAG,
    require_structured_response,
)

RESP_TOOL = "ResearchResult"


def _run(coro):
    return asyncio.run(coro)


def _call(gate, messages):
    return _run(gate.aafter_model({"messages": messages}, None))


def test_nudges_when_turn_ends_without_response_tool():
    # The observed failure: empty AIMessage, no tool calls, no response emitted.
    gate = require_structured_response(RESP_TOOL)
    out = _call(gate, [
        HumanMessage(content="research the CVE"),
        AIMessage(content=""),
    ])
    assert out is not None
    assert out["jump_to"] == "model"
    assert _NUDGE_TAG in out["messages"][0].content
    assert RESP_TOOL in out["messages"][0].content


def test_no_nudge_when_response_tool_emitted():
    # Finalizing turn: the structured ToolMessage is present → let it return.
    gate = require_structured_response(RESP_TOOL)
    out = _call(gate, [
        HumanMessage(content="research"),
        AIMessage(content="", tool_calls=[{"name": RESP_TOOL, "args": {}, "id": "r1"}]),
        ToolMessage(content="structured response", tool_call_id="r1", name=RESP_TOOL),
    ])
    assert out is None


def test_no_nudge_while_model_is_calling_tools():
    # Mid-run: the model called a real tool — loop should proceed, no nudge.
    gate = require_structured_response(RESP_TOOL)
    out = _call(gate, [
        HumanMessage(content="research"),
        AIMessage(content="", tool_calls=[{"name": "browser__goto", "args": {}, "id": "g1"}]),
    ])
    assert out is None


def test_detects_tool_calls_in_content_blocks():
    # Anthropic content-block form of a tool call must also count as "not done".
    gate = require_structured_response(RESP_TOOL)
    msg = AIMessage(content=[{"type": "tool_use", "name": "browser__goto", "input": {}, "id": "g1"}])
    out = _call(gate, [HumanMessage(content="x"), msg])
    assert out is None


def test_bounded_by_max_nudges():
    gate = require_structured_response(RESP_TOOL, max_nudges=2)
    msgs = [
        HumanMessage(content="research"),
        HumanMessage(content=f"{_NUDGE_TAG} call it"),
        HumanMessage(content=f"{_NUDGE_TAG} call it again"),
        AIMessage(content=""),  # still empty after 2 nudges
    ]
    assert _call(gate, msgs) is None  # gives up rather than loop forever


def test_empty_message_list_is_safe():
    gate = require_structured_response(RESP_TOOL)
    assert _call(gate, []) is None
