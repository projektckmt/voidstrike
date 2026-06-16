"""Tests for the tool-error guard.

Reproduces the real failure: an MCP tool raising `ToolException` (e.g. a
malformed `tmux_send` with no `command`) propagated all the way up and panicked
the engagement, because langgraph's default handler re-raises everything that
isn't its own `ToolInvocationError`. The guard must turn any tool exception into
a recoverable `status="error"` ToolMessage, while re-raising langgraph
control-flow signals (HITL interrupts, recursion halts) untouched.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from langchain_core.tools import ToolException
from langgraph.errors import GraphBubbleUp, GraphInterrupt

from src.agent.middleware.tool_error_guard import tool_error_guard


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name: str = "shell__tmux_send", call_id: str = "c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": {"session_name": "shell1"}, "id": call_id},
    )


def test_tool_exception_becomes_recoverable_message():
    guard = tool_error_guard()

    async def handler(request):
        raise ToolException(
            "Error executing tool tmux_send: 1 validation error ... command Field required"
        )

    res = _run(guard.awrap_tool_call(_request(), handler))
    assert res.status == "error"
    assert "TOOL_ERROR" in res.content
    assert "command" in res.content  # original detail is preserved
    assert res.name == "shell__tmux_send"
    assert res.tool_call_id == "c1"


def test_generic_exception_is_also_caught():
    guard = tool_error_guard()

    async def handler(request):
        raise ValueError("MCP server unreachable")

    res = _run(guard.awrap_tool_call(_request("surface__nmap"), handler))
    assert res.status == "error"
    assert "ValueError" in res.content
    assert "MCP server unreachable" in res.content


def test_successful_result_passes_through():
    guard = tool_error_guard()
    sentinel = SimpleNamespace(content='{"ok": true}', name="shell__tmux_send", status="success")

    async def handler(request):
        return sentinel

    res = _run(guard.awrap_tool_call(_request(), handler))
    assert res is sentinel


def test_graph_interrupt_is_reraised():
    # HITL: action_class_gate / stuck_detector raise GraphInterrupt via
    # interrupt(). The guard must NOT swallow it or HITL breaks.
    guard = tool_error_guard()

    async def handler(request):
        raise GraphInterrupt(())

    with pytest.raises(GraphInterrupt):
        _run(guard.awrap_tool_call(_request(), handler))


def test_graph_bubbleup_family_is_reraised():
    guard = tool_error_guard()

    async def handler(request):
        raise GraphBubbleUp()

    with pytest.raises(GraphBubbleUp):
        _run(guard.awrap_tool_call(_request(), handler))
