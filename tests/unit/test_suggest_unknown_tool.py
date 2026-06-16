"""Tests for the wrong-prefix tool suggester.

The model sometimes calls a tool under the wrong server prefix
(`shell__get_cookies` instead of `browser__get_cookies`). langgraph passes the
unknown call through with `request.tool=None`; this guard redirects it to the
real tool by matching the suffix against the subagent's bound tools.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from src.agent.middleware.suggest_unknown_tool import suggest_unknown_tool

KNOWN = {
    "browser__get_cookies",
    "browser__goto",
    "shell__tmux_send",
    "exploit__generate_payload",
}


def _run(coro):
    return asyncio.run(coro)


def _request(name: str, *, tool_known: bool, call_id: str = "c1"):
    # langgraph sets request.tool=None for unknown tools.
    tool = SimpleNamespace(name=name) if tool_known else None
    return SimpleNamespace(tool=tool, tool_call={"name": name, "args": {}, "id": call_id})


async def _passthrough(request):
    return SimpleNamespace(content="executed", name=request.tool_call["name"], status="success")


def test_redirects_wrong_prefix_to_real_tool():
    guard = suggest_unknown_tool(KNOWN)
    res = _run(guard.awrap_tool_call(_request("shell__get_cookies", tool_known=False), _passthrough))
    assert res.status == "error"
    assert "UNKNOWN_TOOL" in res.content
    assert "browser__get_cookies" in res.content
    assert res.tool_call_id == "c1"


def test_known_tool_passes_through():
    guard = suggest_unknown_tool(KNOWN)
    res = _run(guard.awrap_tool_call(_request("browser__get_cookies", tool_known=True), _passthrough))
    assert res.content == "executed"


def test_unknown_with_no_suffix_match_falls_through_to_default():
    # No tool with suffix "florble" — defer to langgraph's standard error
    # (here, the passthrough handler stands in for that).
    guard = suggest_unknown_tool(KNOWN)
    res = _run(guard.awrap_tool_call(_request("shell__florble", tool_known=False), _passthrough))
    assert res.content == "executed"  # handler was called, no override


def test_unprefixed_unknown_falls_through():
    guard = suggest_unknown_tool(KNOWN)
    res = _run(guard.awrap_tool_call(_request("get_cookies", tool_known=False), _passthrough))
    assert res.content == "executed"
