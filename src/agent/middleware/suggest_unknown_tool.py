"""Suggest the right tool when the model calls an unknown one with a wrong prefix.

MCP tools are namespaced `<server>__<name>` (see `_load_prefixed_mcp_tools`), and
the model sometimes guesses the wrong server: it called `shell__get_cookies`
when the real tool is `browser__get_cookies`. langgraph then returns a generic
"not a valid tool, try one of [...]" dump, which the model has to scan.

langgraph defers unknown-tool validation so interceptors can short-circuit
(`_arun_one`: `tool = tools_by_name.get(name)` may be None, but the request
still reaches `awrap_tool_call`). So when an unknown tool is called and a tool
with the *same suffix* exists under a different prefix in this subagent's
toolset, we return a precise "did you mean `browser__get_cookies`?" instead.
When we have no confident suggestion we pass through and let langgraph emit its
normal unknown-tool error.
"""

from __future__ import annotations

from collections.abc import Iterable


def suggest_unknown_tool(known_tools: Iterable[str]):
    """Return middleware that redirects a wrong-prefix tool call to the real tool.

    `known_tools` is this subagent's bound MCP tool names (used to match suffixes
    across server prefixes).
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    # suffix ("get_cookies") -> full names exposing it ("browser__get_cookies")
    by_suffix: dict[str, list[str]] = {}
    for name in known_tools:
        if "__" in name:
            by_suffix.setdefault(name.split("__", 1)[1], []).append(name)

    class SuggestUnknownTool(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            # Known tools have a resolved `.tool`; unknown ones come through with
            # tool=None (langgraph defers the validation to us).
            if getattr(request, "tool", None) is not None:
                return await handler(request)

            tool_call = getattr(request, "tool_call", {}) or {}
            name = tool_call.get("name", "") or ""
            if "__" in name:
                alts = by_suffix.get(name.split("__", 1)[1])
                if alts:
                    return ToolMessage(
                        content=(
                            f"UNKNOWN_TOOL: `{name}` does not exist — wrong server prefix. "
                            f"Did you mean `{alts[0]}`? Call that exact name instead."
                        ),
                        tool_call_id=tool_call.get("id", "") or "",
                        name=name,
                        status="error",
                    )
            # No confident suggestion — let langgraph emit its standard
            # "not a valid tool, try one of [...]" error.
            return await handler(request)

    return SuggestUnknownTool()
