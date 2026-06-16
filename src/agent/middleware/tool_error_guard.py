"""Convert recoverable tool failures into ToolMessages instead of crashing the run.

langgraph's default tool-error handler (`_default_handle_tool_errors` in
`langgraph/prebuilt/tool_node.py`) only turns its own `ToolInvocationError`
(the arg-schema validation langgraph does itself) into a message — every other
exception is re-raised. So an MCP tool that raises propagates all the way up and
**panics the whole engagement** (`_panic_or_proceed` → raise). The canonical
case: `langchain-mcp-adapters` raises `ToolException` when the model sends a
malformed call (e.g. `tmux_send` with no `command`), and one bad tool call kills
the run.

A single malformed or failed tool call should be feedback the model can act on,
not fatal. This middleware wraps tool execution and converts any such failure
into a `status="error"` ToolMessage, so the loop continues and the model retries
or pivots. langgraph control-flow signals are re-raised untouched so HITL and
recursion limits keep working: `GraphBubbleUp` (the base for `GraphInterrupt`
from `interrupt()`, `ParentCommand`, ...) and `GraphRecursionError`.

Attach as the INNERMOST per-loop middleware (last in the list). It then wraps
exactly the tool execution — not the RoE/action-class/HITL gates above it — and
its `status="error"` result is visible to outer guards like `repeat_guard`,
which counts a repeated failing call.
"""

from __future__ import annotations


def tool_error_guard():
    """Return middleware that turns tool exceptions into recoverable ToolMessages.

    Re-raises langgraph control-flow exceptions so HITL/interrupts and the
    recursion limit are never swallowed.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415
    from langgraph.errors import GraphBubbleUp, GraphRecursionError  # noqa: PLC0415

    class ToolErrorGuard(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            try:
                return await handler(request)
            except (GraphBubbleUp, GraphRecursionError):
                # Control flow (HITL interrupt, parent command, recursion halt) —
                # never swallow these.
                raise
            except Exception as e:  # noqa: BLE001
                tool = getattr(request, "tool", None)
                tool_name = getattr(tool, "name", "") or ""
                tool_call = getattr(request, "tool_call", {}) or {}
                tool_call_id = tool_call.get("id", "") or ""
                return ToolMessage(
                    content=(
                        f"TOOL_ERROR: `{tool_name}` raised {type(e).__name__}: {e} "
                        "This is recoverable, not fatal — the engagement is still "
                        "running. Check the arguments you sent (required fields and "
                        "types) and retry, or take a different approach."
                    ),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                    status="error",
                )

    return ToolErrorGuard()
