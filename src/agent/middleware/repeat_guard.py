"""Guard against identical-call loops inside a subagent.

The orchestrator carries `stuck_detector`, but langchain v1 middleware is
per-loop: it does **not** intercept tool calls made inside a subagent's own
runtime (the same reason `fuzz_guard` is attached to the surface subagent
directly). So an exploit/postex subagent can spin forever re-issuing the exact
same malformed call, ignoring the error each time, with nothing to break it.

This middleware counts *consecutive identical failing* `(tool, args)` calls per
signature. After `max_repeats` it stops running the call and returns a hard
directive telling the model to change approach or hand back to the
orchestrator. A successful result for that signature resets its counter, so
legitimate repeated polling (e.g. `shell__tmux_read` while waiting on output)
is never blocked — only calls that keep *failing* identically.
"""

from __future__ import annotations

import json
from typing import Any


def _parse_tool_content(result: Any) -> Any:
    """Best-effort decode of a ToolMessage's content into a Python object."""
    content = getattr(result, "content", result)
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text", block)))
            else:
                parts.append(str(getattr(block, "text", block)))
        content = "".join(parts)
    if not isinstance(content, str):
        return content
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return None


def _is_failure(result: Any) -> bool:
    if getattr(result, "status", "") == "error":
        return True
    parsed = _parse_tool_content(result)
    if isinstance(parsed, dict):
        if parsed.get("ok") is False:
            return True
        if parsed.get("error"):
            return True
    return False


def _signature(tool_name: str, args: Any) -> str:
    try:
        return tool_name + "::" + json.dumps(args, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return tool_name + "::" + repr(args)


def repeat_guard(max_repeats: int = 3):
    """Break loops where a subagent re-issues an identical *failing* call.

    Deterministic — the prompt can tell the model to pivot, but this stops a bad
    loop from grinding regardless. Attach one instance per subagent loop.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    fail_counts: dict[str, int] = {}

    class RepeatGuard(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            tool_name = getattr(tool, "name", "") or ""
            tool_call = getattr(request, "tool_call", {}) or {}
            args = tool_call.get("args", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""
            sig = _signature(tool_name, args)

            if fail_counts.get(sig, 0) >= max_repeats:
                return ToolMessage(
                    content=(
                        f"REPEAT_BLOCKED: `{tool_name}` has been called with these exact "
                        f"arguments {fail_counts[sig]} times in a row and failed every time. "
                        "Re-read the error from the previous attempts — repeating the same "
                        "call will not change the result. Either fix the arguments / switch "
                        "technique, or return to the orchestrator with what you have so far."
                    ),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                    status="error",
                )

            result = await handler(request)
            if _is_failure(result):
                fail_counts[sig] = fail_counts.get(sig, 0) + 1
            else:
                fail_counts[sig] = 0
            return result

    return RepeatGuard()
