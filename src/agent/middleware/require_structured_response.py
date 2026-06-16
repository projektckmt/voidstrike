"""Force a subagent to actually emit its structured response.

A subagent with a `ToolStrategy` response_format returns its result by *calling*
the response tool (e.g. `ResearchResult`). But the model sometimes ends its turn
with a plain assistant message — empty or just prose — and **never calls the
response tool**. langchain treats a no-tool-call AIMessage as "done", so the
loop ends and `task()` returns nothing. Observed in the wild: the researcher
browsed exploit-db for a CVE chain, then ended with `content='' tool_calls=[]`
and returned 0 chars twice, leaving the orchestrator with no plan.

This is the inverse of `require_episode_log`: that one fires when the response
*was* emitted but logging was skipped; this one fires when the model is about to
end **without** emitting the response at all. In `aafter_model`, if the last
message is a final AIMessage (no tool calls) and the structured response tool
has not been emitted yet this invocation, we append a directive and
`jump_to: "model"` to make the model call the response tool.

Safety mirrors `require_episode_log`: stateless (facts derived from the
per-invocation message list), bounded by `max_nudges`, and fail-safe (a missed
`jump_to` just leaves one extra message; the subagent still returns).
"""

from __future__ import annotations

from typing import Any

_NUDGE_TAG = "[STRUCTURED_RESPONSE_REQUIRED]"


def _has_tool_calls(msg: Any) -> bool:
    """True if an AIMessage carries any tool call (native or content-block form)."""
    if getattr(msg, "tool_calls", None):
        return True
    content = getattr(msg, "content", None)
    if isinstance(content, list):
        return any(isinstance(b, dict) and b.get("type") == "tool_use" for b in content)
    return False


def require_structured_response(response_tool_name: str, max_nudges: int = 2):
    """Return middleware that blocks a subagent from ending without calling
    `response_tool_name` (its ToolStrategy response tool)."""
    from langchain.agents.middleware import AgentMiddleware, hook_config  # noqa: PLC0415
    from langchain_core.messages import AIMessage, HumanMessage, ToolMessage  # noqa: PLC0415

    def _emitted(messages: list[Any]) -> bool:
        # The structured response tool call is parsed in the model node and shows
        # up as a ToolMessage with the response tool's name once emitted.
        return any(
            isinstance(m, ToolMessage) and getattr(m, "name", "") == response_tool_name
            for m in messages
        )

    def _nudges_so_far(messages: list[Any]) -> int:
        return sum(
            1
            for m in messages
            if isinstance(m, HumanMessage) and _NUDGE_TAG in str(getattr(m, "content", ""))
        )

    class RequireStructuredResponse(AgentMiddleware):
        @hook_config(can_jump_to=["model"])
        async def aafter_model(self, state, runtime):  # noqa: ANN001, ARG002
            messages = state.get("messages") or []
            if not messages:
                return None

            last = messages[-1]
            # Only act when the model is trying to END the turn: a final AIMessage
            # with no tool calls. If it called tools (including the response tool),
            # let the loop run — the response tool ends it normally.
            if not isinstance(last, AIMessage) or _has_tool_calls(last):
                return None
            if _emitted(messages):
                return None
            if _nudges_so_far(messages) >= max_nudges:
                return None  # bounded — give up rather than loop forever

            return {
                "jump_to": "model",
                "messages": [
                    HumanMessage(
                        content=(
                            f"{_NUDGE_TAG} You ended your turn without returning a result. "
                            f"You MUST finish by calling the `{response_tool_name}` tool — that "
                            f"is the ONLY way your work reaches the orchestrator; a plain-text "
                            f"or empty reply is discarded. Even if your findings are partial, "
                            f"negative, or inconclusive, call `{response_tool_name}` now and put "
                            f"what you have (and what's still unknown) in its fields."
                        )
                    )
                ],
            }

    return RequireStructuredResponse()
