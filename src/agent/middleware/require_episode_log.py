"""Require an episode-log write before a subagent may return its findings.

A subagent with a `ToolStrategy` response_format ends its loop the instant it
emits the structured response — so a planned "log findings" step gets folded
into "return findings" and skipped. We make logging a hard precondition instead
of trusting the model's plan.

Mechanism: the structured-output tool call is parsed inside the *model* node and
never reaches `awrap_tool_call` (langchain excludes it from tool dispatch), so we
gate in `aafter_model`. On the turn that emits the structured response (its
matching ToolMessage is the last message), if no successful
`episodes__write_episode` exists in this subagent's conversation, we append a
corrective instruction and `jump_to: "model"` to force another turn.

Safety:
- Stateless — the "logged?" and "already nudged N times?" facts are derived from
  the message list, which is per-subagent-invocation, so it resets correctly for
  each `task()` call without any cross-invocation leakage.
- Bounded — after `max_nudges` it gives up and lets the response through, so it
  can never loop forever.
- Fail-safe — if `jump_to` were ever ignored, the only effect is one extra
  message in the transcript; the subagent still returns normally.
"""

from __future__ import annotations

from typing import Any

# Marker on our injected nudges so we can count them from the transcript alone
# (keeps the middleware stateless across subagent invocations).
_NUDGE_TAG = "[EPISODE_LOG_REQUIRED]"

_DEFAULT_EPISODE_TOOL = "episodes__write_episode"


def structured_tool_name(response_format: Any) -> str | None:
    """The tool name a `ToolStrategy` response_format exposes to the model.

    Mirrors langchain's own derivation (`schema_specs[0].name`, i.e. the schema
    class `__name__`). Returns None for non-ToolStrategy formats so the caller
    can skip wiring the gate.
    """
    specs = getattr(response_format, "schema_specs", None)
    if specs:
        return getattr(specs[0], "name", None)
    return None


def require_episode_log(
    response_tool_name: str,
    episode_tool: str = _DEFAULT_EPISODE_TOOL,
    max_nudges: int = 2,
):
    """Return middleware that blocks `response_tool_name` until `episode_tool`
    has been called successfully in the current subagent invocation."""
    from langchain.agents.middleware import AgentMiddleware, hook_config  # noqa: PLC0415
    from langchain_core.messages import HumanMessage, ToolMessage  # noqa: PLC0415

    def _logged(messages: list[Any]) -> bool:
        for m in messages:
            if not isinstance(m, ToolMessage):
                continue
            name = getattr(m, "name", "") or ""
            if name.startswith(episode_tool) and getattr(m, "status", None) != "error":
                return True
        return False

    def _nudges_so_far(messages: list[Any]) -> int:
        return sum(
            1
            for m in messages
            if isinstance(m, HumanMessage) and _NUDGE_TAG in str(getattr(m, "content", ""))
        )

    class RequireEpisodeLog(AgentMiddleware):
        @hook_config(can_jump_to=["model"])
        async def aafter_model(self, state, runtime):  # noqa: ANN001, ARG002
            messages = state.get("messages") or []
            if not messages:
                return None

            # The finalizing turn appends [AIMessage(structured call), ToolMessage]
            # — so the structured response is in flight iff the last message is the
            # structured tool's ToolMessage.
            last = messages[-1]
            if not (isinstance(last, ToolMessage) and getattr(last, "name", "") == response_tool_name):
                return None

            if _logged(messages):
                return None
            if _nudges_so_far(messages) >= max_nudges:
                return None  # bounded — give up rather than loop forever

            return {
                "jump_to": "model",
                "messages": [
                    HumanMessage(
                        content=(
                            f"{_NUDGE_TAG} You returned {response_tool_name} without recording "
                            f"your work in the engagement's episode log. That log is the source "
                            f"of truth the analyst's report is built from. Before this is "
                            f"accepted you MUST call `{episode_tool}` to record what you found "
                            f"(pass the engagement_id from your task instructions verbatim, "
                            f"agent_name, the tool/result, and outcome_tag). Do that now, then "
                            f"return your {response_tool_name} again."
                        )
                    )
                ],
            }

    return RequireEpisodeLog()
