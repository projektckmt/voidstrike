"""Flag-completion gate.

Once the engagement's expected number of flags has been recorded, the only
productive thing left is to write the report. The orchestrator prompt asks it to
hand off to the analyst at that point, but it does so reliably only some of the
time — it tends to keep delegating enumeration/exploitation against a box it has
already won.

This middleware makes the handoff deterministic: after `expected_flags` distinct
flags are recorded via the `record_flag` tool, any `task` delegation to a
subagent *other than* the analyst is refused, with a tool result telling the
orchestrator to delegate to the analyst instead. The block is returned as a
proper `ToolMessage` (the tool_result for the call), so the message sequence
stays valid.

One agent — and therefore one instance of this middleware — is built per
engagement (see `build_agent`), so plain instance state is correct here; no
per-thread keying is needed.
"""

from __future__ import annotations


def flag_completion_gate(expected_flags: int):
    """Returns an `AgentMiddleware` that forces the analyst handoff once
    `expected_flags` flags are recorded. Callers should only install this when
    `expected_flags` is a positive int (flag count is the completion signal)."""
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    class FlagCompletionGate(AgentMiddleware):
        def __init__(self) -> None:
            super().__init__()
            self._flags: set[str] = set()
            self._complete = False

        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            tool_name = getattr(tool, "name", "") or ""
            tool_call = getattr(request, "tool_call", {}) or {}
            args = tool_call.get("args", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""

            # Objective already met: permit only the analyst handoff (plus
            # idempotent re-recording of a flag). Refuse other delegations.
            if self._complete and tool_name == "task":
                target = (args.get("subagent_type") or "").strip()
                if target != "analyst":
                    return ToolMessage(
                        content=(
                            f"OBJECTIVE COMPLETE — all {expected_flags} flag(s) are "
                            f"recorded. Delegating to {target!r} is disabled. Call "
                            'task(subagent_type="analyst", ...) now to produce the '
                            "report; that is the only remaining step."
                        ),
                        tool_call_id=tool_call_id,
                        name=tool_name,
                        status="error",
                    )

            result = await handler(request)

            # Count distinct flags as they're recorded, then latch completion.
            if tool_name == "record_flag":
                flag_value = (args.get("flag") or "").strip()
                if flag_value:
                    self._flags.add(flag_value)
                if not self._complete and len(self._flags) >= expected_flags:
                    self._complete = True

            return result

    return FlagCompletionGate()
