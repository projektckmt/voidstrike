"""Stuck-detection middleware.

If N consecutive tool calls pass without an episode tagged `new_finding`, escalate
with a structured `StuckReport` via the HITL interrupt path.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from ...schemas.episodes import OutcomeTag
from ...schemas.findings import StuckReport


@dataclass
class _StuckState:
    """Per-engagement rolling window of recent outcomes."""

    threshold: int
    window: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=64))
    last_escalation_at: int = 0

    @property
    def calls_since_finding(self) -> int:
        count = 0
        for entry in reversed(self.window):
            if entry["outcome"] == OutcomeTag.NEW_FINDING:
                break
            count += 1
        return count

    def record(self, tool_name: str, args: dict[str, Any], outcome: OutcomeTag) -> None:
        self.window.append({"tool": tool_name, "args": args, "outcome": outcome})

    def should_escalate(self) -> bool:
        return self.calls_since_finding >= self.threshold


def stuck_detector(threshold: int = 15):
    """Returns an `AgentMiddleware` that detects stuck loops.

    Each tool result is classified into a coarse outcome; if `threshold`
    consecutive tool calls pass without a productive outcome, the middleware
    raises a structured `StuckReport` interrupt so the operator can answer
    one question instead of watching the agent grind.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import AIMessage, ToolMessage  # noqa: PLC0415
    from langgraph.types import interrupt  # noqa: PLC0415

    states: dict[str, _StuckState] = {}

    def _get_state(thread_id: str) -> _StuckState:
        if thread_id not in states:
            states[thread_id] = _StuckState(threshold=threshold)
        return states[thread_id]

    PRODUCTIVE_KEYWORDS = ("new finding", "shell landed", "objective met", "priv escalated")  # noqa: N806

    def _outcome_from_message(msg) -> OutcomeTag:  # noqa: ANN001
        # Heuristic: scan the tool message content for productive markers. Real
        # outcome tagging happens in the `episodes` MCP server; this lighter
        # check is just for stuck detection.
        text = (getattr(msg, "content", "") or "").lower()
        if any(k in text for k in PRODUCTIVE_KEYWORDS):
            return OutcomeTag.NEW_FINDING
        if "error" in text or getattr(msg, "status", "") == "error":
            return OutcomeTag.ERROR
        return OutcomeTag.NO_RESULT

    class StuckDetector(AgentMiddleware):
        async def aafter_model(self, state):  # noqa: ANN001
            thread_id = state.get("thread_id") or state.get("configurable", {}).get("thread_id") or "default"
            s = _get_state(thread_id)

            messages = state.get("messages") or []
            # Look at the last message only — record one outcome per step.
            if messages and isinstance(messages[-1], ToolMessage):
                msg = messages[-1]
                s.record(
                    tool_name=getattr(msg, "name", "") or "",
                    args={},
                    outcome=_outcome_from_message(msg),
                )

            if not s.should_escalate():
                return None
            if len(s.window) - s.last_escalation_at < threshold:
                return None
            s.last_escalation_at = len(s.window)

            report = StuckReport(
                engagement_id=thread_id,
                current_objective=state.get("current_objective", "(unknown)"),
                attempts=[e["tool"] for e in s.window if e["outcome"] != OutcomeTag.NEW_FINDING],
                surfaces_probed=_collect_targets(s.window),
                hypotheses_ruled_out=[],
                operator_questions=[
                    "Is there a target detail (creds, internal hostname, hint) not in the spec?",
                    "Should I broaden scope or change technique?",
                    "Is the target reachable from the sandbox right now?",
                ],
                raw_episode_tail=list(s.window)[-10:],
            )
            response = interrupt({"kind": "stuck_report", **report.model_dump()})
            guidance = (response or {}).get("guidance", "")
            return {
                "messages": [
                    AIMessage(
                        content=(
                            f"OPERATOR HITL RESPONSE: {guidance}\n"
                            "Resuming with this new context."
                        )
                    )
                ]
            }

    return StuckDetector()


def _collect_targets(window: deque[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    for entry in window:
        for key in ("host", "target", "url", "hosts", "targets"):
            value = entry.get("args", {}).get(key)
            if isinstance(value, str) and value not in seen:
                seen.append(value)
            elif isinstance(value, list):
                for v in value:
                    if isinstance(v, str) and v not in seen:
                        seen.append(v)
    return seen
