"""Cap how many tool steps a subagent takes in one invocation, to break the
quadratic token cost of a long-running loop.

An agent loop is stateless between turns: each step re-sends the *entire*
accumulated transcript (every prior tool call + result) as model input. So a
subagent that takes N tool steps costs ~O(N²) input tokens — and in the logs a
single shell-driving subagent hit **930 steps / 4.4 MB (73% of the whole run)**,
its `tmux_read` results (1.9 MB) re-sent on every later turn.

The fix is to bound N. When a subagent hits the step cap, this forces it to
record progress and **return**, so the orchestrator re-delegates with FRESH
context — a new invocation starts with just the task brief, not the 930-step
history, which resets the quadratic (5×150² ≈ 112k tokens vs 930² ≈ 865k). The
tmux sessions live in the shell MCP server and persist by name, so the re-tasked
subagent re-attaches and loses no operational state — only the (re-derivable)
conversation context resets.

Wrap-up tools (`episodes__write_*`) are always allowed so the subagent can log
its progress before returning; the structured-response tool is parsed in the
model node (never reaches `awrap_tool_call`), so it's never blocked. Count is
read statelessly from `request.state`, so each `task()` invocation starts fresh.
"""

from __future__ import annotations

from typing import Any
from ._util import messages_from_state as _messages_from_state

# Tools the subagent may always call, even past the budget — they're how it
# wraps up (records progress) before returning.
_WRAPUP_TOOLS = frozenset({
    "episodes__write_episode",
    "episodes__write_finding",
})


def step_budget(max_steps: int = 130):
    """Return middleware that forces a subagent to return after `max_steps` tool
    steps in one invocation (so the orchestrator re-tasks it with fresh context).
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    class StepBudget(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            name = getattr(tool, "name", "") or ""
            # Always let it log progress so it can wrap up cleanly.
            if name in _WRAPUP_TOOLS:
                return await handler(request)

            messages = _messages_from_state(getattr(request, "state", None))
            steps = sum(1 for m in messages if isinstance(m, ToolMessage))
            if steps >= max_steps:
                tool_call = getattr(request, "tool_call", {}) or {}
                return ToolMessage(
                    content=(
                        f"STEP_BUDGET_EXHAUSTED: you've taken {steps} tool steps in this "
                        "invocation — that's the cap. A single long loop gets very "
                        "expensive (every step re-sends the whole transcript). STOP and "
                        "RETURN now: record what you've achieved and any landed session "
                        "names with `episodes__write_episode`, then emit your structured "
                        "result with your progress and the exact next step. The "
                        "orchestrator will re-task you with FRESH context to continue — "
                        "your tmux sessions persist by name, so you lose nothing. Do not "
                        "call other tools."
                    ),
                    tool_call_id=tool_call.get("id", "") or "",
                    name=name,
                    status="error",
                )
            return await handler(request)

    return StepBudget()
