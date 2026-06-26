"""Serialize the orchestrator's subagent delegation — one `task()` per turn.

The orchestrator delegates to subagents via the `task` tool deepagents injects.
When the model emits **more than one** `task` call in a single assistant turn,
langgraph's ToolNode runs them **concurrently** — two subagents execute
interleaved. That broke a real run (see `logs/debug_reactor3.jsonl`):

  * The orchestrator dispatched `researcher` + `postex` in one turn.
  * A parallel dispatch is a **join barrier**: the orchestrator can't resume
    until BOTH subagents return their structured result.
  * `postex` finished and did the real privesc enumeration, but the
    `researcher` branch spiralled into a long `browser__goto` crawl and never
    returned — so the orchestrator sat blocked on the dead-end branch and the
    whole engagement stalled.

There's also a latent correctness hazard: subagents share the stateful `shell`
server's tmux sessions. Two concurrent subagents both driving `shell__tmux_*`
would interleave commands into the same sessions and corrupt each other's
shells. The architecture gives the shell server sole ownership of stateful
processes precisely so this doesn't happen — but nothing stops a parallel
dispatch from violating it.

So this middleware enforces serial delegation deterministically: on a
multi-`task` turn it lets the **first** task run and returns a directive
ToolMessage for each of the others telling the orchestrator they were NOT
started and to re-issue them (or drop them) after the running one returns. The
model then dispatches one subagent at a time, with fresh context per delegation
— and can decide a now-redundant follow-up task isn't worth running.

Attach to the **orchestrator** only: subagents don't carry the `task` tool.
"""

from __future__ import annotations

from typing import Any

from ._util import messages_from_state as _messages_from_state


def _sibling_task_ids(messages: list[Any], tool_call_id: str) -> list[str]:
    """Ordered ids of the `task` tool calls in the AIMessage that emitted
    `tool_call_id`. Empty if not found.

    We scan from the end for the most recent message whose `tool_calls` include
    this id — that's the triggering assistant turn — and return the ids of the
    `task` calls within it, in emission order.
    """
    for m in reversed(messages):
        tcs = getattr(m, "tool_calls", None)
        if not tcs:
            continue
        ids = [tc.get("id") for tc in tcs]
        if tool_call_id not in ids:
            continue
        return [tc.get("id") for tc in tcs if tc.get("name") == "task" and tc.get("id")]
    return []


def serialize_tasks():
    """Return middleware that forces one `task()` delegation per turn.

    Deterministic — the prompt can ask the orchestrator to delegate serially,
    but this guarantees it. The first `task` in a multi-task turn runs; the rest
    are short-circuited with a directive to re-issue them sequentially.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    class SerializeTasks(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            name = getattr(tool, "name", "") or ""
            if name != "task":
                return await handler(request)

            tool_call = getattr(request, "tool_call", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""

            messages = _messages_from_state(getattr(request, "state", None))
            task_ids = _sibling_task_ids(messages, tool_call_id)

            # Lone task in this turn (or we couldn't resolve siblings) — run it.
            if len(task_ids) <= 1 or task_ids[0] == tool_call_id:
                return await handler(request)

            # A later task in a parallel batch — defer it, don't start the
            # subagent. The first task in the batch runs; the orchestrator
            # re-issues this one next turn if it still wants it.
            return ToolMessage(
                content=(
                    "PARALLEL_DISPATCH_BLOCKED: you dispatched multiple subagents in a "
                    "single turn. Subagents run concurrently and share stateful "
                    "resources (the shell server's tmux sessions), and a parallel "
                    "dispatch blocks you until ALL of them return — one slow or "
                    "dead-end branch stalls the whole engagement. This task was NOT "
                    "started. Wait for the task that IS running to return, review its "
                    "result, then re-issue this task if still needed (or drop it). "
                    "Delegate ONE subagent at a time."
                ),
                tool_call_id=tool_call_id,
                name=name,
                status="error",
            )

    return SerializeTasks()
