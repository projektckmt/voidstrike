"""Auto-log offensive tool calls to the episode log (verbatim command + output).

The analyst's report replays the episode log into a "Methodology — command &
output log" section — that's the writeup body. But subagents only hand-write a
few milestone *summaries* (and leave `tool_input` empty), so the methodology read
like a sparse summary rather than a writeup with the actual commands the agent
ran.

This middleware records every meaningful target-facing tool call — the real
`tool_input` (the command/args) and its output — as an episode, so the
methodology becomes a verbatim command-and-output writeup. It's deterministic:
the commands come straight from what was executed, not from the LLM
re-transcribing them later (which the report design deliberately avoids, to keep
the methodology hallucination-free).

Attached to the shell-/scan-driving subagents (surface, exploit, postex, ad) in
`build_agent`. Writes go through the gateway's own Postgres connection — the same
path the report's timeline loader already uses — so the offensive containers
still reach the log only via the episodes MCP server. Best-effort: any DB error
is swallowed so logging can never break a tool call.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger(__name__)

# Read-only / bookkeeping / plumbing tools that carry no methodology value:
# pane polling, session management, and the agent's own episode/finding writes
# (those are logged by the agent already). Everything else with an MCP `__`
# prefix is a real action worth recording in the writeup.
_SKIP_LOG = frozenset({
    "shell__tmux_read",
    "shell__tmux_list_sessions",
    "shell__stabilize_shell",
    "shell__tmux_new_session",
    "episodes__write_episode",
    "episodes__write_finding",
    "episodes__read_episode_tail",
    "episodes__read_engagement",
    "episodes__list_findings",
    "episodes__summarize_engagement",
})

# Per-episode output cap. The report trims further (to _STEP_OUTPUT_CHARS); this
# just stops a giant scan dump from bloating a row.
_OUTPUT_CAP = 8000


def _loggable(name: str) -> bool:
    """A real target-facing MCP tool call worth recording (not a read/plumbing one)."""
    return "__" in name and name not in _SKIP_LOG


def _stringify_output(result: Any) -> str:
    """Best-effort decode of a ToolMessage's content into plain text, capped."""
    content = getattr(result, "content", result)
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text", block)))
            else:
                parts.append(str(getattr(block, "text", block)))
        content = "".join(parts)
    text = "" if content is None else str(content)
    return text[:_OUTPUT_CAP]


def _insert_episode(
    pg_url: str,
    engagement_id: str,
    agent_name: str,
    action: str,
    tool_input: dict[str, Any],
    tool_output: str,
    outcome_tag: str,
    error: str | None,
) -> None:
    """Synchronous direct INSERT — run via asyncio.to_thread so it never blocks
    the event loop. Mirrors the episodes MCP server's write shape."""
    import psycopg  # noqa: PLC0415

    with psycopg.connect(pg_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO episodes (
                    engagement_id, agent_name, ts, action, tool_input,
                    tool_output, outcome_tag, cost_usd, duration_ms, error
                ) VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)
                """,
                (
                    engagement_id,
                    agent_name,
                    datetime.now(UTC),
                    action,
                    json.dumps(tool_input or {}, default=str),
                    tool_output,
                    outcome_tag,
                    0.0,
                    0,
                    error,
                ),
            )
        conn.commit()


def command_logger(engagement_id: str | None, agent_name: str, *, pg_url: str | None = None):
    """Return middleware that appends an episode for each meaningful tool call.

    `engagement_id` ties the rows to the run (it's the LangGraph `thread_id`); a
    falsy value disables logging (the middleware then just passes calls through).
    `agent_name` is the subagent's name, recorded as the episode's author.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415

    url = pg_url or os.environ.get(
        "POSTGRES_URL", "postgresql://voidstrike:changeme@postgres:5432/voidstrike"
    )

    class CommandLogger(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            result = await handler(request)
            try:
                tool = getattr(request, "tool", None)
                name = getattr(tool, "name", "") or ""
                if engagement_id and _loggable(name):
                    tool_call = getattr(request, "tool_call", {}) or {}
                    args = tool_call.get("args", {}) or {}
                    output = _stringify_output(result)
                    status = getattr(result, "status", "")
                    error = output if status == "error" else None
                    # `ok`, not `no_result`: this auto-logs that a tool *ran*, it
                    # doesn't inspect the output. `no_result`/`new_finding` are the
                    # agent's own assertions via episodes__write_episode.
                    outcome = "error" if status == "error" else "ok"
                    await asyncio.to_thread(
                        _insert_episode,
                        url, engagement_id, agent_name, name, args, output, outcome, error,
                    )
            except Exception:  # noqa: BLE001 — logging must never break a tool call
                log.debug("command_logger: failed to record episode for tool call", exc_info=True)
            return result

    # Distinct class name per subagent so langchain doesn't reject two instances
    # (it dedupes middleware by class name) when several subagents each carry one.
    CommandLogger.__name__ = f"CommandLogger_{agent_name}"
    CommandLogger.__qualname__ = CommandLogger.__name__
    return CommandLogger()
