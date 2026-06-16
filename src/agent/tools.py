"""In-process orchestrator tools.

These don't need to live in MCP servers — they're pure state operations against
the engagement filesystem. The orchestrator binds them directly. Phase 2.
"""

from __future__ import annotations

import datetime as _dt
import os
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from . import lab_state
from .lab_state import HostStatus

ENGAGEMENT_DIR = Path(os.environ.get("ENGAGEMENT_DIR", "./engagements"))


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@tool
def mark_host_owned(engagement_id: str, host: str, notes: str = "") -> dict[str, Any]:
    """Mark a host as owned (foothold landed). Lab/engagement modes use this to
    track breadth-first progress across a multi-host scope."""
    state = lab_state.load(ENGAGEMENT_DIR, engagement_id)
    state.upsert(host, status=HostStatus.OWNED, reason="foothold landed", notes=notes, last_change=_now())
    lab_state.save(state, ENGAGEMENT_DIR)
    return {"ok": True, "progress": state.progress()}


@tool
def mark_host_skipped(engagement_id: str, host: str, reason: str = "") -> dict[str, Any]:
    """Mark a host as skipped (out of scope after probing, or low-value). It
    won't be picked up by `next_target` again."""
    state = lab_state.load(ENGAGEMENT_DIR, engagement_id)
    state.upsert(host, status=HostStatus.SKIPPED, reason=reason, last_change=_now())
    lab_state.save(state, ENGAGEMENT_DIR)
    return {"ok": True, "progress": state.progress()}


@tool
def mark_host_dead(engagement_id: str, host: str) -> dict[str, Any]:
    """Mark a host as unreachable / no services. Tried, nothing there."""
    state = lab_state.load(ENGAGEMENT_DIR, engagement_id)
    state.upsert(host, status=HostStatus.DEAD, last_change=_now())
    lab_state.save(state, ENGAGEMENT_DIR)
    return {"ok": True, "progress": state.progress()}


@tool
def add_pending_hosts(engagement_id: str, hosts: list[str]) -> dict[str, Any]:
    """Register hosts discovered during recon. They become candidates for
    `next_target` if not already known."""
    state = lab_state.load(ENGAGEMENT_DIR, engagement_id)
    for host in hosts:
        if host not in state.hosts:
            state.upsert(host, status=HostStatus.PENDING, last_change=_now())
    lab_state.save(state, ENGAGEMENT_DIR)
    return {"ok": True, "progress": state.progress(), "registered": hosts}


@tool
def next_target(engagement_id: str) -> dict[str, Any]:
    """Return the next pending host (FIFO). Returns `{host: None}` when the
    lab is exhausted."""
    state = lab_state.load(ENGAGEMENT_DIR, engagement_id)
    pending = state.pending()
    if not pending:
        return {"host": None, "progress": state.progress()}
    record = pending[0]
    state.upsert(record.address, status=HostStatus.PROBING, last_change=_now())
    lab_state.save(state, ENGAGEMENT_DIR)
    return {"host": record.address, "progress": state.progress()}


@tool
def lab_progress(engagement_id: str) -> dict[str, Any]:
    """Snapshot of breadth-tracking state for the orchestrator's read step."""
    state = lab_state.load(ENGAGEMENT_DIR, engagement_id)
    return {
        "progress": state.progress(),
        "owned": [r.address for r in state.owned()],
        "pending": [r.address for r in state.pending()][:50],
    }


@tool
def write_objective(engagement_id: str, objective: str) -> dict[str, Any]:
    """Update the current objective string. The stuck detector reads this so
    the StuckReport shows what we were trying to do."""
    obj_path = ENGAGEMENT_DIR / engagement_id / "objective.txt"
    obj_path.parent.mkdir(parents=True, exist_ok=True)
    obj_path.write_text(objective)
    return {"ok": True}


@tool
def record_flag(engagement_id: str, flag: str, host: str = "", path: str = "") -> dict[str, Any]:
    """Record a captured flag (CTF/lab modes). One line per flag, append-only."""
    flag_path = ENGAGEMENT_DIR / engagement_id / "flags.txt"
    flag_path.parent.mkdir(parents=True, exist_ok=True)
    line = f"{_now()} host={host} path={path} {flag}\n"
    with flag_path.open("a") as fh:
        fh.write(line)
    return {"ok": True, "flag_count_file": str(flag_path)}


@tool
async def read_episode_tail(engagement_id: str, n: int = 30) -> dict[str, Any]:
    """Read the most recent N episodes for this engagement, newest first.

    The episode log is the engagement's source of truth — subagents append to it
    as they work. Read it before triaging so you can see what's already been
    tried (and what produced findings) instead of re-deriving it. Pass the
    `engagement_id` from your kickoff message verbatim.
    """
    import psycopg  # noqa: PLC0415
    from psycopg.rows import dict_row  # noqa: PLC0415

    pg_url = os.environ.get(
        "POSTGRES_URL", "postgresql://voidstrike:changeme@postgres:5432/voidstrike"
    )
    try:
        n = int(n)  # the model sometimes passes "30" as a string
    except (TypeError, ValueError):
        n = 30
    n = max(1, min(n, 200))

    try:
        async with await psycopg.AsyncConnection.connect(pg_url) as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(
                    """
                    SELECT id, agent_name, ts, action, outcome_tag, tool_output, error
                    FROM episodes
                    WHERE engagement_id = %s
                    ORDER BY ts DESC
                    LIMIT %s
                    """,
                    (engagement_id, n),
                )
                rows = await cur.fetchall()
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"could not read episode log: {exc}"}

    episodes = [
        {
            "id": r["id"],
            "agent_name": r["agent_name"],
            "timestamp": r["ts"].isoformat() if r["ts"] else None,
            "action": r["action"],
            "outcome_tag": r["outcome_tag"],
            # Trim output so a tail read doesn't blow up the orchestrator context.
            "tool_output": (r["tool_output"] or "")[:1000],
            "error": r["error"],
        }
        for r in rows
    ]
    return {"ok": True, "count": len(episodes), "episodes": episodes}


# Cap on methodology-log steps pulled into the report — a writeup wants the
# full narrative, but an unbounded run shouldn't produce a multi-MB report.md.
_TIMELINE_MAX_STEPS = 500


def _load_episode_timeline(engagement_id: str) -> list[dict[str, Any]]:
    """Read the full episode log in chronological order for the methodology
    writeup. Best-effort: a DB hiccup yields an empty timeline, never a failed
    report (the findings sections don't depend on this)."""
    import psycopg  # noqa: PLC0415
    from psycopg.rows import dict_row  # noqa: PLC0415

    pg_url = os.environ.get(
        "POSTGRES_URL", "postgresql://voidstrike:changeme@postgres:5432/voidstrike"
    )
    try:
        with psycopg.connect(pg_url) as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT agent_name, ts, action, tool_input, tool_output,
                           outcome_tag, error
                    FROM episodes
                    WHERE engagement_id = %s
                    ORDER BY ts ASC
                    LIMIT %s
                    """,
                    (engagement_id, _TIMELINE_MAX_STEPS),
                )
                rows = cur.fetchall()
    except Exception:  # noqa: BLE001 — timeline is optional; never block the report
        return []

    return [
        {
            "agent_name": r["agent_name"],
            "timestamp": r["ts"].isoformat() if r["ts"] else None,
            "action": r["action"],
            "tool_input": r["tool_input"],
            "tool_output": r["tool_output"],
            "outcome_tag": r["outcome_tag"],
            "error": r["error"],
        }
        for r in rows
    ]


@tool
def render_report(
    engagement_id: str,
    engagement_name: str,
    mode: str,
    targets: list[str],
    findings: list[dict[str, Any]],
    flags: list[str] | None = None,
    failed_objectives: list[str] | None = None,
    executive_summary: str = "",
    episode_summary: str = "",
    walkthrough: str = "",
    include_timeline: bool = True,
) -> dict[str, Any]:
    """Build the final engagement report (Markdown) from collected state.

    The analyst subagent calls this after `episodes__list_findings`. Deterministic
    parts (severity rollup, ATT&CK mapping, grouping by host) happen here so the
    LLM cannot hallucinate counts.

    `walkthrough` is your authored narrative (oxdf/HTB-writeup style) — prose
    organized by phase with fenced `$ <command>` + key-output blocks quoted
    verbatim from the episode log. It becomes the report's main "## Walkthrough"
    section. Quote real commands only; the deterministic appendix is the ground
    truth you draw from.

    When `include_timeline` is set (default), the full episode log — every
    command and its output — is replayed chronologically into the appendix
    section. The data comes straight from the
    episode log, so the commands and outputs are verbatim, not LLM-transcribed.
    """
    from .report import build_report

    flag_path = ENGAGEMENT_DIR / engagement_id / "flags.txt"
    if flags is None and flag_path.exists():
        flags = [line.strip() for line in flag_path.read_text().splitlines() if line.strip()]

    timeline = _load_episode_timeline(engagement_id) if include_timeline else []

    report = build_report(
        engagement_name=engagement_name,
        mode=mode,
        target_summary=targets,
        findings=findings,
        flags=flags or [],
        failed_objectives=failed_objectives or [],
        executive_summary=executive_summary,
        episode_summary=episode_summary,
        walkthrough=walkthrough,
        timeline=timeline,
    )

    out_path = ENGAGEMENT_DIR / engagement_id / "report.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report.to_markdown())
    return {
        "ok": True,
        "path": str(out_path),
        "severity_rollup": report.severity_rollup,
        "timeline_steps": len(timeline),
    }


ORCHESTRATOR_TOOLS = [
    mark_host_owned,
    mark_host_skipped,
    mark_host_dead,
    add_pending_hosts,
    next_target,
    lab_progress,
    write_objective,
    record_flag,
    read_episode_tail,
]

ANALYST_TOOLS = [render_report]
