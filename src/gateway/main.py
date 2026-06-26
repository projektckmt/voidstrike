"""FastAPI gateway. CLI + Web dashboard both talk to this."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import traceback
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import redis.asyncio as redis
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("voidstrike.gateway")

# Each engagement keeps a backlog of recent events in a Redis list so SSE
# subscribers see what happened before they connected (fixes the publish-before-
# subscribe race for short-lived clients).
EVENT_BACKLOG_MAX = 500

from ..schemas.engagement import EngagementSpec  # noqa: E402

app = FastAPI(title="Voidstrike", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
ENGAGEMENT_DIR = Path(os.environ.get("ENGAGEMENT_DIR", "./engagements"))
ENGAGEMENT_DIR.mkdir(parents=True, exist_ok=True)

# Why direct Postgres instead of round-tripping the episodes MCP server:
# the MCP HTTP transport is a stream/event protocol over `/mcp`, not a REST
# tree at `/mcp/tools/<name>`. The dashboard-facing read endpoints below
# (findings/episodes/etc.) were originally written to POST a REST URL that
# doesn't exist, which returned 404 and made the engagement view appear
# empty. The data is in Postgres regardless of which client wrote it, so
# we query it directly here.
POSTGRES_URL = os.environ.get(
    "POSTGRES_URL",
    "postgresql://voidstrike:changeme@postgres:5432/voidstrike",
)

_redis: redis.Redis | None = None
_pg_pool = None  # lazy-initialized psycopg_pool.AsyncConnectionPool

# Live engagement tasks, keyed by engagement_id. We track these so `/cancel`
# can call `task.cancel()` on the specific run. Tasks are removed from this
# dict in `_run_engagement`'s finally block.
_engagement_tasks: dict[str, asyncio.Task] = {}


def _get_redis() -> redis.Redis:
    global _redis
    if _redis is None:
        _redis = redis.from_url(REDIS_URL, decode_responses=True)
    return _redis


def _get_pg_pool():
    """Lazy psycopg_pool. Opens on first use; the pool itself is async and
    needs `await pool.open()` before the first connection is taken."""
    global _pg_pool
    if _pg_pool is None:
        from psycopg_pool import AsyncConnectionPool  # noqa: PLC0415
        _pg_pool = AsyncConnectionPool(POSTGRES_URL, open=False, min_size=1, max_size=8)
    return _pg_pool


# `infra/postgres-init.sql` creates the engagements table, but only on a *fresh*
# volume's first boot — a pre-existing DB never gets it. Ensure it here too
# (idempotent), mirroring the self-heal in the episodes MCP server. Columns match
# postgres-init.sql exactly.
_ENGAGEMENTS_DDL = """
CREATE TABLE IF NOT EXISTS engagements (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    mode            TEXT NOT NULL CHECK (mode IN ('ctf','lab','engagement')),
    profile         TEXT NOT NULL DEFAULT 'eco',
    spec_yaml       TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'running',
    budget_usd      NUMERIC(10, 4) NOT NULL DEFAULT 10.0,
    cost_usd        NUMERIC(10, 4) NOT NULL DEFAULT 0.0,
    notes           TEXT NOT NULL DEFAULT ''
);
"""

_engagements_schema_ready = False


async def _ready_engagements_pool():
    """Open the pool and ensure the engagements table exists (once per process)."""
    global _engagements_schema_ready
    pool = _get_pg_pool()
    await pool.open()
    if not _engagements_schema_ready:
        async with pool.connection() as conn:
            await conn.execute(_ENGAGEMENTS_DDL)
            await conn.commit()
        _engagements_schema_ready = True
    return pool


class StartEngagementResponse(BaseModel):
    engagement_id: str
    thread_id: str
    spec_path: str


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/engagements", response_model=StartEngagementResponse)
async def start_engagement(
    spec: UploadFile = File(...),
    vpn_config: UploadFile | None = File(None),
    profile: str = Form("eco"),
) -> StartEngagementResponse:
    """Upload a spec (YAML) and optional .ovpn; kick off the engagement.

    We use `asyncio.create_task` directly (not FastAPI's `BackgroundTasks`)
    so we can hold a reference and cancel the task via `/cancel`.
    """
    engagement_id = str(uuid.uuid4())
    out_dir = ENGAGEMENT_DIR / engagement_id
    out_dir.mkdir(parents=True, exist_ok=True)
    spec_path = out_dir / "spec.yaml"
    spec_path.write_bytes(await spec.read())

    if vpn_config is not None:
        vpn_path = out_dir / "client.ovpn"
        vpn_path.write_bytes(await vpn_config.read())
        # Patch the spec to point at the saved file.
        parsed = EngagementSpec.from_yaml(spec_path)
        parsed.vpn_config = str(vpn_path)
        spec_path.write_text(parsed.model_dump_json(indent=2))

    # Persist the profile so `/resume` can rebuild the agent with the same
    # model tier configuration without requiring the operator to re-specify.
    (out_dir / "profile").write_text(profile)

    # Persist a durable engagements row so `started_at` survives independently of
    # filesystem mtimes. Best-effort: a DB hiccup must not stop the run starting —
    # list_engagements falls back to the spec file's mtime when the row is absent.
    try:
        parsed_spec = EngagementSpec.from_yaml(spec_path)
        pool = await _ready_engagements_pool()
        async with pool.connection() as conn:
            await conn.execute(
                """
                INSERT INTO engagements (id, name, mode, profile, spec_yaml, budget_usd)
                VALUES (%s::uuid, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (
                    engagement_id,
                    parsed_spec.name,
                    parsed_spec.mode.value,
                    profile,
                    spec_path.read_text(),
                    parsed_spec.budget_usd,
                ),
            )
            await conn.commit()
    except Exception as exc:  # noqa: BLE001
        log.warning("engagement %s: failed to persist engagements row: %s", engagement_id, exc)

    task = asyncio.create_task(
        _run_engagement(str(spec_path), engagement_id, profile),
        name=f"engagement-{engagement_id}",
    )
    _engagement_tasks[engagement_id] = task
    return StartEngagementResponse(
        engagement_id=engagement_id,
        thread_id=engagement_id,
        spec_path=str(spec_path),
    )


@app.post("/engagements/{engagement_id}/cancel")
async def cancel_engagement(engagement_id: str) -> dict[str, Any]:
    """Cancel a running or paused engagement. Triggered by the CLI when the
    operator runs `voidstrike cancel`."""
    task = _engagement_tasks.get(engagement_id)

    # Paused engagement: no live task, but we still want /cancel to be a
    # proper terminal action. Clear the marker + emit cancelled.
    if (task is None or task.done()) and _is_paused(engagement_id):
        log.info("engagement %s: cancel requested while paused", engagement_id)
        _paused_marker_path(engagement_id).unlink(missing_ok=True)
        await _emit(engagement_id, {
            "event": "cancelled",
            "reason": "operator cancelled a paused engagement",
        })
        return {"engagement_id": engagement_id, "status": "cancelled"}

    if task is None:
        # Either it already finished or it's not ours. Either way the right
        # response is "not running". 404 vs 200 here is debatable; we go
        # with 200 + a status so the CLI doesn't trip on a missing task.
        return {"engagement_id": engagement_id, "status": "not_running"}
    if task.done():
        return {"engagement_id": engagement_id, "status": "already_finished"}
    log.info("engagement %s: cancellation requested by operator", engagement_id)
    await _emit(engagement_id, {
        "event": "cancelling",
        "reason": "operator requested cancellation",
    })
    task.cancel()
    # Cancel supersedes pause — clear the marker so resume can't pick this back up.
    _paused_marker_path(engagement_id).unlink(missing_ok=True)
    return {"engagement_id": engagement_id, "status": "cancelling"}


def _paused_marker_path(engagement_id: str) -> Path:
    return ENGAGEMENT_DIR / engagement_id / ".paused"


def _is_paused(engagement_id: str) -> bool:
    return _paused_marker_path(engagement_id).exists()


@app.post("/engagements/{engagement_id}/pause")
async def pause_engagement(engagement_id: str) -> dict[str, Any]:
    """Pause a running engagement.

    Cancels the running asyncio task and writes a `.paused` marker. The
    LangGraph checkpoint in Postgres is what carries state across the pause —
    on `/resume` we start a new task that calls `astream(None, ...)` against
    the same `thread_id` and the agent picks up from the last completed step.

    Any in-flight tool call (a running nmap / ffuf, etc.) is killed by the
    `task.cancel()`. Worst case the agent loses one tool result on resume.
    """
    task = _engagement_tasks.get(engagement_id)
    if task is None:
        return {"engagement_id": engagement_id, "status": "not_running"}
    if task.done():
        return {"engagement_id": engagement_id, "status": "already_finished"}

    log.info("engagement %s: pause requested by operator", engagement_id)
    marker = _paused_marker_path(engagement_id)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    await _emit(engagement_id, {
        "event": "paused",
        "reason": "operator requested pause",
    })
    task.cancel()
    return {"engagement_id": engagement_id, "status": "pausing"}


@app.post("/engagements/{engagement_id}/resume")
async def resume_engagement(engagement_id: str) -> dict[str, Any]:
    """Resume a paused engagement.

    Reads the saved spec from disk, removes the `.paused` marker, and starts
    a new asyncio task that continues the agent from its last checkpoint.
    """
    if engagement_id in _engagement_tasks and not _engagement_tasks[engagement_id].done():
        return {"engagement_id": engagement_id, "status": "already_running"}

    spec_path = ENGAGEMENT_DIR / engagement_id / "spec.yaml"
    if not spec_path.exists():
        raise HTTPException(status_code=404, detail=f"engagement {engagement_id} has no saved spec")

    if not _is_paused(engagement_id):
        # Not paused. Could be finished, cancelled, or never started.
        # We don't auto-resume a terminal engagement — the operator should
        # start a fresh one. Return a status the CLI can render usefully.
        return {"engagement_id": engagement_id, "status": "not_paused"}

    # Read the profile back from the engagement directory if we recorded it.
    profile_path = ENGAGEMENT_DIR / engagement_id / "profile"
    profile = profile_path.read_text().strip() if profile_path.exists() else "eco"

    log.info("engagement %s: resume requested by operator (profile=%s)", engagement_id, profile)
    _paused_marker_path(engagement_id).unlink(missing_ok=True)
    await _emit(engagement_id, {
        "event": "resuming",
        "reason": "operator requested resume",
    })
    task = asyncio.create_task(
        _run_engagement(str(spec_path), engagement_id, profile, resume=True),
        name=f"engagement-{engagement_id}-resume",
    )
    _engagement_tasks[engagement_id] = task
    return {"engagement_id": engagement_id, "status": "resuming"}


@app.post("/engagements/cancel_all")
async def cancel_all_engagements() -> dict[str, Any]:
    """Cancel every running engagement. Returns a per-engagement status list.

    NB: route declared *before* any `/engagements/{id}/...` patterns above —
    FastAPI matches routes in declaration order and `cancel_all` would
    otherwise be captured by `{engagement_id}`. (Path here is unambiguous
    because we use `/engagements/cancel_all` not `/engagements/{id}/cancel_all`.)
    """
    results: list[dict[str, Any]] = []
    # Snapshot to avoid mutation-during-iteration when tasks finish + remove
    # themselves from `_engagement_tasks` mid-loop.
    for eng_id, task in list(_engagement_tasks.items()):
        if task.done():
            results.append({"engagement_id": eng_id, "status": "already_finished"})
            continue
        log.info("engagement %s: cancellation requested via cancel_all", eng_id)
        await _emit(eng_id, {
            "event": "cancelling",
            "reason": "operator requested cancellation (cancel_all)",
        })
        task.cancel()
        results.append({"engagement_id": eng_id, "status": "cancelling"})
    return {
        "cancelled_count": sum(1 for r in results if r["status"] == "cancelling"),
        "total": len(results),
        "engagements": results,
    }


async def _emit(engagement_id: str, payload: dict) -> None:
    """Publish to Redis pubsub AND append to the backlog list.

    SSE subscribers replay the backlog on connect, then live-tail via pubsub.
    Without the backlog, anything emitted before the CLI/dashboard subscribes
    is lost.
    """
    r = _get_redis()
    blob = json.dumps(payload)
    backlog_key = f"engagement:{engagement_id}:backlog"
    channel = f"engagement:{engagement_id}"
    # Append + trim atomically, then publish for live tails.
    pipe = r.pipeline()
    pipe.rpush(backlog_key, blob)
    pipe.ltrim(backlog_key, -EVENT_BACKLOG_MAX, -1)
    pipe.expire(backlog_key, 86400)
    pipe.publish(channel, blob)
    await pipe.execute()


async def _reset_shell_sessions(engagement_id: str) -> None:
    """Ask the shell MCP server to purge every live tmux session.

    Best-effort: if the shell container is unreachable we log and continue
    — the engagement can still run, the operator just keeps the stale
    state. The endpoint is `/admin/reset` on the shell server (non-MCP,
    declared via `app.custom_route` in src/mcp_servers/shell/server.py).
    """
    base = os.environ.get("MCP_SHELL_URL", "http://shell-mcp:8080/mcp")
    # MCP_SHELL_URL points at the streamable-http MCP path; the admin route
    # is a sibling on the same server, not under /mcp.
    reset_url = base.rstrip("/").removesuffix("/mcp") + "/admin/reset"
    try:
        import httpx  # noqa: PLC0415
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(reset_url)
        if resp.status_code != 200:
            log.warning(
                "engagement %s: shell reset returned HTTP %s — continuing",
                engagement_id, resp.status_code,
            )
            return
        body = resp.json()
        count = body.get("count", 0)
        if count:
            log.info("engagement %s: purged %d stale tmux session(s) before start", engagement_id, count)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "engagement %s: shell reset failed (%s) — continuing with stale state",
            engagement_id, exc,
        )


async def _ensure_report_exists(engagement_id: str, spec_path: str) -> None:
    """Write a minimal `report.md` if the analyst didn't.

    Best-effort: pulls flags from `flags.txt`, findings from the Postgres
    `findings` table, and target list from the engagement spec. Emits a
    warning event so the operator knows the report came from the safety
    net rather than the analyst's writeup.
    """
    report_path = ENGAGEMENT_DIR / engagement_id / "report.md"
    if report_path.exists():
        return

    try:
        flag_path = ENGAGEMENT_DIR / engagement_id / "flags.txt"
        flags = (
            [line.strip() for line in flag_path.read_text().splitlines() if line.strip()]
            if flag_path.exists()
            else []
        )

        try:
            from ..schemas.engagement import EngagementSpec
            spec = EngagementSpec.from_yaml(spec_path)
            engagement_name = spec.name
            mode = spec.mode.value
            targets = spec.targets
        except Exception:  # noqa: BLE001
            engagement_name = engagement_id
            mode = "unknown"
            targets = []

        findings: list[dict[str, Any]] = []
        try:
            from psycopg.rows import dict_row  # noqa: PLC0415
            pool = _get_pg_pool()
            await pool.open()
            async with pool.connection() as conn:
                async with conn.cursor(row_factory=dict_row) as cur:
                    await cur.execute(
                        """
                        SELECT title, severity, host, description, evidence,
                               suggested_remediation
                        FROM findings
                        WHERE engagement_id = %s
                        ORDER BY ts ASC
                        """,
                        (engagement_id,),
                    )
                    findings = [dict(r) for r in await cur.fetchall()]
        except Exception:  # noqa: BLE001
            log.warning("safety-net report: failed to read findings from Postgres", exc_info=True)

        from ..agent.report import build_report
        report = build_report(
            engagement_name=engagement_name,
            mode=mode,
            target_summary=targets,
            findings=findings,
            flags=flags,
            failed_objectives=[],
            executive_summary=(
                "Auto-generated stub — the analyst subagent did not call "
                "`render_report`. Findings and flags listed below come from the "
                "Postgres episode/finding log and the on-disk flags file."
            ),
            episode_summary="",
        )
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report.to_markdown())
        log.warning("engagement %s: wrote safety-net report.md (analyst skipped render_report)", engagement_id)
        await _emit(engagement_id, {
            "event": "report_fallback",
            "reason": "analyst skipped render_report; wrote a stub from durable state",
            "path": str(report_path),
        })
    except Exception:  # noqa: BLE001
        log.exception("engagement %s: safety-net report write failed", engagement_id)


def _kickoff_text(spec: Any, engagement_id: str) -> str:
    """The operator-style HumanMessage that starts the orchestrator loop.

    Carries the engagement context and, when the spec has operator `notes`, an
    OPERATOR BRIEFING block — the channel for pre-engagement context the agent
    must act on (e.g. assumed-breach / provided credentials, an internal hostname,
    a scope hint). Without this the `notes` field never reached the agent.
    """
    lines = [
        f"Begin engagement {engagement_id}.",
        f"Target(s): {', '.join(spec.targets)}",
        f"Objective: {spec.objective}",
        f"Mode: {spec.mode.value}",
    ]
    briefing = (spec.notes or "").strip()
    if briefing:
        lines += [
            "",
            "OPERATOR BRIEFING — pre-engagement notes from the operator. Treat as "
            "ground truth, act on it, and relay anything a subagent needs (provided "
            "credentials, internal hostnames, scope hints) into its task brief:",
            briefing,
        ]
    lines += ["", "Follow the loop in your system prompt. Start with Surface."]
    return "\n".join(lines)


def _extract_interrupt(update: Any) -> Any | None:
    """Pull a HITL interrupt payload out of a stream update, or None.

    LangGraph surfaces an `interrupt()` as `{"__interrupt__": (Interrupt(...),)}`
    in the streamed update dict. We return the first interrupt's `.value` — the
    dict the middleware passed to `interrupt()` (e.g. `{"kind": "stuck_report",
    ...}`)."""
    if not isinstance(update, dict):
        return None
    intr = update.get("__interrupt__")
    if not intr:
        return None
    first = intr[0] if isinstance(intr, (list, tuple)) else intr
    return getattr(first, "value", first)


async def _await_hitl_reply(engagement_id: str, payload: Any) -> Any:
    """Enqueue a pending HITL interrupt, block until the operator replies, and
    return the reply value to resume the graph with.

    Publishes the pending item to `hitl:queue` (the cross-engagement queue the
    dashboards read) and, for stuck reports, to `engagement:{id}:stuck`, then
    waits on the per-engagement reply channel that the `approve` /
    `stuck_response` endpoints publish to. The pending item is removed once
    answered. Operator pause/cancel propagates out of the `get_message` await and
    tears the wait down via the normal CancelledError path."""
    r = _get_redis()
    kind = payload.get("kind") if isinstance(payload, dict) else None
    item = json.dumps({
        "engagement_id": engagement_id,
        **(payload if isinstance(payload, dict) else {"value": payload}),
    })

    pubsub = r.pubsub()
    # Subscribe BEFORE enqueuing so an unusually fast reply can't slip past us
    # (the same publish-before-subscribe race the SSE backlog guards against).
    await pubsub.subscribe(f"engagement:{engagement_id}:hitl")
    await r.rpush("hitl:queue", item)
    if kind == "stuck_report":
        await r.rpush(f"engagement:{engagement_id}:stuck", item)
    await _emit(engagement_id, {"event": "hitl_pending", "kind": kind, "payload": _safe(payload)})

    try:
        while True:
            try:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=15.0)
            except RedisTimeoutError:
                continue  # idle — a human can take a while; keep waiting
            if msg is None:
                continue
            try:
                return json.loads(msg["data"])
            except (json.JSONDecodeError, TypeError, KeyError):
                continue  # malformed reply — ignore and keep waiting
    finally:
        await pubsub.unsubscribe(f"engagement:{engagement_id}:hitl")
        await pubsub.close()
        await r.lrem("hitl:queue", 1, item)
        if kind == "stuck_report":
            await r.lrem(f"engagement:{engagement_id}:stuck", 1, item)
        await _emit(engagement_id, {"event": "hitl_resolved", "kind": kind})


def _walk_record_flags(obj: Any) -> list[str]:
    """Recursively pull flag strings from `record_flag` tool calls anywhere in a
    (JSON-safe) event payload — the orchestrator records each captured flag via
    that tool. Mirrors the CLI's extractor so HTB flag-submit works server-side."""
    found: list[str] = []
    if isinstance(obj, dict):
        if obj.get("name") == "record_flag":
            args = obj.get("args") or obj.get("input") or {}
            flag = args.get("flag") if isinstance(args, dict) else None
            if isinstance(flag, str) and flag.strip():
                found.append(flag.strip())
        for v in obj.values():
            found.extend(_walk_record_flags(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(_walk_record_flags(v))
    return found


def _root_signal_in_event(safe_update: Any) -> bool:
    """True if an event payload carries a root/objective-capture signal. Lets an
    HTB run count as solved even when the spec didn't set `expected_flags`."""
    blob = json.dumps(safe_update).lower()
    return "objective_met" in blob or "root flag captured" in blob


def _htb_solved(flags: list[str], rooted: bool, expected_flags: int | None) -> bool:
    """HTB success = a root/objective signal, or at least `expected_flags` distinct
    flags captured (only when the spec sets a positive count)."""
    if rooted:
        return True
    return expected_flags is not None and expected_flags > 0 and len(flags) >= expected_flags


def _rewrite_spec_targets(spec_path: str, targets: list[str]) -> None:
    """Persist `targets` into the saved spec so build_agent + the kickoff use the
    spawned box's IP. Written as JSON (valid YAML), which `from_yaml` reads back."""
    from ..schemas.engagement import EngagementSpec  # noqa: PLC0415
    spec = EngagementSpec.from_yaml(spec_path)
    spec.targets = targets
    Path(spec_path).write_text(spec.model_dump_json(indent=2))


async def _htb_spawn(cfg: Any, engagement_id: str):
    """Resolve + spawn (or reuse) the spec's HTB machine and return its live IP.

    Returns `(client, machine, ip)`. The caller owns `client` and must
    `aclose()` it (see `_htb_finalize`). Raises `HtbError` on failure (after
    closing the client). A *different* already-spawned box is terminated first —
    HTB allows one active machine, so a leftover would just block the run."""
    from ..integrations.htb import HtbClient, HtbError  # noqa: PLC0415

    token = os.environ.get("HTB_TOKEN", "").strip()
    if not token:
        raise HtbError(
            "spec has an `htb:` block but HTB_TOKEN is not set in the gateway "
            "environment — add it to .env so the gateway can provision the box"
        )

    async def ev(stage: str, msg: str) -> None:
        await _emit(engagement_id, {"event": "htb", "stage": stage, "message": msg})

    client = HtbClient(token=token)
    try:
        machine = await client.resolve_machine(cfg.machine)
        await ev("resolve", f"id={machine.id} kind={machine.kind}")
        active = await client.active_machine()
        if active and active.id != machine.id:
            await ev("preflight", f"terminating other active machine {active.name!r}")
            await client.terminate(active)
        if active and active.id == machine.id:
            machine.ip = active.ip
            if cfg.reset_before:
                await ev("reset", "resetting already-spawned target to clean state")
                await client.reset(machine)
            await ev("spawn", "target already spawned; reusing")
        else:
            await ev("spawn", "requesting spawn")
            await client.spawn(machine)
        ip = machine.ip or await client.wait_for_ip(machine, timeout_s=cfg.spawn_timeout_s)
        machine.ip = ip
        await ev("ready", f"target IP {ip}")
        return client, machine, ip
    except Exception:
        await client.aclose()
        raise


async def _htb_finalize(
    client: Any, machine: Any, cfg: Any, *, status: str, flags: list[str], engagement_id: str
) -> None:
    """Submit captured flags (best-effort) and tear the box down per policy, then
    close the client. Never raises — teardown failure must not mask the run.

    Safe to call from `_run_engagement`'s finally: by then any operator-cancel
    CancelledError has been caught (not re-raised), so these awaits run."""
    from ..agent.challenge import _should_teardown  # noqa: PLC0415
    from ..integrations.htb import HtbError  # noqa: PLC0415

    async def ev(stage: str, msg: str) -> None:
        await _emit(engagement_id, {"event": "htb", "stage": stage, "message": msg})

    try:
        submitted: list[str] = []
        if cfg.submit_flags and flags:
            for flag in flags:
                try:
                    await client.submit_flag(machine, flag, difficulty=cfg.difficulty)
                    submitted.append(flag)
                except HtbError as exc:
                    await ev("flag", f"submit failed ({flag[:8]}…): {exc}")
            if submitted:
                await ev("flag", f"{len(submitted)} flag(s) submitted to HTB")
        if _should_teardown(cfg.teardown, status):
            try:
                await client.terminate(machine)
                await ev("teardown", "machine terminated")
            except HtbError as exc:
                await ev("teardown", f"failed (leaving machine up): {exc}")
        else:
            await ev("teardown", f"skipped (policy={cfg.teardown}, status={status})")
    finally:
        await client.aclose()


async def _run_engagement(
    spec_path: str,
    engagement_id: str,
    profile: str,
    *,
    resume: bool = False,
) -> None:
    """Drives one engagement to completion, streaming events into Redis.

    `resume=True` skips the kickoff `HumanMessage` and feeds `None` to
    `astream`, which makes LangGraph continue from the last Postgres
    checkpoint for this `thread_id`.
    """
    log.info(
        "engagement %s %s (spec=%s, profile=%s)",
        engagement_id, "resuming" if resume else "starting", spec_path, profile,
    )
    if not resume:
        await _emit(engagement_id, {"event": "start", "engagement_id": engagement_id})
    else:
        await _emit(engagement_id, {"event": "resumed", "engagement_id": engagement_id})

    # HTB provisioning state (set during spawn below; drives flag-submit + teardown
    # in the finally). Stays None for static targets and on resume.
    htb_cfg = None
    htb_client = None
    htb_machine = None
    htb_flags: list[str] = []
    htb_rooted = False
    htb_status = "error"

    try:
        if not resume:
            # Clear stale tmux sessions (listeners, landed shells, msfconsole
            # instances) left behind by the previous engagement. The shell MCP
            # container is long-lived and shared across engagements; without
            # this purge the new engagement inherits leftover state and the
            # agent gets confused by sessions it didn't create. Inside the
            # try block so a cancel during the HTTP call still routes through
            # the normal `cancelled` event path.
            await _reset_shell_sessions(engagement_id)

        from langchain_core.messages import HumanMessage

        from ..agent.main import build_agent
        from ..schemas.engagement import EngagementSpec

        # HTB auto-provisioning (spec-driven): if the spec carries an `htb:` block,
        # spawn the named box and write its IP into `targets:` BEFORE the agent
        # builds. This makes provisioning work for ANY client (CLI, web) — the
        # spec alone decides. On resume the box is already up and the spec already
        # holds its IP, so we skip spawning (and skip auto-teardown/submit).
        if not resume:
            _prov_spec = EngagementSpec.from_yaml(spec_path)
            if _prov_spec.htb is not None:
                htb_cfg = _prov_spec.htb
                htb_client, htb_machine, _ip = await _htb_spawn(htb_cfg, engagement_id)
                _rewrite_spec_targets(spec_path, [_ip])

        # The system prompt has the engagement context (target, objective, mode);
        # we kick off the loop with a brief operator-style HumanMessage. Without
        # at least one message Anthropic rejects the request as malformed.
        if resume:
            agent_input: Any = None
        else:
            spec = EngagementSpec.from_yaml(spec_path)
            kickoff = HumanMessage(content=_kickoff_text(spec, engagement_id))
            agent_input = {"messages": [kickoff]}

        # Sustained provider overload can outlast model_retry's per-call budget
        # and escape as a terminal OverloadedError/429/5xx — which used to kill
        # the engagement outright. The Postgres checkpoint survives the crash, so
        # instead of dying we auto-resume from it (feed `None` → LangGraph picks
        # up at the last checkpoint, re-running only the failed model node).
        # Bounded with growing backoff so a genuine outage still terminates.
        from ..agent.middleware.model_retry import _is_transient  # noqa: PLC0415

        _max_auto_resumes = 4
        auto_resume = 0
        from langgraph.types import Command  # noqa: PLC0415

        while True:
            try:
                pending_interrupt: Any = None
                async with build_agent(spec_path, profile=profile, engagement_id=engagement_id) as agent:
                    log.info("engagement %s: agent built, beginning astream", engagement_id)
                    # `subgraphs=True` makes subagent (= subgraph) events bubble
                    # up so the operator can see each subagent's individual tool
                    # dispatches (e.g. surface__nmap_quick,
                    # exploit__generate_payload) — not just the outer `task()`
                    # call. Each yielded item becomes `(namespace_tuple,
                    # update_dict)` where `namespace_tuple` is `()` for the root
                    # agent and something like `('task:abc', 'surface')` for a
                    # running subagent.
                    async for raw in agent.astream(
                        agent_input,
                        config={"configurable": {"thread_id": engagement_id}},
                        subgraphs=True,
                    ):
                        namespace, update = _unpack_stream_event(raw)
                        safe_update = _safe(update)
                        await _emit(engagement_id, {
                            "event": "step",
                            "namespace": list(namespace),
                            "data": safe_update,
                        })
                        # HTB runs: harvest captured flags + a rooted signal from
                        # the event stream so we can submit them after the run.
                        if htb_cfg is not None:
                            for _f in _walk_record_flags(safe_update):
                                if _f not in htb_flags:
                                    htb_flags.append(_f)
                            if not htb_rooted and _root_signal_in_event(safe_update):
                                htb_rooted = True
                        intr = _extract_interrupt(update)
                        if intr is not None:
                            pending_interrupt = intr
                if pending_interrupt is None:
                    break  # astream drained to completion — done
                # Paused at a HITL interrupt (action approval / stuck report).
                # Surface it to the dashboards, block for the operator's reply,
                # then resume the graph from its Postgres checkpoint with the
                # decision as the `interrupt()` return value.
                reply = await _await_hitl_reply(engagement_id, pending_interrupt)
                agent_input = Command(resume=reply)
                auto_resume = 0  # a human pause isn't a transient failure
                continue
            except asyncio.CancelledError:
                raise  # operator pause/cancel — handled by the outer except
            except Exception as exc:  # noqa: BLE001
                if not (_is_transient(exc) and auto_resume < _max_auto_resumes):
                    raise  # non-transient, or out of auto-resumes → fail for real
                auto_resume += 1
                delay = min(30.0 * 2 ** (auto_resume - 1), 300.0)
                log.warning(
                    "engagement %s: terminal transient error (%s) — auto-resuming "
                    "%d/%d from checkpoint in %.0fs",
                    engagement_id, type(exc).__name__, auto_resume, _max_auto_resumes, delay,
                )
                await _emit(engagement_id, {
                    "event": "resumed",
                    "engagement_id": engagement_id,
                    "reason": f"auto-resume after {type(exc).__name__} "
                              f"(attempt {auto_resume}/{_max_auto_resumes})",
                })
                await asyncio.sleep(delay)
                agent_input = None  # resume from the Postgres checkpoint

        # End-of-engagement skill proposer (was a middleware in older versions;
        # langchain v1 middlewares are per-step, so we run this as a post-step
        # hook). Reads episodes directly from Postgres — round-tripping the
        # MCP server via REST doesn't work (the MCP HTTP transport speaks
        # streamable-http over `/mcp`, not a REST tree).
        try:
            from psycopg.rows import dict_row  # noqa: PLC0415

            from ..agent.middleware.skill_proposer import skill_proposer
            proposer = skill_proposer()
            pool = _get_pg_pool()
            await pool.open()
            async with pool.connection() as conn:
                async with conn.cursor(row_factory=dict_row) as cur:
                    await cur.execute(
                        """
                        SELECT id, engagement_id, agent_name, ts, action,
                               tool_input, tool_output, outcome_tag,
                               cost_usd, duration_ms, error
                        FROM episodes
                        WHERE engagement_id = %s
                        ORDER BY ts ASC
                        """,
                        (engagement_id,),
                    )
                    rows = await cur.fetchall()
            episodes = [_episode_row(r) for r in rows]
            paths = proposer({"thread_id": engagement_id}, episodes)
            if paths:
                log.info("engagement %s: %d skill proposal(s) emitted", engagement_id, len(paths))
                await _emit(engagement_id, {"event": "skill_proposals", "paths": paths})
        except Exception:  # noqa: BLE001
            log.exception("skill proposer failed (non-fatal)")

        # Safety net: render_report writes `engagements/<id>/report.md`, and
        # `_engagement_status` reads that file to decide "finished". If the
        # analyst skipped its render_report call (LLM non-compliance — the
        # ToolStrategy structured-response contract is satisfied without ever
        # touching the tool), we'd otherwise end up with no file on disk and
        # the engagement permanently reported as "stopped". Write a stub
        # using whatever durable state we have.
        await _ensure_report_exists(engagement_id, spec_path)

        # HTB success = a root/objective signal, or enough flags for the spec.
        # Drives the on_success teardown policy and what we report.
        if htb_cfg is not None:
            _ef = EngagementSpec.from_yaml(spec_path).expected_flags
            htb_status = "solved" if _htb_solved(htb_flags, htb_rooted, _ef) else "failed"

        await _emit(engagement_id, {"event": "complete"})
        log.info("engagement %s completed normally", engagement_id)
    except asyncio.CancelledError:
        # Two paths land here: operator pressed `/pause` (marker file present)
        # or operator pressed `/cancel` (marker absent). The /pause endpoint
        # already emitted a `paused` event; we just log and exit cleanly,
        # leaving the checkpoint intact for a future /resume. /cancel emits
        # `cancelled` here as before.
        if _is_paused(engagement_id):
            log.info("engagement %s paused by operator", engagement_id)
        else:
            log.info("engagement %s cancelled by operator", engagement_id)
            await _emit(engagement_id, {
                "event": "cancelled",
                "reason": "operator requested cancellation",
            })
    except Exception as exc:  # noqa: BLE001
        tb = traceback.format_exc()
        log.exception("engagement %s failed", engagement_id)
        await _emit(engagement_id, {
            "event": "error",
            "error": str(exc),
            "error_type": type(exc).__name__,
            "traceback": tb,
        })
    finally:
        # HTB teardown + flag-submit (best-effort, never raises). Runs on every
        # exit path — success, failure, error, or operator cancel — so a box we
        # spawned is never stranded. Safe here: any cancel was already caught
        # above (not re-raised), so these awaits complete. On cancel htb_status
        # is still "error", so the default on_complete policy still tears down.
        if htb_client is not None and htb_machine is not None and htb_cfg is not None:
            try:
                await _htb_finalize(
                    htb_client, htb_machine, htb_cfg,
                    status=htb_status, flags=htb_flags, engagement_id=engagement_id,
                )
            except Exception:  # noqa: BLE001
                log.exception("engagement %s: HTB finalize failed (non-fatal)", engagement_id)
        await _emit(engagement_id, {"event": "end"})
        # Remove our task tracking entry so a future engagement with the
        # same ID (rare, but possible on resume) doesn't see a stale ref.
        _engagement_tasks.pop(engagement_id, None)


def _unpack_stream_event(raw: Any) -> tuple[tuple, Any]:
    """Normalize the shape `agent.astream(..., subgraphs=True)` yields.

    With `subgraphs=True`, langgraph yields `(namespace_tuple, update_dict)`.
    Without it, just `update_dict`. We always return a `(namespace, update)`
    pair so the downstream emit/render paths can stay uniform.

    `namespace` is a tuple of strings like `("agent:foo:bar", "surface")` —
    the components identify the subgraph path. Empty tuple = root agent.
    """
    if isinstance(raw, tuple) and len(raw) == 2 and isinstance(raw[0], tuple):
        return raw[0], raw[1]
    return (), raw


def _safe(payload: Any) -> Any:
    """Make event payloads JSON-serializable WHILE PRESERVING STRUCTURE.

    The previous version used `default=str` which would call `str()` on any
    non-JSON-serializable object — including langchain BaseMessage subclasses
    (AIMessage, ToolMessage, HumanMessage). That collapsed each message into
    its Python repr (e.g. `content=[{'text': ...}]`), which the CLI then
    rendered as one truncated line, hiding tool dispatches inside.

    Here we walk the payload, converting any BaseMessage to its dict form
    via `model_dump()` (preserving content blocks, tool_calls, type, etc.),
    and only fall back to `str()` for things we genuinely can't structure.
    """
    return json.loads(json.dumps(_dump(payload), default=str))


def _dump(value: Any) -> Any:
    """Recursive walker: turn langchain messages into dicts, leave plain
    JSON types alone, fall through to dict-like / list-like containers."""
    # Lazy import — keep the gateway importable without langchain in tests.
    try:
        from langchain_core.messages import BaseMessage  # type: ignore[import-not-found]
    except Exception:  # noqa: BLE001
        BaseMessage = None  # type: ignore[assignment]  # noqa: N806

    if BaseMessage is not None and isinstance(value, BaseMessage):
        try:
            return value.model_dump()
        except Exception:  # noqa: BLE001
            # Older langchain or partial init — fall back to attribute pull.
            return {
                "type": getattr(value, "type", "unknown"),
                "content": getattr(value, "content", ""),
                "tool_calls": getattr(value, "tool_calls", None),
                "name": getattr(value, "name", None),
            }
    if isinstance(value, dict):
        return {k: _dump(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_dump(v) for v in value]
    return value


@app.get("/engagements/{engagement_id}/stream")
async def stream_engagement(engagement_id: str) -> StreamingResponse:
    """SSE stream of every step in the engagement.

    Replays the Redis backlog list first (so subscribers see everything that
    happened before they connected), then live-tails the pubsub channel.
    """

    async def event_stream() -> AsyncIterator[str]:
        r = _get_redis()
        backlog_key = f"engagement:{engagement_id}:backlog"
        channel = f"engagement:{engagement_id}"

        # Subscribe FIRST so no live events are missed during backlog replay.
        pubsub = r.pubsub()
        await pubsub.subscribe(channel)

        try:
            # Replay backlog.
            backlog = await r.lrange(backlog_key, 0, -1)
            for item in backlog:
                yield f"data: {item}\n\n"

            # Sentinel so the client knows replay is done.
            yield 'data: {"event": "subscribed"}\n\n'

            # Live-tail until we see the engagement's `end` event or the client
            # disconnects. Use get_message with periodic heartbeats instead of
            # pubsub.listen(); redis-py's blocking listen can surface socket
            # read timeouts during idle streams, which used to tear down the
            # FastAPI response with a noisy traceback.
            while True:
                try:
                    msg = await pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=15.0,
                    )
                except RedisTimeoutError:
                    yield ": heartbeat\n\n"
                    continue
                except RedisConnectionError as exc:
                    log.warning("engagement %s stream redis connection lost: %s", engagement_id, exc)
                    yield 'data: {"event": "error", "error": "redis stream connection lost"}\n\n'
                    break

                if msg is None:
                    yield ": heartbeat\n\n"
                    continue
                if msg["type"] != "message":
                    continue
                data = msg["data"]
                yield f"data: {data}\n\n"
                try:
                    parsed = json.loads(data)
                    if parsed.get("event") == "end":
                        break
                except Exception:  # noqa: BLE001
                    pass
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()

    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.get("/engagements/{engagement_id}/events")
async def get_event_backlog(engagement_id: str) -> dict[str, Any]:
    """Plain JSON dump of the engagement's event backlog. Useful for `curl` debugging."""
    r = _get_redis()
    items = await r.lrange(f"engagement:{engagement_id}:backlog", 0, -1)
    return {"engagement_id": engagement_id, "events": [json.loads(i) for i in items]}


class ApprovalPayload(BaseModel):
    decision: str  # accept | reject | edit
    guidance: str = ""
    edited_args: dict[str, Any] | None = None


@app.post("/engagements/{engagement_id}/approve")
async def approve(engagement_id: str, payload: ApprovalPayload) -> dict[str, str]:
    """Respond to a pending HITL interrupt."""
    r = _get_redis()
    await r.publish(
        f"engagement:{engagement_id}:hitl",
        json.dumps(payload.model_dump()),
    )
    return {"ok": "true"}


class StuckResponse(BaseModel):
    engagement_id: str
    guidance: str


@app.post("/engagements/{engagement_id}/stuck_response")
async def stuck_response(engagement_id: str, payload: StuckResponse) -> dict[str, str]:
    """Resume from a StuckReport interrupt with operator guidance."""
    r = _get_redis()
    await r.publish(
        f"engagement:{engagement_id}:hitl",
        json.dumps({"decision": "respond", "guidance": payload.guidance}),
    )
    return {"ok": "true"}


@app.get("/engagements/{engagement_id}/episodes")
async def list_episodes_for_engagement(engagement_id: str, n: int = 100) -> dict[str, Any]:
    """Tail the episode log — queried directly from Postgres."""
    from psycopg.rows import dict_row  # noqa: PLC0415

    pool = _get_pg_pool()
    await pool.open()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT id, engagement_id, agent_name, ts, action, tool_input,
                       tool_output, outcome_tag, cost_usd, duration_ms, error
                FROM episodes
                WHERE engagement_id = %s
                ORDER BY ts DESC
                LIMIT %s
                """,
                (engagement_id, n),
            )
            rows = await cur.fetchall()
    return {"episodes": [_episode_row(r) for r in rows]}


def _episode_row(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": r["id"],
        "engagement_id": r["engagement_id"],
        "agent_name": r["agent_name"],
        "timestamp": r["ts"].isoformat(),
        "action": r["action"],
        "tool_input": r["tool_input"],
        "tool_output": r["tool_output"],
        "outcome_tag": r["outcome_tag"],
        "cost_usd": float(r["cost_usd"] or 0.0),
        "duration_ms": int(r["duration_ms"] or 0),
        "error": r["error"],
    }


@app.get("/engagements")
async def list_engagements(running: bool = False) -> dict[str, Any]:
    """List engagements known to the gateway.

    Combines two sources of truth:
      - Filesystem (every engagement that started has a `engagements/<id>/`)
      - In-memory task table (which IDs are currently running)

    `running=true` filters to live tasks only.
    """
    entries = []
    fs_ids: set[str] = set()

    # Durable start times from Postgres, keyed by id. Best-effort: if the DB is
    # unreachable we fall back per-entry to the spec file's mtime below.
    started_map: dict[str, str] = {}
    try:
        pool = await _ready_engagements_pool()
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SELECT id::text, started_at FROM engagements")
                for row in await cur.fetchall():
                    if row[1] is not None:
                        started_map[row[0]] = row[1].isoformat()
    except Exception as exc:  # noqa: BLE001
        log.warning("list_engagements: could not read started_at from db: %s", exc)

    if ENGAGEMENT_DIR.exists():
        for path in sorted(ENGAGEMENT_DIR.iterdir()):
            if not path.is_dir():
                continue
            # Engagement dirs are gateway-minted UUIDs. Skip anything else (e.g. a
            # stray `loot/` an agent wrote one level too high) so junk folders
            # don't surface as phantom nameless engagements.
            try:
                uuid.UUID(path.name)
            except ValueError:
                continue
            fs_ids.add(path.name)
            spec_file = path / "spec.yaml"
            # Start time: prefer the durable engagements.started_at row; fall back
            # to spec.yaml's mtime (written once at kickoff, never touched after)
            # for engagements that predate the persisted row.
            created_at = started_map.get(path.name)
            if created_at is None:
                import datetime as _dt  # noqa: PLC0415
                try:
                    stat_src = spec_file if spec_file.exists() else path
                    created_at = _dt.datetime.fromtimestamp(
                        stat_src.stat().st_mtime, _dt.UTC
                    ).isoformat()
                except OSError:
                    created_at = None
            entry: dict[str, Any] = {
                "engagement_id": path.name,
                "status": _engagement_status(path.name),
                "created_at": created_at,
            }
            if spec_file.exists():
                try:
                    from ..schemas.engagement import EngagementSpec
                    spec = EngagementSpec.from_yaml(spec_file)
                    entry.update({
                        "name": spec.name,
                        "mode": spec.mode.value,
                        "targets": spec.targets,
                        "profile": spec.profile,
                    })
                except Exception:  # noqa: BLE001
                    pass
            entries.append(entry)

    # A running task whose engagement dir somehow doesn't exist on disk would
    # otherwise be invisible. Surface it anyway so the operator can cancel.
    for eng_id, task in _engagement_tasks.items():
        if eng_id in fs_ids:
            continue
        if task.done():
            continue
        entries.append({
            "engagement_id": eng_id,
            "status": "running",
            "name": "(no spec on disk)",
            "created_at": None,
        })

    if running:
        entries = [e for e in entries if e.get("status") == "running"]
    # Newest first. created_at is a uniform ISO/UTC string, so lexical sort is
    # chronological; a missing timestamp (running task with no dir yet) is newest,
    # so it sorts to the top.
    entries.sort(key=lambda e: e.get("created_at") or "9999", reverse=True)
    return {"engagements": entries}


def _engagement_status(engagement_id: str) -> str:
    """Return one of: running | paused | finished | cancelled | stopped."""
    task = _engagement_tasks.get(engagement_id)
    if task is not None and not task.done():
        return "running"
    # A `.paused` marker on disk wins over both "task gone from tracking"
    # and "no report yet" — it means we're between pause and resume.
    if _is_paused(engagement_id):
        return "paused"
    if task is not None and task.cancelled():
        return "cancelled"
    # Once a task finishes, it's removed from _engagement_tasks (see the
    # finally block in _run_engagement). So past-tense status comes from
    # the disk: if a `report.md` exists, we treat it as finished; otherwise
    # we don't actually know (it might have crashed). Phase 4 will record
    # explicit terminal status in Postgres.
    report_path = ENGAGEMENT_DIR / engagement_id / "report.md"
    if report_path.exists():
        return "finished"
    return "stopped"


@app.get("/engagements/{engagement_id}/findings")
async def list_findings(engagement_id: str) -> dict[str, Any]:
    """List Findings rows directly from Postgres."""
    from psycopg.rows import dict_row  # noqa: PLC0415

    pool = _get_pg_pool()
    await pool.open()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT id, engagement_id, title, severity, host, description,
                       impact, evidence, cve, attack_pattern, remediation, created_at
                FROM findings
                WHERE engagement_id = %s
                ORDER BY created_at DESC
                """,
                (engagement_id,),
            )
            rows = await cur.fetchall()
    return {
        "findings": [
            {**dict(r), "created_at": r["created_at"].isoformat()} for r in rows
        ]
    }


@app.get("/engagements/{engagement_id}/lab_progress")
async def lab_progress(engagement_id: str) -> dict[str, Any]:
    """Lab-mode breadth tracker snapshot."""
    from ..agent import lab_state
    state = lab_state.load(ENGAGEMENT_DIR, engagement_id)
    return {
        "engagement_id": engagement_id,
        "progress": state.progress(),
        "hosts": [
            {"address": r.address, "status": r.status.value, "reason": r.reason, "notes": r.notes}
            for r in state.hosts.values()
        ],
    }


@app.get("/engagements/{engagement_id}/graph")
async def engagement_graph(engagement_id: str) -> dict[str, Any]:
    """Snapshot of the Neo4j-derived projection for this engagement."""
    try:
        from neo4j import AsyncGraphDatabase  # type: ignore
    except ImportError:
        return {"hosts": [], "services": [], "credentials": [], "cves": []}

    uri = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "changeme")
    driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
    try:
        async with driver.session() as session:
            hosts = [r.data() async for r in await session.run(
                "MATCH (e:Engagement {id: $eid})-[:TARGETS]->(h:Host) RETURN h.address AS address",
                eid=engagement_id,
            )]
            services = [r.data() async for r in await session.run(
                "MATCH (h:Host)-[:EXPOSES]->(s:Service) "
                "WHERE EXISTS { MATCH (e:Engagement {id: $eid})-[:TARGETS]->(h) } "
                "RETURN h.address AS host, s.port AS port, s.service AS service, s.version AS version",
                eid=engagement_id,
            )]
            creds = [r.data() async for r in await session.run(
                "MATCH (e:Engagement {id: $eid})-[:HARVESTED]->(c:Credential) "
                "RETURN c.host AS host, c.type AS type, c.source AS source",
                eid=engagement_id,
            )]
            cves = [r.data() async for r in await session.run(
                "MATCH (e:Engagement {id: $eid})-[:OBSERVED]->(v:Vuln) RETURN v.id AS cve",
                eid=engagement_id,
            )]
    finally:
        await driver.close()

    return {"hosts": hosts, "services": services, "credentials": creds, "cves": cves}


@app.get("/engagements/{engagement_id}/report")
async def get_report(engagement_id: str) -> dict[str, Any]:
    """Raw `report.md` markdown for an engagement, or `{exists: false}`.

    Validates the id is a UUID before touching the filesystem — this endpoint
    reads a path under `ENGAGEMENT_DIR`, so an unvalidated id would be a path
    traversal vector (unlike the DB/Redis endpoints which key by value)."""
    try:
        uuid.UUID(engagement_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid engagement id") from None
    report_path = ENGAGEMENT_DIR / engagement_id / "report.md"
    if not report_path.exists():
        return {"exists": False, "markdown": ""}
    return {"exists": True, "markdown": report_path.read_text()}


@app.get("/engagements/{engagement_id}/stuck")
async def list_stuck(engagement_id: str) -> dict[str, Any]:
    """Active stuck reports for this engagement. Pulled from Redis."""
    r = _get_redis()
    raw = await r.lrange(f"engagement:{engagement_id}:stuck", 0, -1)
    return {"reports": [json.loads(item) for item in raw]}


@app.get("/hitl/queue")
async def hitl_queue() -> dict[str, Any]:
    """Pending HITL approvals across all engagements."""
    r = _get_redis()
    items = await r.lrange("hitl:queue", 0, -1)
    return {"pending": [json.loads(i) for i in items]}


async def _call_mcp_tool(
    server_url: str, tool_name: str, arguments: dict[str, Any] | None = None,
    timeout_s: float = 5.0,
) -> dict[str, Any] | None:
    """Call one tool on an MCP streamable-http server. Returns the parsed
    result on success, None on any failure (server unreachable, tool errors,
    etc.). Callers should treat None as "no data".

    This is the right way to call MCP tools from the gateway — POSTing to
    `/mcp/tools/<name>` (the previous incorrect approach) is a 404; the
    MCP server only speaks the streamable-http protocol on `/mcp`.
    """
    try:
        from mcp import ClientSession  # noqa: PLC0415
        from mcp.client.streamable_http import streamablehttp_client  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        log.warning("MCP client libs not importable: %s", exc)
        return None

    try:
        async with streamablehttp_client(server_url) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments or {})
        # `result.content` is a list of TextContent / etc. blocks. We expect
        # one text block whose value is JSON (our MCP tools all return dicts).
        if not result.content:
            return None
        text = getattr(result.content[0], "text", "") or ""
        if not text:
            return None
        return json.loads(text)
    except Exception as exc:  # noqa: BLE001
        log.warning("MCP tool %s on %s failed: %s", tool_name, server_url, exc)
        return None


@app.get("/engagements/{engagement_id}/shells")
async def list_shells(engagement_id: str) -> dict[str, Any]:
    """List active tmux sessions for an engagement.

    Returns empty for engagements whose shell-mcp container has been
    recreated since the engagement ran — tmux sessions don't survive a
    container restart and aren't persisted anywhere else.
    """
    shell_url = os.environ.get("MCP_SHELL_URL", "http://shell-mcp:8080/mcp")
    result = await _call_mcp_tool(shell_url, "tmux_list_sessions")
    sessions = (result or {}).get("sessions") or []
    return {
        "sessions": [
            s for s in sessions
            if s.get("bound_to_engagement") == engagement_id
        ]
    }


@app.get("/engagements/{engagement_id}/shell/{session_name}/read")
async def read_shell(engagement_id: str, session_name: str) -> dict[str, Any]:
    """Read recent output from a specific tmux session (read-only)."""
    shell_url = os.environ.get("MCP_SHELL_URL", "http://shell-mcp:8080/mcp")
    result = await _call_mcp_tool(
        shell_url, "tmux_read",
        {"session_name": session_name, "timeout_s": 1.0, "wait_for_prompt": False},
        timeout_s=10.0,
    )
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"shell session {session_name!r} not reachable (server down "
                   "or the engagement's container has been recreated)",
        )
    return result


@app.get("/auth/{provider}/login")
async def auth_login(provider: str, redirect_uri: str) -> dict[str, str]:
    """Begin the OAuth flow for `provider` (anthropic|openai|google).

    Returns the authorize URL. The caller opens it in a browser; the provider
    redirects back to `redirect_uri` with `code` and `state`. Use
    `/auth/{provider}/callback` to exchange the code.
    """
    from ..auth.oauth import build_authorization_url

    if provider not in {"anthropic", "openai", "google"}:
        raise HTTPException(status_code=400, detail="unknown provider")
    req = build_authorization_url(provider, redirect_uri)  # type: ignore[arg-type]

    # Stash state + verifier in Redis (5 min TTL) so the callback can validate.
    r = _get_redis()
    await r.setex(f"oauth:{provider}:{req.state}", 300, req.code_verifier)

    return {"authorize_url": req.url, "state": req.state}


class CallbackPayload(BaseModel):
    code: str
    state: str
    redirect_uri: str


@app.post("/auth/{provider}/callback")
async def auth_callback(provider: str, payload: CallbackPayload) -> dict[str, Any]:
    """Exchange an authorization code for an access token + persist (encrypted)."""
    from ..auth.oauth import exchange_code_for_token

    if provider not in {"anthropic", "openai", "google"}:
        raise HTTPException(status_code=400, detail="unknown provider")

    r = _get_redis()
    verifier = await r.get(f"oauth:{provider}:{payload.state}")
    if not verifier:
        raise HTTPException(status_code=400, detail="state expired or unknown")

    token = await exchange_code_for_token(
        provider,  # type: ignore[arg-type]
        payload.code,
        verifier,
        payload.redirect_uri,
    )
    # Real persistence: encrypt at rest in Postgres. Scaffolding only stores in
    # Redis with a 24h TTL — the engagement runtime picks it up by provider.
    await r.setex(
        f"token:{provider}",
        token.get("expires_in", 86400),
        json.dumps(token),
    )
    return {"ok": True, "provider": provider, "expires_in": token.get("expires_in")}


@app.get("/skills/_proposed")
async def list_proposed_skills() -> dict[str, Any]:
    proposed_dir = Path("skills/_proposed")
    if not proposed_dir.exists():
        return {"proposals": []}
    items = []
    for path in sorted(proposed_dir.glob("*.md")):
        items.append({"name": path.stem, "path": str(path), "preview": path.read_text()[:1024]})
    return {"proposals": items}


@app.post("/skills/_proposed/{name}/accept")
async def accept_proposal(name: str, target_dir: str) -> dict[str, str]:
    src = Path("skills/_proposed") / f"{name}.md"
    if not src.exists():
        raise HTTPException(status_code=404, detail="proposal not found")
    dest = Path("skills") / target_dir / name / "SKILL.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(src.read_text())
    src.unlink()
    return {"ok": "true", "path": str(dest)}


def main() -> None:
    import uvicorn
    uvicorn.run(
        "src.gateway.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
    )


if __name__ == "__main__":
    main()
