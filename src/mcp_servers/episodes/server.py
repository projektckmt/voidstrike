"""Episodes MCP server — append-only log, Postgres-backed.

The source of truth. Agents reason episodically — they read their
own recent episodes to decide what to try next. Neo4j graph is a *derived*
projection populated by the ETL worker, not written from here.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

from mcp.server.fastmcp import FastMCP
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

app = FastMCP(
    "episodes",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
)

PG_URL = os.environ.get(
    "POSTGRES_URL",
    "postgresql://voidstrike:changeme@postgres:5432/voidstrike",
)

_pool: AsyncConnectionPool | None = None
_schema_ready = False

# Idempotent DDL for the tables this server owns. `infra/postgres-init.sql` runs
# only on a *fresh* Postgres volume's first boot — a pre-existing volume created
# before the episodes/findings tables were added never gets them, and every
# write then fails with `relation "episodes" does not exist`. Running this once
# per process makes the server self-healing regardless of how the DB was
# provisioned. All statements are `IF NOT EXISTS` / `OR REPLACE`, so it's a no-op
# when the schema is already present.
_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS episodes (
    id              BIGSERIAL PRIMARY KEY,
    engagement_id   TEXT NOT NULL,
    agent_name      TEXT NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,
    action          TEXT NOT NULL,
    tool_input      JSONB NOT NULL DEFAULT '{}'::jsonb,
    tool_output     TEXT NOT NULL DEFAULT '',
    outcome_tag     TEXT NOT NULL DEFAULT 'no_result',
    cost_usd        NUMERIC(12, 6) NOT NULL DEFAULT 0.0,
    duration_ms     INTEGER NOT NULL DEFAULT 0,
    error           TEXT
);
CREATE INDEX IF NOT EXISTS episodes_engagement_ts ON episodes (engagement_id, ts);
CREATE INDEX IF NOT EXISTS episodes_outcome ON episodes (engagement_id, outcome_tag);
CREATE INDEX IF NOT EXISTS episodes_agent ON episodes (engagement_id, agent_name);
CREATE TABLE IF NOT EXISTS episode_etl_marker (
    episode_id      BIGINT PRIMARY KEY REFERENCES episodes(id) ON DELETE CASCADE,
    processed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    engagement_id   TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    host            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    impact          TEXT NOT NULL DEFAULT '',
    evidence        TEXT NOT NULL DEFAULT '',
    cve             TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    attack_pattern  TEXT,
    remediation     TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS findings_engagement ON findings (engagement_id);
CREATE INDEX IF NOT EXISTS findings_host ON findings (engagement_id, host);
CREATE OR REPLACE FUNCTION episodes_notify() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify(
        'episodes_inserted',
        json_build_object(
            'id', NEW.id,
            'engagement_id', NEW.engagement_id,
            'agent_name', NEW.agent_name,
            'action', NEW.action,
            'tool_input', NEW.tool_input,
            'tool_output', NEW.tool_output,
            'outcome_tag', NEW.outcome_tag,
            'ts', NEW.ts
        )::text
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS episodes_notify_trigger ON episodes;
CREATE TRIGGER episodes_notify_trigger
AFTER INSERT ON episodes
FOR EACH ROW EXECUTE FUNCTION episodes_notify();
"""


def _get_pool() -> AsyncConnectionPool:
    global _pool
    if _pool is None:
        _pool = AsyncConnectionPool(PG_URL, open=False, min_size=1, max_size=8)
    return _pool


async def _ready_pool() -> AsyncConnectionPool:
    """Open the pool and ensure the schema exists (once per process)."""
    global _schema_ready
    pool = _get_pool()
    await pool.open()
    if not _schema_ready:
        async with pool.connection() as conn:
            await conn.execute(_SCHEMA_DDL)
            await conn.commit()
        _schema_ready = True
    return pool


@app.tool()
async def write_episode(
    engagement_id: str,
    agent_name: str,
    action: str,
    tool_input: dict[str, Any] | None = None,
    tool_output: str = "",
    outcome_tag: str = "no_result",
    cost_usd: float = 0.0,
    duration_ms: int = 0,
    error: str | None = None,
) -> dict[str, Any]:
    """Append a single episode. Returns the assigned id."""
    pool = await _ready_pool()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                INSERT INTO episodes (
                    engagement_id, agent_name, ts, action, tool_input, tool_output,
                    outcome_tag, cost_usd, duration_ms, error
                ) VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    engagement_id,
                    agent_name,
                    datetime.now(UTC),
                    action,
                    json.dumps(tool_input or {}),
                    tool_output,
                    outcome_tag,
                    cost_usd,
                    duration_ms,
                    error,
                ),
            )
            row = await cur.fetchone()
        await conn.commit()
    return {"ok": True, "episode_id": row["id"] if row else None}


@app.tool()
async def read_episode_tail(
    engagement_id: str,
    n: int = 20,
    agent_name: str | None = None,
    outcome_tag: str | None = None,
) -> dict[str, Any]:
    """Read the most recent N episodes, newest first. Optional filters."""
    pool = await _ready_pool()
    where = ["engagement_id = %s"]
    params: list[Any] = [engagement_id]
    if agent_name:
        where.append("agent_name = %s")
        params.append(agent_name)
    if outcome_tag:
        where.append("outcome_tag = %s")
        params.append(outcome_tag)
    params.append(n)

    sql = f"""
        SELECT id, engagement_id, agent_name, ts, action, tool_input,
               tool_output, outcome_tag, cost_usd, duration_ms, error
        FROM episodes
        WHERE {' AND '.join(where)}
        ORDER BY ts DESC
        LIMIT %s
    """
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(sql, params)
            rows = await cur.fetchall()
    return {"episodes": [_row_to_episode(r) for r in rows]}


@app.tool()
async def read_engagement(engagement_id: str) -> dict[str, Any]:
    """Read all episodes for an engagement. Bounded by `EPISODES_MAX_READ`."""
    pool = await _ready_pool()
    limit = int(os.environ.get("EPISODES_MAX_READ", "10000"))
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT id, engagement_id, agent_name, ts, action, tool_input,
                       tool_output, outcome_tag, cost_usd, duration_ms, error
                FROM episodes
                WHERE engagement_id = %s
                ORDER BY ts ASC
                LIMIT %s
                """,
                (engagement_id, limit),
            )
            rows = await cur.fetchall()
    return {"episodes": [_row_to_episode(r) for r in rows]}


@app.tool()
async def write_finding(
    engagement_id: str,
    title: str,
    severity: str,
    host: str,
    description: str = "",
    impact: str = "",
    evidence: str = "",
    cve: list[str] | None = None,
    attack_pattern: str | None = None,
    remediation: str = "",
) -> dict[str, Any]:
    """Persist a Finding row for the Analyst to read at end-of-engagement."""
    pool = await _ready_pool()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                INSERT INTO findings (engagement_id, title, severity, host,
                    description, impact, evidence, cve, attack_pattern, remediation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    engagement_id, title, severity, host, description, impact,
                    evidence, cve or [], attack_pattern, remediation,
                ),
            )
            row = await cur.fetchone()
        await conn.commit()
    return {"ok": True, "finding_id": row["id"] if row else None}


@app.tool()
async def list_findings(engagement_id: str) -> dict[str, Any]:
    """All findings for an engagement, newest first. Analyst's input."""
    pool = await _ready_pool()
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
    return {"findings": [dict(r, created_at=r["created_at"].isoformat()) for r in rows]}


@app.tool()
async def summarize_engagement(engagement_id: str) -> dict[str, Any]:
    """Quick aggregate over an engagement — counts by outcome, cost, agents."""
    pool = await _ready_pool()
    async with pool.connection() as conn:
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                """
                SELECT
                    outcome_tag,
                    COUNT(*) AS n,
                    SUM(cost_usd) AS cost,
                    SUM(duration_ms) AS duration
                FROM episodes
                WHERE engagement_id = %s
                GROUP BY outcome_tag
                """,
                (engagement_id,),
            )
            outcomes = await cur.fetchall()
            await cur.execute(
                """
                SELECT agent_name, COUNT(*) AS n, SUM(cost_usd) AS cost
                FROM episodes
                WHERE engagement_id = %s
                GROUP BY agent_name
                """,
                (engagement_id,),
            )
            agents = await cur.fetchall()
    return {
        "engagement_id": engagement_id,
        "by_outcome": [dict(r) for r in outcomes],
        "by_agent": [dict(r) for r in agents],
    }


def _row_to_episode(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "engagement_id": row["engagement_id"],
        "agent_name": row["agent_name"],
        "timestamp": row["ts"].isoformat(),
        "action": row["action"],
        "tool_input": row["tool_input"],
        "tool_output": row["tool_output"],
        "outcome_tag": row["outcome_tag"],
        "cost_usd": float(row["cost_usd"] or 0.0),
        "duration_ms": int(row["duration_ms"] or 0),
        "error": row["error"],
    }


def main() -> None:
    # Host/port are set on the FastMCP constructor — see top of module.
    app.run(transport="streamable-http")


if __name__ == "__main__":
    main()
