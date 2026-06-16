-- Voidstrike Postgres schema bootstrap.
--
-- `episodes` is the source of truth. Neo4j is a *derived*
-- projection populated by the ETL worker. If the graph is wrong, drop it and
-- rebuild from this table.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

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

-- NOTIFY hook for the ETL worker. It does a backfill on startup, then live-
-- tails via LISTEN.
CREATE OR REPLACE FUNCTION episodes_notify() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify(
        'episodes_inserted',
        json_build_object(
            'id', NEW.id,
            'engagement_id', NEW.engagement_id,
            'agent_name', NEW.agent_name,
            'tool_input', NEW.tool_input,
            'tool_output', NEW.tool_output,
            'outcome_tag', NEW.outcome_tag
        )::text
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS episodes_notify_trigger ON episodes;
CREATE TRIGGER episodes_notify_trigger
AFTER INSERT ON episodes
FOR EACH ROW EXECUTE FUNCTION episodes_notify();
