"""Episode log → Neo4j projection worker.

One-way ETL. Reads from `episodes` (Postgres), writes
`Host/Service/Vuln/Credential/Finding` nodes to Neo4j. If the graph is wrong,
drop it and rebuild from the log.

Runs as a long-lived consumer using Postgres `LISTEN/NOTIFY` (trigger writes a
notification on every insert into `episodes`).
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Any

import psycopg
from neo4j import AsyncGraphDatabase

from .extractors import extract

PG_URL = os.environ.get("POSTGRES_URL", "postgresql://voidstrike:changeme@postgres:5432/voidstrike")
NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "changeme")


async def main() -> None:
    driver = AsyncGraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    await _ensure_schema(driver)

    aconn = await psycopg.AsyncConnection.connect(PG_URL, autocommit=True)
    async with aconn.cursor() as cur:
        await cur.execute("LISTEN episodes_inserted")

        # Backfill anything that arrived before we started listening.
        await _backfill(aconn, driver)

        # Now consume the live stream.
        async for notify in aconn.notifies():
            try:
                payload = json.loads(notify.payload)
            except json.JSONDecodeError:
                continue
            await _process_episode(driver, payload)
            await _mark_processed(aconn, payload.get("id"))


async def _mark_processed(aconn: Any, episode_id: Any) -> None:
    """Record that an episode has been projected, so a worker restart's backfill
    skips it instead of re-running the projection over the whole history. Without
    this the marker table stays empty and every restart reprocesses everything.
    """
    if episode_id is None:
        return
    try:
        async with aconn.cursor() as cur:
            await cur.execute(
                "INSERT INTO episode_etl_marker (episode_id) VALUES (%s) "
                "ON CONFLICT (episode_id) DO NOTHING",
                (episode_id,),
            )
    except Exception:  # noqa: BLE001 — marker is best-effort; never break the worker
        pass


async def _ensure_schema(driver: Any) -> None:
    constraints = [
        "CREATE CONSTRAINT host_addr IF NOT EXISTS FOR (h:Host) REQUIRE h.address IS UNIQUE",
        "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vuln) REQUIRE v.id IS UNIQUE",
        "CREATE CONSTRAINT eng_id IF NOT EXISTS FOR (e:Engagement) REQUIRE e.id IS UNIQUE",
        "CREATE CONSTRAINT svc_key IF NOT EXISTS FOR (s:Service) REQUIRE (s.host, s.port) IS UNIQUE",
        "CREATE CONSTRAINT path_key IF NOT EXISTS FOR (w:WebPath) REQUIRE w.url IS UNIQUE",
        "CREATE CONSTRAINT cred_key IF NOT EXISTS FOR (c:Credential) REQUIRE (c.host, c.type, c.source) IS UNIQUE",
    ]
    async with driver.session() as session:
        for c in constraints:
            await session.run(c)


async def _backfill(aconn: Any, driver: Any) -> None:
    async with aconn.cursor() as cur:
        await cur.execute(
            """
            SELECT id, engagement_id, agent_name, action, tool_input, tool_output,
                   outcome_tag, ts
            FROM episodes
            WHERE NOT EXISTS (
                SELECT 1 FROM episode_etl_marker m WHERE m.episode_id = episodes.id
            )
            ORDER BY id ASC
            LIMIT 5000
            """
        )
        rows = await cur.fetchall()
    for row in rows:
        await _process_episode(driver, {
            "id": row[0],
            "engagement_id": row[1],
            "agent_name": row[2],
            "action": row[3],
            "tool_input": row[4],
            "tool_output": row[5],
            "outcome_tag": row[6],
            "ts": row[7],
        })
        await _mark_processed(aconn, row[0])


async def _process_episode(driver: Any, episode: dict[str, Any]) -> None:
    engagement_id = episode.get("engagement_id")
    facts = extract(episode)

    async with driver.session() as session:
        await session.run("MERGE (e:Engagement {id: $id})", id=engagement_id)

        for host in facts.hosts:
            await session.run(
                """
                MERGE (h:Host {address: $host})
                MERGE (e:Engagement {id: $eid})
                MERGE (e)-[:TARGETS]->(h)
                """,
                host=host, eid=engagement_id,
            )

        for svc in facts.services:
            await session.run(
                """
                MERGE (h:Host {address: $host})
                MERGE (s:Service {host: $host, port: $port})
                SET s.protocol = coalesce($protocol, s.protocol),
                    s.service = coalesce($service, s.service),
                    s.version = coalesce($version, s.version),
                    s.product = coalesce($product, s.product),
                    s.banner = coalesce($banner, s.banner)
                MERGE (h)-[:EXPOSES]->(s)
                """,
                host=svc["host"],
                port=svc["port"],
                protocol=svc.get("protocol", "tcp"),
                service=svc.get("service"),
                version=svc.get("version"),
                product=svc.get("product"),
                banner=svc.get("banner"),
            )

        for web in facts.web_paths:
            await session.run(
                """
                MERGE (w:WebPath {url: $url})
                SET w.status = coalesce($status, w.status),
                    w.title = coalesce($title, w.title)
                WITH w
                MATCH (e:Engagement {id: $eid})
                MERGE (e)-[:DISCOVERED]->(w)
                """,
                url=web["url"],
                status=web.get("status"),
                title=web.get("title"),
                eid=engagement_id,
            )

        for cred in facts.credentials:
            await session.run(
                """
                MERGE (c:Credential {host: $host, type: $type, source: $source})
                WITH c
                MATCH (e:Engagement {id: $eid})
                MERGE (e)-[:HARVESTED]->(c)
                """,
                host=cred["host"], type=cred["type"], source=cred["source"],
                eid=engagement_id,
            )

        for cve in facts.cves:
            await session.run(
                """
                MERGE (v:Vuln {id: $cve})
                WITH v
                MATCH (e:Engagement {id: $eid})
                MERGE (e)-[:OBSERVED]->(v)
                """,
                cve=cve, eid=engagement_id,
            )


if __name__ == "__main__":
    asyncio.run(main())
