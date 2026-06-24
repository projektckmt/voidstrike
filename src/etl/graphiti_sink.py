"""Cross-engagement memory — the Graphiti sink.

The Neo4j projection in `log_to_graph` is *per-engagement and disposable*. This
is the opposite: a **persistent** temporal knowledge graph that accumulates
across every engagement, so any agent can recall what worked (and what failed)
before. It is the "learn from previous engagements" layer.

Same one-way ETL discipline as the rest of the system: episodes (Postgres) →
Graphiti. The episode log stays the source of truth — if this graph is wrong,
drop the `graphiti-neo4j` volume and replay the log.

Design notes
------------
- **Best-effort.** Ingestion failures here must NEVER break the primary
  projection write in `log_to_graph`. Every entry point swallows + logs.
- **Disabled by default.** Set `GRAPHITI_ENABLED=true` to turn it on. When off,
  every function is a cheap no-op so the ETL worker and the orchestrator tool
  keep running unchanged.
- **LLM + embedder route through the LiteLLM proxy** (OpenAI-compatible), so
  extraction runs on Claude Haiku by default and shares the same spend tracking
  / caching as everything else. Override via `GRAPHITI_LLM_*` if you want to
  point it elsewhere.
- **`group_id` is the confidentiality lever.** Everything lands in one shared
  group (`GRAPHITI_GROUP_ID`, default `tradecraft`) so recall spans engagements.
  Client-specific identifiers (hosts, creds) inevitably get extracted too — if
  that's unacceptable for a given engagement, point it at a per-client group.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field

log = structlog.get_logger(__name__)

# --- config ----------------------------------------------------------------

GRAPHITI_ENABLED = os.environ.get("GRAPHITI_ENABLED", "false").lower() in ("1", "true", "yes")
GROUP_ID = os.environ.get("GRAPHITI_GROUP_ID", "tradecraft")

_NEO4J_URI = os.environ.get("GRAPHITI_NEO4J_URI", "bolt://graphiti-neo4j:7687")
_NEO4J_USER = os.environ.get("GRAPHITI_NEO4J_USER", "neo4j")
_NEO4J_PASSWORD = os.environ.get("GRAPHITI_NEO4J_PASSWORD", "changeme")

# LLM + embedder default to the LiteLLM proxy's OpenAI-compatible surface.
_LLM_BASE_URL = os.environ.get("GRAPHITI_LLM_BASE_URL") or (
    os.environ.get("LITELLM_PROXY_URL", "http://litellm:4000").rstrip("/") + "/v1"
)
_LLM_API_KEY = os.environ.get("GRAPHITI_LLM_API_KEY") or os.environ.get(
    "LITELLM_MASTER_KEY", "sk-changeme"
)
_LLM_MODEL = os.environ.get("GRAPHITI_LLM_MODEL", "anthropic/claude-haiku-4-5")
_EMBED_MODEL = os.environ.get("GRAPHITI_EMBED_MODEL", "openai/text-embedding-3-large")


# --- entity taxonomy -------------------------------------------------------
# Mirrors the per-engagement projection's node labels so extracted memory stays
# in the same shape the rest of the system reasons about.


class Host(BaseModel):
    """A target host — an IP address or hostname seen during an engagement."""

    address: str | None = Field(None, description="IPv4/IPv6 address or hostname")


class Service(BaseModel):
    """A network service exposed on a host (port + product/version)."""

    port: int | None = Field(None, description="TCP/UDP port")
    product: str | None = Field(None, description="Service product, e.g. 'OpenSSH', 'Jenkins'")
    version: str | None = Field(None, description="Version string if known")


class Vulnerability(BaseModel):
    """A vulnerability or CVE observed or exploited."""

    cve: str | None = Field(None, description="CVE identifier, e.g. CVE-2021-22205")


class Technique(BaseModel):
    """An offensive technique, tool, or attack step the agent attempted."""

    tool: str | None = Field(None, description="Tool or technique name, e.g. 'kerberoast'")


class Outcome(BaseModel):
    """The result of an attempted action — did the technique work here?"""

    succeeded: bool | None = Field(None, description="True if the action achieved its goal")


ENTITY_TYPES: dict[str, type[BaseModel]] = {
    "Host": Host,
    "Service": Service,
    "Vulnerability": Vulnerability,
    "Technique": Technique,
    "Outcome": Outcome,
}


# --- client ----------------------------------------------------------------

_graphiti: Any = None


def _build_client() -> Any:
    from graphiti_core import Graphiti
    from graphiti_core.embedder.openai import OpenAIEmbedder, OpenAIEmbedderConfig
    from graphiti_core.llm_client.config import LLMConfig
    from graphiti_core.llm_client.openai_client import OpenAIClient

    llm = OpenAIClient(
        config=LLMConfig(
            api_key=_LLM_API_KEY,
            base_url=_LLM_BASE_URL,
            model=_LLM_MODEL,
            small_model=_LLM_MODEL,
        )
    )
    embedder = OpenAIEmbedder(
        config=OpenAIEmbedderConfig(
            api_key=_LLM_API_KEY,
            base_url=_LLM_BASE_URL,
            embedding_model=_EMBED_MODEL,
        )
    )
    return Graphiti(
        _NEO4J_URI,
        _NEO4J_USER,
        _NEO4J_PASSWORD,
        llm_client=llm,
        embedder=embedder,
    )


async def get_client() -> Any | None:
    """Lazy singleton. Returns None when memory is disabled or unavailable."""
    global _graphiti
    if not GRAPHITI_ENABLED:
        return None
    if _graphiti is None:
        try:
            _graphiti = _build_client()
        except Exception as exc:  # noqa: BLE001
            log.warning("graphiti.client_init_failed", error=str(exc))
            return None
    return _graphiti


async def ensure_indices() -> None:
    """Create Graphiti's indices/constraints once at worker startup. No-op when off."""
    client = await get_client()
    if client is None:
        return
    try:
        await client.build_indices_and_constraints()
    except Exception as exc:  # noqa: BLE001
        log.warning("graphiti.build_indices_failed", error=str(exc))


# --- ingest ----------------------------------------------------------------


def _episode_body(episode: dict[str, Any], facts: Any) -> str:
    """High-signal JSON for the extractor — structured facts + outcome, not raw dumps.

    Framing every episode as `action → outcome` over concrete targets is what
    lets a later search surface *what worked*, not just what exists.
    """
    payload = {
        "agent": episode.get("agent_name"),
        "action": episode.get("action"),
        "outcome": episode.get("outcome_tag"),
        "hosts": sorted(facts.hosts),
        "services": [
            {k: s.get(k) for k in ("host", "port", "service", "product", "version")}
            for s in facts.services
        ],
        "cves": sorted(facts.cves),
        "credentials": facts.credentials,
        "web_paths": [w.get("url") for w in facts.web_paths][:20],
        "output_excerpt": (episode.get("tool_output") or "")[:1500],
    }
    return json.dumps(payload, default=str)


async def ingest_episode(episode: dict[str, Any], facts: Any) -> None:
    """Project one episode into the cross-engagement graph. Best-effort, never raises."""
    client = await get_client()
    if client is None:
        return
    from graphiti_core.nodes import EpisodeType

    ref_time = episode.get("ts") or datetime.now(UTC)
    if isinstance(ref_time, str):
        try:
            ref_time = datetime.fromisoformat(ref_time)
        except ValueError:
            ref_time = datetime.now(UTC)

    try:
        await client.add_episode(
            name=f"{episode.get('agent_name', 'agent')}#{episode.get('id', '')}",
            episode_body=_episode_body(episode, facts),
            source=EpisodeType.json,
            source_description=(
                f"agent={episode.get('agent_name')} engagement={episode.get('engagement_id')}"
            ),
            reference_time=ref_time,
            group_id=GROUP_ID,
            entity_types=ENTITY_TYPES,
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("graphiti.ingest_failed", episode_id=episode.get("id"), error=str(exc))


# --- recall ----------------------------------------------------------------


async def recall(query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Hybrid search over the cross-engagement graph. Returns ranked facts.

    Each fact carries its bi-temporal validity so the agent can tell stale
    intelligence from current. Empty list when memory is disabled/unavailable.
    """
    client = await get_client()
    if client is None:
        return []
    try:
        results = await client.search(query, group_ids=[GROUP_ID], num_results=limit)
    except TypeError:
        # Older signatures don't accept num_results/group_ids kwargs.
        results = await client.search(query)
    except Exception as exc:  # noqa: BLE001
        log.warning("graphiti.recall_failed", error=str(exc))
        return []

    facts: list[dict[str, Any]] = []
    for edge in results or []:
        fact = getattr(edge, "fact", None)
        if not fact:
            continue
        facts.append(
            {
                "fact": fact,
                "valid_at": str(getattr(edge, "valid_at", "") or ""),
                "invalid_at": str(getattr(edge, "invalid_at", "") or ""),
            }
        )
    return facts[:limit]
