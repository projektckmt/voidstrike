"""Structured findings exchanged between subagents and orchestrator.

The shapes here are deliberately loose in their `notes`/`interesting_paths` fields.
Over-structuring the handoff is how you lose the banner string that would have told
the exploiter which CVE to try.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ExposedService(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    service: str | None = None
    version: str | None = None
    banner: str | None = None
    notes: str = ""


class WebSurface(BaseModel):
    url: str
    tech_stack: list[str] = Field(default_factory=list)
    interesting_paths: list[str] = Field(default_factory=list)
    forms: list[dict] = Field(default_factory=list)
    suspected_vulns: list[str] = Field(default_factory=list)
    notes: str = ""


class Credential(BaseModel):
    username: str | None = None
    password: str | None = None
    hash: str | None = None
    domain: str | None = None
    service: str | None = None
    source: str = ""


class SurfaceFindings(BaseModel):
    """Returned by the `surface` subagent. Triage input for the orchestrator."""

    services: list[ExposedService] = Field(default_factory=list)
    web: list[WebSurface] = Field(default_factory=list)
    credentials_seen: list[Credential] = Field(default_factory=list)
    suspected_entry_points: list[str] = Field(default_factory=list)
    summary: str = ""


class Finding(BaseModel):
    """Persistent, report-grade finding emitted by Exploit/PostEx for the Analyst."""

    title: str
    severity: str  # info | low | medium | high | critical
    host: str
    description: str
    impact: str = ""
    evidence: str = ""
    cve: list[str] = Field(default_factory=list)
    attack_pattern: str | None = None  # raw description; ATT&CK mapping happens in Analyst
    remediation: str = ""


class StuckReport(BaseModel):
    """Emitted by stuck_detector — surfaces to the operator via HITL."""

    engagement_id: str
    current_objective: str
    attempts: list[str] = Field(default_factory=list)
    surfaces_probed: list[str] = Field(default_factory=list)
    hypotheses_ruled_out: list[str] = Field(default_factory=list)
    operator_questions: list[str] = Field(default_factory=list)
    raw_episode_tail: list[dict] = Field(default_factory=list)
