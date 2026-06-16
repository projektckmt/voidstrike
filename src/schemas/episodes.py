"""Append-only episode log. Source of truth for agent working memory."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OutcomeTag(StrEnum):
    NEW_FINDING = "new_finding"
    DUPLICATE = "duplicate"
    NO_RESULT = "no_result"
    ERROR = "error"
    BLOCKED_BY_ROE = "blocked_by_roe"
    SHELL_LANDED = "shell_landed"
    PRIV_ESCALATED = "priv_escalated"
    OBJECTIVE_MET = "objective_met"
    VPN_LOST = "vpn_lost"


class Episode(BaseModel):
    engagement_id: str
    agent_name: str  # orchestrator | surface | exploit | postex | analyst
    timestamp: datetime
    action: str  # short verb, e.g. "tool:nmap_quick"
    tool_input: dict[str, Any] = Field(default_factory=dict)
    tool_output: str = ""
    outcome_tag: OutcomeTag = OutcomeTag.NO_RESULT
    cost_usd: float = 0.0
    duration_ms: int = 0
    error: str | None = None
