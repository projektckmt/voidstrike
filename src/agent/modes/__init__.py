"""Engagement mode resolution.

Each mode is a *distinct* orchestrator prompt + default roster + interrupt policy.
They share infrastructure (subagents, MCP servers) but the behaviour is shaped
here. Modes are not flags on a single workflow.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ...schemas.engagement import EngagementMode, EngagementSpec, RulesOfEngagement
from .ctf import ctf_mode
from .engagement import engagement_mode
from .lab import lab_mode


@dataclass
class ResolvedMode:
    """The materialized policy for an engagement run."""

    name: EngagementMode
    orchestrator_prompt: str
    allowlist: RulesOfEngagement
    budget_usd: float
    interrupt_policy: dict[str, Any]
    default_subagents: list[str]
    spec: EngagementSpec


_MODE_RESOLVERS: dict[EngagementMode, Callable[[EngagementSpec], ResolvedMode]] = {
    EngagementMode.CTF: ctf_mode,
    EngagementMode.LAB: lab_mode,
    EngagementMode.ENGAGEMENT: engagement_mode,
}


def resolve_mode(spec: EngagementSpec | str | Path) -> ResolvedMode:
    """Materialize the mode-specific policy from a spec file or object."""
    if isinstance(spec, (str, Path)):
        spec = EngagementSpec.from_yaml(spec)
    resolver = _MODE_RESOLVERS[spec.mode]
    return resolver(spec)


__all__ = ["ResolvedMode", "resolve_mode", "ctf_mode", "lab_mode", "engagement_mode"]
