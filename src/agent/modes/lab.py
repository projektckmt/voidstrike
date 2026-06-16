"""Lab mode — multi-host environments (HTB Pro Labs, OffSec PG).

Map the network, prioritize foothold *breadth*, HITL only on lateral movement.
"""

from __future__ import annotations

from ...schemas.engagement import EngagementSpec
from ..prompts.lab import LAB_ORCHESTRATOR_PROMPT
from .ctf import _LAB_HOST_PATTERNS, _allowlist_from_targets


def lab_mode(spec: EngagementSpec):
    from . import ResolvedMode

    # Labs vary (HTB Pro Labs, internal ranges, ...), so don't assume a VPN
    # client range — honor whatever the operator declared as their own infra.
    # Seed the lab-TLD wildcards so discovered vhosts (.htb / AD .local) of
    # in-scope hosts aren't flagged as new out-of-scope targets.
    allowlist = _allowlist_from_targets(
        spec.targets,
        self_hosts=spec.roe.self_hosts,
        extra_allowed_hosts=[*_LAB_HOST_PATTERNS, *spec.roe.allowed_hosts],
    )
    # Lab allowlists default to "broader" — the operator's targets are usually CIDRs.
    return ResolvedMode(
        name=spec.mode,
        orchestrator_prompt=LAB_ORCHESTRATOR_PROMPT.format(
            target=", ".join(spec.targets),
            objective=spec.objective or "map and foothold breadth across the lab",
        ),
        allowlist=allowlist,
        budget_usd=spec.budget_usd,
        # HITL only for explicit lateral-movement decisions (action gating in the agent).
        interrupt_policy={
            "lateral_movement": {"allow_accept": True, "allow_edit": True, "allow_respond": True},
        },
        default_subagents=["surface", "researcher", "exploit", "postex", "analyst"],
        spec=spec,
    )
