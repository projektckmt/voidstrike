"""CTF mode — HTB single-target, fast loop, no HITL.

The orchestrator pushes hard, accepts noisy techniques, and aims for the flag.
"""

from __future__ import annotations

import ipaddress

from ...schemas.engagement import EngagementSpec, RulesOfEngagement
from ..prompts.ctf import CTF_ORCHESTRATOR_PROMPT

# HTB VPN client (tun0) ranges — the *attacker* side, never a target. HTB
# machines live in 10.129.0.0/16 (active) and 10.10.10/11.x (retired), which do
# not overlap these, so seeding them is safe and stops a payload LHOST / staging
# IP from tripping the RoE gate. Override per-environment via `spec.roe.self_hosts`.
_HTB_VPN_CLIENT_RANGES = ["10.10.14.0/23", "10.10.16.0/23"]

# Non-routable lab TLDs. Boxes serve their content under vhosts like
# `silentium.htb` / `dc01.corp.local` that the agent maps (via /etc/hosts) to
# the in-scope target IP. These TLDs don't resolve on the internet, so they can
# only ever point at lab hosts — allowing them as wildcards lets the RoE gate
# accept a discovered vhost of an in-scope box without flagging it as a new
# out-of-scope target. Real internet TLDs (`.com`, ...) are still gated.
_LAB_HOST_PATTERNS = ["*.htb", "*.local", "*.lab", "*.vl", "*.thm"]


def _allowlist_from_targets(
    targets: list[str],
    self_hosts: list[str] | None = None,
    extra_allowed_hosts: list[str] | None = None,
) -> RulesOfEngagement:
    hosts: list[str] = []
    networks: list[str] = []
    for entry in targets:
        try:
            ipaddress.ip_network(entry, strict=False)
            networks.append(entry)
        except ValueError:
            hosts.append(entry)
    # De-dupe while preserving order (target hosts first, then seeded patterns).
    allowed_hosts = list(dict.fromkeys([*hosts, *(extra_allowed_hosts or [])]))
    return RulesOfEngagement(
        allowed_hosts=allowed_hosts,
        allowed_networks=networks,
        self_hosts=list(self_hosts or []),
        destructive_requires_approval=False,
        allowed_techniques=["*"],
    )


def ctf_mode(spec: EngagementSpec):
    from . import ResolvedMode

    # CTF == HTB: seed the attacker-side VPN ranges so LHOST/staging IPs don't
    # trip the RoE gate, and the lab-TLD wildcards so a discovered vhost
    # (silentium.htb) of the in-scope box is accepted. Plus the operator's spec.
    allowlist = _allowlist_from_targets(
        spec.targets,
        self_hosts=[*_HTB_VPN_CLIENT_RANGES, *spec.roe.self_hosts],
        extra_allowed_hosts=[*_LAB_HOST_PATTERNS, *spec.roe.allowed_hosts],
    )
    return ResolvedMode(
        name=spec.mode,
        orchestrator_prompt=CTF_ORCHESTRATOR_PROMPT.format(
            target=", ".join(spec.targets),
            objective=spec.objective or "root flag",
        ),
        allowlist=allowlist,
        budget_usd=spec.budget_usd,
        interrupt_policy={},  # no HITL in CTF mode
        default_subagents=["surface", "researcher", "exploit", "postex", "analyst"],
        spec=spec,
    )
