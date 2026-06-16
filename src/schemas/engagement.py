"""Engagement spec, RoE, mode resolution types."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class EngagementMode(StrEnum):
    CTF = "ctf"
    LAB = "lab"
    ENGAGEMENT = "engagement"


class RulesOfEngagement(BaseModel):
    """Allow-only network scope. The middleware enforces this deterministically."""

    allowed_hosts: list[str] = Field(default_factory=list)  # hostnames (exact or wildcard)
    allowed_networks: list[str] = Field(default_factory=list)  # CIDR
    blocked_hosts: list[str] = Field(default_factory=list)
    # Attacker-side infrastructure — your LHOST / VPN tun IP / staging server.
    # Never treated as a target: referencing your own box (payload LHOST, a
    # reverse-shell listener, an HTTP staging server) is not an RoE violation,
    # so these IPs/CIDRs are exempt from the target allowlist check. CTF mode
    # seeds this with the HTB VPN client ranges; set it explicitly for other
    # environments (e.g. your tun0 CIDR).
    self_hosts: list[str] = Field(default_factory=list)  # attacker IPs / CIDRs
    blocked_ports: list[int] = Field(default_factory=list)
    allowed_techniques: list[str] = Field(
        default_factory=lambda: ["*"]
    )  # `*` or category names: recon, exploit, postex, etc.
    blocked_techniques: list[str] = Field(default_factory=list)
    destructive_requires_approval: bool = True
    signed_document_path: str | None = None  # required for engagement mode
    signed_by: str | None = None
    signed_at: datetime | None = None

    @field_validator("allowed_networks", "blocked_hosts", mode="after")
    @classmethod
    def _validate_cidr(cls, value: list[str]) -> list[str]:
        # blocked_hosts may be plain hostnames; allowed_networks must parse as CIDR
        return value

    def parsed_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(net, strict=False) for net in self.allowed_networks]


class ProvidedCredential(BaseModel):
    """An operator-provided / assumed-breach credential the engagement starts with.

    Real pentests often begin with a foothold account ("you start with
    alex.turner / Checkpoint2024!"). These are surfaced durably into the
    orchestrator and offensive-subagent system prompts so the agent uses them
    instead of trying to discover/crack what it already holds.
    """

    username: str
    secret: str = ""             # password, NTLM hash, key material, token
    kind: str = "password"       # password | hash | ssh-key | token | api-key
    service: str | None = None   # ssh | smb | winrm | http | mysql | domain ...
    host: str | None = None      # where it applies, if scoped to one host
    notes: str | None = None

    def one_line(self) -> str:
        """Single-line summary for the credentials prompt block."""
        line = f"{self.username} : {self.secret or '(no secret provided)'}"
        quals = [self.kind]
        if self.service:
            quals.append(f"service: {self.service}")
        if self.host:
            quals.append(f"host: {self.host}")
        line += f"  ({'; '.join(quals)})"
        if self.notes:
            line += f" — {self.notes}"
        return line


class EngagementSpec(BaseModel):
    """Loaded from a YAML file the operator supplies."""

    name: str
    mode: EngagementMode
    targets: list[str] = Field(default_factory=list)  # hostnames or CIDRs
    objective: str = "root"  # ctf default
    # How many flags constitute "done". When set (e.g. 2 for a user+root HTB
    # box), the completion gate deterministically forces a handoff to the
    # analyst once that many flags are recorded — instead of relying on the
    # orchestrator prompt, which routes correctly only some of the time. Leave
    # unset for multi-host labs where flag count isn't the completion signal.
    expected_flags: int | None = None
    budget_usd: float = 10.0
    profile: str = "eco"  # eco | max | test
    vpn_config: str | None = None  # path to .ovpn
    roe: RulesOfEngagement = Field(default_factory=RulesOfEngagement)
    # Operator briefing delivered to the agent at kickoff (the gateway folds it
    # into the opening message as an "OPERATOR BRIEFING" block). Use it for
    # pre-engagement context the agent must act on — an internal hostname, a
    # scope hint, anything free-text. Relayed verbatim in the kickoff message.
    # For starting credentials prefer the structured `credentials` field below.
    notes: str = ""
    # Assumed-breach / operator-provided credentials the engagement starts with.
    # Surfaced durably into the orchestrator + offensive-subagent system prompts.
    credentials: list[ProvidedCredential] = Field(default_factory=list)

    def credentials_block(self) -> str:
        """Prompt block describing the provided credentials, or '' if none.

        Appended to the orchestrator and offensive-subagent system prompts so the
        agent always has them — system prompts aren't summarized away over a long
        run, unlike the kickoff message."""
        if not self.credentials:
            return ""
        lines = [
            "## Provided credentials (assumed-breach — operator-supplied)",
            "",
            "You begin this engagement already holding these credentials. Treat "
            "them as ground truth and USE them — for authenticated enumeration, "
            "service access, and lateral movement — before trying to discover or "
            "crack new ones. When delegating, pass the relevant credential to the "
            "subagent in its task brief.",
            "",
            *(f"- {c.one_line()}" for c in self.credentials),
        ]
        return "\n".join(lines)

    @classmethod
    def from_yaml(cls, path: str | Path) -> EngagementSpec:
        import yaml

        with open(path) as fh:
            return cls.model_validate(yaml.safe_load(fh))
