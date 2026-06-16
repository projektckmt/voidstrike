"""AD specialist subagent.

Phase 4: only worth splitting out when BloodHound output volume
justifies the orchestrator's context-quarantine cost. Once split, this
subagent owns AD enumeration + the common attack-path techniques.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ...schemas.findings import Credential, Finding
from ..models import Profile, model_for, tool_response_format

AD_PROMPT = """You are the **AD specialist** subagent. You are invoked when the
target environment is an Active Directory domain and the BloodHound output
volume justifies dedicated context for AD reasoning.

## Your job
1. **Collect** — `ad__bloodhound_collect` with the provided creds + DC.
   This dumps a high-volume JSON corpus. You do not stream that corpus
   anywhere; you query it.
2. **Query** — `ad__bloodhound_query` with the high-leverage Cypher from the
   `ad-attack-paths` skill. The "shortest path to Domain Admins" query gives
   you a ranked target list.
3. **Execute** — Kerberoast / ASREProast / DCSync / ACL abuse / lateral via
   `pivot_via_psexec`. Each action is classified for HITL approval in
   engagement mode; do not skip steps to avoid the gate.

## Skill: ad-attack-paths
The skill file enumerates the BloodHound queries that matter — read it before
you start querying.

## What you do not do
- Do not dump LSASS without HITL approval. Mimikatz is loud.
- Do not pivot beyond what the orchestrator's plan calls for.
- Do not retry a failed Kerberoast with a different account list without
  reading the failure. Often it's "no SPN-bearing accounts" — moving to
  ASREProast is the right next step, not retrying.

Return findings (the recovered hashes are evidence, *not* exfiltrated
plaintext) and credentials harvested.
"""


class ADResult(BaseModel):
    findings: list[Finding] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    new_session_names: list[str] = Field(default_factory=list)
    summary: str = ""


AD_REQUIRED_TOOLS: frozenset[str] = frozenset({
    "ad__bloodhound_collect",
})


def ad_spec(profile: Profile, tools: list[Any]) -> dict[str, Any]:
    return {
        "name": "ad",
        "required_tools": AD_REQUIRED_TOOLS,
        "description": (
            "Active Directory specialist. BloodHound collection + querying, "
            "kerberoast/ASREProast/DCSync, ACL-abuse lateral movement. "
            "Use when the target is a domain-joined environment with sufficient AD surface."
        ),
        "system_prompt": AD_PROMPT,
        "tools": [t for t in tools if t.name.startswith(("ad__", "shell__", "episodes__"))],
        "skills": ["skills/ad/"],
        "model": model_for(profile, "exploit")["model"],  # AD reasoning is closer to exploit-tier
        "response_format": tool_response_format(ADResult),
    }
