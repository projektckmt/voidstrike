"""AD specialist subagent.

Phase 4: only worth splitting out when BloodHound output volume
justifies the orchestrator's context-quarantine cost. Once split, this
subagent owns AD enumeration + the common attack-path techniques.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ...schemas.findings import Credential, Finding
from ..models import Profile, spec_model, tool_response_format

AD_PROMPT = """You are the **AD specialist** subagent. You are invoked when the
target environment is an Active Directory domain and the BloodHound output
volume justifies dedicated context for AD reasoning.

## ALWAYS / NEVER (read first)
- ALWAYS read the `ad-attack-paths` skill before querying — it lists the
  BloodHound Cypher queries that matter.
- ALWAYS query the collected corpus with `ad__bloodhound_query`; never stream
  the high-volume JSON dump anywhere.
- ALWAYS read the failure before retrying Kerberoast. A "no SPN-bearing
  accounts" result means pivot to ASREProast — NOT retry with another account
  list (that tests the same dead proposition).
- NEVER dump LSASS without HITL approval (Mimikatz is loud).
- NEVER pivot beyond what the orchestrator's plan calls for.
- NEVER skip steps to dodge the HITL gate — Kerberoast/ASREProast/DCSync/ACL
  abuse/lateral are each classified for engagement-mode approval.
- Recovered hashes are evidence, NOT exfiltrated plaintext.

## Your job
1. **Collect** — `ad__bloodhound_collect` with the provided creds + DC.
   This dumps a high-volume JSON corpus. You do not stream that corpus
   anywhere; you query it.
2. **Query** — `ad__bloodhound_query` with the high-leverage Cypher from the
   `ad-attack-paths` skill. The "shortest path to Domain Admins" query gives
   you a ranked target list.
3. **Execute** — Kerberoast / ASREProast / DCSync / ACL abuse / lateral via
   `pivot_via_psexec`.

Return findings and credentials harvested.
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
        "model": spec_model(profile, "exploit"),  # AD reasoning is closer to exploit-tier
        "response_format": tool_response_format(ADResult),
    }
