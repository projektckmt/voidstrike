"""MITRE ATT&CK heuristic mapping.

ATT&CK is *output*, not internal planning. The Analyst subagent
uses this module to label findings with `(tactic, technique)` pairs for the
final report. Nowhere else in the system uses these strings.

The map is intentionally a flat dict, not a full ATT&CK STIX import. We map
the things our tools actually produce. Unknown findings get an empty mapping
and a note that the analyst should review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (tactic_id, technique_id) — see attack.mitre.org for canonical names.
@dataclass(frozen=True)
class AttackRef:
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str


# Keyed by signature substring; first-match wins so order is meaningful.
_SIGNATURES: list[tuple[re.Pattern, AttackRef]] = [
    # `\b` doesn't work across `surface__nmap_quick` because `_` is a word char,
    # so we use plain substring matching for the tool-name signatures.
    (re.compile(r"nmap_(quick|full)"),
     AttackRef("TA0043", "Reconnaissance", "T1595.001", "Scanning IP Blocks")),
    (re.compile(r"httpx_fingerprint"),
     AttackRef("TA0043", "Reconnaissance", "T1595.002", "Vulnerability Scanning")),
    (re.compile(r"subfinder"),
     AttackRef("TA0043", "Reconnaissance", "T1590.005", "IP Addresses")),
    (re.compile(r"vhost_enum|ffuf"),
     AttackRef("TA0043", "Reconnaissance", "T1595.003", "Wordlist Scanning")),

    (re.compile(r"deliver_via_web|web_shell|file_upload"),
     AttackRef("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application")),
    (re.compile(r"deliver_via_ssh"),
     AttackRef("TA0001", "Initial Access", "T1078.004", "Valid Accounts: Cloud Accounts")),
    (re.compile(r"deliver_via_smb|impacket-psexec"),
     AttackRef("TA0008", "Lateral Movement", "T1021.002", "SMB/Windows Admin Shares")),

    (re.compile(r"reverse_(tcp|https)|meterpreter|shell_landed"),
     AttackRef("TA0002", "Execution", "T1059.004", "Unix Shell")),

    (re.compile(r"linpeas|linux_basic_enum|suid_enum|SUID|setuid|setgid", re.IGNORECASE),
     AttackRef("TA0004", "Privilege Escalation", "T1548.001", "Setuid and Setgid")),
    (re.compile(r"windows_basic_enum|seimpersonate|juicy_potato|godpotato"),
     AttackRef("TA0004", "Privilege Escalation", "T1134.001", "Token Impersonation/Theft")),
    (re.compile(r"kernel_suggester|dirtypipe|dirtycow"),
     AttackRef("TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation")),

    (re.compile(r"loot_credentials"),
     AttackRef("TA0006", "Credential Access", "T1552", "Unsecured Credentials")),
    (re.compile(r"/etc/shadow|hashcat|john"),
     AttackRef("TA0006", "Credential Access", "T1003.008", "/etc/passwd and /etc/shadow")),
    (re.compile(r"mimikatz|lsass"),
     AttackRef("TA0006", "Credential Access", "T1003.001", "LSASS Memory")),
    (re.compile(r"kerberoast"),
     AttackRef("TA0006", "Credential Access", "T1558.003", "Kerberoasting")),
    (re.compile(r"asreproast"),
     AttackRef("TA0006", "Credential Access", "T1558.004", "AS-REP Roasting")),
    (re.compile(r"dcsync"),
     AttackRef("TA0006", "Credential Access", "T1003.006", "DCSync")),

    (re.compile(r"bloodhound|sharphound|powerview"),
     AttackRef("TA0007", "Discovery", "T1087.002", "Domain Account")),
]


def map_episode(action: str, tool_output: str = "") -> AttackRef | None:
    """Return the first matching ATT&CK ref, or None if no signature matches."""
    haystack = f"{action} {tool_output}"
    for pattern, ref in _SIGNATURES:
        if pattern.search(haystack):
            return ref
    return None


def map_finding(finding: dict) -> list[AttackRef]:
    """Map a single Finding object to its likely ATT&CK refs.

    Looks at the title, attack_pattern (if the agent left one), and evidence.
    Returns *all* matches — a single finding may span multiple techniques.
    """
    haystack = " ".join([
        finding.get("title", ""),
        finding.get("attack_pattern", "") or "",
        finding.get("description", ""),
        finding.get("evidence", ""),
    ])
    refs: list[AttackRef] = []
    seen: set[str] = set()
    for pattern, ref in _SIGNATURES:
        if pattern.search(haystack) and ref.technique_id not in seen:
            refs.append(ref)
            seen.add(ref.technique_id)
    return refs
