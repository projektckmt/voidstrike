---
name: attack-mapping
description: Mapping concrete attack steps to MITRE ATT&CK tactics and techniques for the final report.
---

# ATT&CK mapping (analyst-only)

This is the **only** place ATT&CK enters the workflow. The
orchestrator and other subagents think in concrete terms; the analyst maps
findings to taxonomy at end-of-engagement.

## Common mappings

| Episode signal | Tactic | Technique |
|---|---|---|
| Port scan, service enum | TA0043 Reconnaissance | T1595 Active Scanning |
| Subdomain / vhost enum | TA0043 | T1590.005 Gather Victim Network Info |
| Default creds login | TA0001 Initial Access | T1078 Valid Accounts |
| Web exploit landing a shell | TA0001 + TA0002 | T1190 Exploit Public-Facing App |
| SSH with creds | TA0001 | T1078.004 Cloud Accounts |
| File upload → web shell | TA0001 + TA0002 | T1505.003 Web Shell |
| Local privesc via SUID | TA0004 Priv Esc | T1548.001 Setuid and Setgid |
| Token impersonation (Win) | TA0004 | T1134 Access Token Manipulation |
| `mimikatz` LSASS dump | TA0006 Cred Access | T1003.001 LSASS Memory |
| Reading `/etc/shadow` | TA0006 | T1003.008 /etc/passwd & /etc/shadow |
| Lateral via SMB w/ creds | TA0008 Lateral | T1021.002 SMB/Windows Admin Shares |
| Kerberoasting | TA0006 | T1558.003 Kerberoasting |

## Rules

- Map every confirmed exploitation step to at least one technique.
- Do not invent techniques. If a step doesn't map, leave it unmapped and note
  why in the report.
- Multiple tactics per technique is fine — `T1190` is both Initial Access
  (TA0001) and Execution (TA0002).
