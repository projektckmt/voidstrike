# Architecture quick reference

This is the at-a-glance version.

## Two-plane network

- **management-net** — UI, FastAPI gateway, LangGraph runtime, Postgres, Neo4j, Redis, LiteLLM, ETL worker, MCP servers.
- **ops-net (isolated)** — Kali sandbox, optional C2 (sliver), per-engagement targets.

The sandbox writes back to management only via the `episodes` MCP server. No direct DB connection from inside the sandbox.

## Storage split

- **Postgres `episodes` table** — append-only log, *source of truth*. `(engagement_id, agent_name, ts, action, tool_input, tool_output, outcome_tag)`.
- **Neo4j `findings` graph** — *derived* projection populated by the ETL worker. `Host`, `Service`, `Vuln`, `Credential`, `Finding` nodes. If the graph is wrong, drop it and rebuild from the log.

One-way ETL via Postgres `LISTEN/NOTIFY`.

## Subagent roster (phase 1)

| Agent | Owns |
|---|---|
| **Orchestrator** | OPPLAN, mode-specific posture, triage between subagents |
| **Surface** | recon + web testing (fused — same target model) |
| **Exploit** | payload generation, delivery, listener orchestration |
| **PostEx** | local enum, privesc, credential collection |
| **Analyst** | end-of-engagement report with ATT&CK mapping |

## MCP server boundary

Tools live behind MCP servers, not in-process. Process isolation, hot reload, reusable from other clients during dev.

| Server | Stateful? | Responsibilities |
|---|---|---|
| `shell` | yes (tmux sessions) | listeners, long scans, shells, msfconsole |
| `surface` | no | nmap, httpx, ffuf, subfinder, vhost-enum |
| `exploit` | no | searchsploit, msfvenom, generic delivery vectors |
| `postex` | no | enum recipes sent into shell sessions |
| `browser` | per-engagement | Playwright pages with cookies/state |
| `episodes` | yes (Postgres) | write/read the engagement log |

## Middleware stack

Order matters — RoE first, budget second, stuck third, skill proposer at end-of-engagement.

| Middleware | Role |
|---|---|
| `roe_gate` | Deterministic allowlist enforcement. Blocks off-scope targets. |
| `budget_guard` | Warns at 80% spend, hard-stops at 95%. |
| `stuck_detector` | Escalates a `StuckReport` after N tool calls without `new_finding`. |
| `skill_proposer` | At end-of-engagement, writes draft `SKILL.md` if objective met. |

## Three modes (distinct configurations)

- `ctf` — fast loop, no HITL, noisy techniques acceptable.
- `lab` — breadth-first across multi-host, HITL on lateral movement.
- `engagement` — slow, OPSEC-aware-ish, signed RoE required, HITL on all destructive classes.
