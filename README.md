# Voidstrike

Autonomous offensive security agent. Solves HTB-class CTF boxes unattended, tests web apps for OWASP-class issues, reads the web to ground its reasoning. Built on LangGraph + Deep Agents.

**Not a red team replacement.** No claims about OPSEC against modern EDR, no claims about social engineering, no claims about autonomously closing the defensive loop.

## What this is in one paragraph

A small set of subagents (Surface, Exploit, PostEx, Analyst) orchestrated by a main agent that reads structured findings and decides what to look at next. All offensive tooling lives behind MCP servers — `surface` (recon + web), `exploit` (payloads + delivery), `postex` (enum + privesc), `browser` (Playwright), `shell` (tmux sessions), `episodes` (Postgres-backed log). Three engagement modes (`ctf`, `lab`, `engagement`) with distinct prompts and HITL policies. A deterministic Rules-of-Engagement gate enforced by middleware — the model never decides whether a target is in scope.

## Solved boxes

[HackTheBox](https://www.hackthebox.com/) machines Voidstrike has taken to root unattended:

Bounty · Connected · DevArea · DevHub · Helix · Monteverde · Nibbles · Optimum · Querier · Resolute · SmartHIRE · Support · WingData · Reactor · Kobold

**Honest capability profile:** getting an initial foothold (a shell on the box) is a near-solved problem here — recon → vuln → exploit lands reliably across a wide range of targets. **Privilege escalation is hit or miss.** Some boxes go straight to root; others stall on the privesc chain (tunnel-vision on the wrong path, a non-obvious lateral hop, an environment-specific trick), which is where most of the ongoing work is focused.

## Quick start

```bash
# 0. Copy env and edit
cp .env.example .env

# 1. Install the Python backend into a venv
#    Python 3.11+ required. If `python3` is older, install 3.11 or 3.12 first
#    (e.g. `brew install python@3.12`) and substitute below.
python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# 2. Bring up the management plane
docker compose -f infra/docker-compose.yml up -d

# 3a. (Local dev) Bring up DVWA / Juice Shop on the ops network
docker compose -f infra/docker-compose.yml -f infra/docker-compose.ops.yml \
    --profile dev-targets up -d

# 3b. (HTB / external) Skip ahead — `voidstrike engage` brings up the VPN
#     sidecar automatically using the `vpn_config:` field in your engagement
#     YAML. (Pick exactly one of 3a or the VPN overlay — they're mutually
#     exclusive because `network_mode: service:vpn` is exclusive with ops-net.)

# 4. Run an engagement
voidstrike init                                  # one-time onboarding
voidstrike engage docs/examples/ctf-htb.yaml \
    --profile eco
```

The CLI streams every subagent's output (color-coded) to your terminal. The web dashboard (optional) is at http://localhost:3000.

### Full transcript (`--debug-log`)

`engage`, `attach`, and `resume` all accept `--debug-log <path>`, which records the agent's **entire process** — every tool call, tool result, and model message — as JSON Lines (one event per line):

```bash
voidstrike engage docs/examples/ctf-htb.yaml --debug-log logs/run.jsonl
# or capture an already-running engagement:
voidstrike attach <id> --debug-log logs/run.jsonl
```

This is the complete machine-readable record of a run — ideal for post-mortems, replaying what happened, or handing to an LLM to ask "why did it fail here?". The file is **append-mode** (each attach adds a `_debug_meta` delimiter, so reattaching never clobbers earlier capture). Events are captured **only while attached**: if you detach, reattach with `--debug-log` to resume recording.

### VPN flow

The VPN sidecar pattern: a single `vpn` container holds the OpenVPN tunnel, and the offensive MCP servers join its network namespace via `network_mode: "service:vpn"`. Every outbound packet from `nmap`, `curl`, Playwright, or a landed shell routes through the tunnel.

> **Use a TCP `.ovpn`, not UDP.** Under sustained offensive traffic — long `nmap` scans, brute/spray loops, a chatty reverse shell — UDP OpenVPN tunnels tend to drop and silently flap, which surfaces as scans that hang, shells that die mid-command, and "host unreachable" mid-run. A TCP-based config is noticeably more stable for these long-lived, high-connection-count workloads (slower, but it doesn't fall over). If your provider offers both (HackTheBox does), pick the **TCP** profile. If a run keeps losing the target, this is the first thing to check.

- **The `.ovpn` is declared in the engagement YAML.** Set `vpn_config:` to a path (absolute, or relative to the spec file) — `voidstrike engage` resolves it and brings up the vpn sidecar before posting the engagement. Resolution precedence: `--vpn` CLI flag > `VPN_FILE` env var > spec's `vpn_config:`.
- One VPN per compose stack — to swap targets, change the spec's `vpn_config:` and re-run `voidstrike engage`. Compose recreates the sidecar when the mount source changes.
- While the VPN overlay is active, the local dev targets (DVWA, Juice Shop) on `ops-net` are NOT reachable from the MCP containers. Pick local-dev or VPN, not both.
- Pass `--skip-vpn` to leave compose alone (use when the sidecar is already up with the right .ovpn, or for a non-VPN run).

> If `voidstrike: command not found`, the editable install didn't land the entry point on your PATH — re-run `pip install -e .` inside the venv, then make sure `.venv/bin` is on your PATH (or invoke as `python -m src.cli.main <command>`).

## Engagement spec

An engagement is described by a single YAML file passed to `voidstrike engage <spec>.yaml`. Templates live in [`docs/examples/`](docs/examples/). A fully-featured example:

```yaml
name: htb-checkpoint            # label for the engagement (required)
mode: ctf                      # ctf | lab | engagement (required)
targets:                       # hostnames or CIDRs in scope
  - 10.129.245.50
objective: "root flag"         # what "done" means (free text)
expected_flags: 2              # user + root — see below
budget_usd: 5.0                # hard cost cap for the run
profile: eco                   # eco | max | test (model tiers)
vpn_config: ../../client.ovpn  # .ovpn path (absolute, or relative to this file)

# Operator briefing — folded into the agent's opening message verbatim.
# Free-text pre-engagement context: scope hints, an internal hostname, a
# known-good foothold path, "don't touch X". For starting creds use `credentials`.
notes: |
  Assumed-breach start. The DC re-randomizes per spawn — re-derive any
  recovered secret each run rather than reusing an old value.

# Assumed-breach / provided credentials. Surfaced durably into the orchestrator
# and offensive-subagent system prompts so the agent uses them from the start
# instead of trying to discover or crack what it already holds.
credentials:
  - username: alex.turner
    secret: "Checkpoint2024!"
    kind: password             # password | hash | ssh-key | token | api-key
    service: smb               # ssh | smb | winrm | http | mysql | domain | ... (optional)
    host: dc01                 # scope to one host (optional)
    notes: domain account for authenticated enum + lateral movement (optional)

# Rules of engagement. In ctf/lab the scope is auto-derived from `targets`,
# so you usually omit this. Required in `engagement` mode (signed RoE).
roe:
  allowed_hosts: ["*.corp.local"]   # exact or wildcard hostnames
  allowed_networks: ["10.10.0.0/16"]# CIDRs
  blocked_hosts: ["10.10.0.5"]      # never touch, even if in an allowed range
  self_hosts: ["10.10.14.0/23"]     # your LHOST/VPN/staging — exempt from scope checks
  blocked_ports: [3389]
  allowed_techniques: ["*"]         # "*" or categories: recon, exploit, postex, ...
  blocked_techniques: []
  destructive_requires_approval: true
  signed_document_path: ./roe.pdf   # REQUIRED for `engagement` mode
  signed_by: "Jane Client"
  signed_at: 2026-06-01T00:00:00Z
```

### Fields

| Field | Required | Default | Notes |
|---|---|---|---|
| `name` | yes | — | Engagement label (used in the report + `voidstrike ls`). |
| `mode` | yes | — | `ctf` \| `lab` \| `engagement` — see [Three modes](#three-modes). |
| `targets` | yes | `[]` | Hostnames or CIDRs. In ctf/lab these also seed the RoE allowlist. |
| `objective` | no | `"root"` | Free-text goal the orchestrator works toward. |
| `expected_flags` | no | unset | When set (e.g. `2` for HTB user+root), a deterministic gate forces the analyst handoff once that many flags are recorded. Leave unset for multi-host labs. |
| `budget_usd` | no | `10.0` | `budget_guard` warns at 80%, hard-stops at 95%. |
| `profile` | no | `eco` | Model tiers — see [Profiles](#profiles). `--profile` on the CLI overrides this. |
| `vpn_config` | no | none | Path to a `.ovpn`; `voidstrike engage` brings up the VPN sidecar. Precedence: `--vpn` > `VPN_FILE` env > this. |
| `notes` | no | `""` | Operator briefing — see below. |
| `credentials` | no | `[]` | Assumed-breach credentials — see below. |
| `roe` | no¹ | auto | Rules of engagement. ¹Required in `engagement` mode (with `signed_document_path`). |

### `notes` — operator briefing

Free text delivered to the agent verbatim in its opening message as an **OPERATOR BRIEFING** block. Use it for anything the agent should know before starting that isn't a credential: a scope hint, an internal hostname, a known-good foothold path to skip re-deriving, "the box re-randomizes per spawn." It reaches the orchestrator, which relays the relevant parts into subagent task briefs.

### `credentials` — assumed-breach access

A list of credentials the engagement starts with (as in a real "assumed-breach" pentest). Unlike `notes`, these are surfaced **durably** into the orchestrator's and offensive subagents' system prompts (system prompts aren't summarized away over a long run), telling the agent to *use* what it already holds before discovering or cracking new creds.

| Sub-field | Required | Notes |
|---|---|---|
| `username` | yes | The account name. |
| `secret` | no | Password, NTLM hash, key material, token. Omit for username-only hints. |
| `kind` | no (`password`) | `password` \| `hash` \| `ssh-key` \| `token` \| `api-key`. |
| `service` | no | `ssh` \| `smb` \| `winrm` \| `http` \| `mysql` \| `domain` \| … — where it's used. |
| `host` | no | Scope the credential to one host. |
| `notes` | no | Free text (e.g. "rides the docker group"). |

> Don't pin *derived* secrets (a cracked hash, a shadow-cred NTLM) for a box that re-randomizes per spawn — those go stale. Pin only fixed starting creds, and describe how to re-derive the rest in `notes`.

## Three modes

| Mode | Use | RoE | HITL |
|---|---|---|---|
| `ctf` | HTB single-box | Auto from target | None — push hard |
| `lab` | Multi-host labs (Pro Labs, PG) | Auto from targets | Lateral movement only |
| `engagement` | Authorized real testing | Signed document required | All destructive actions |

See [`docs/examples/`](docs/examples/) for templates.

## Profiles

Modes pick the *posture*; profiles pick the *models*. Profiles are independent
of mode — use `--profile` on the CLI to override the value in the spec.

### Tier per role, per profile

| Profile | Orchestrator | Surface | Exploit | PostEx | Analyst | Researcher | AD¹ |
|---|---|---|---|---|---|---|---|
| `eco` (default) | HIGH | MID | HIGH | MID | MID | MID | HIGH |
| `max` | HIGH | HIGH | HIGH | HIGH | HIGH | HIGH | HIGH |
| `test` | LOW | LOW | LOW | LOW | LOW | LOW | LOW |

¹ The AD specialist (opt-in via `MCP_AD_URL`) rides the Exploit tier.

Tier mappings live in [`src/agent/models.py`](src/agent/models.py); the LiteLLM
routing chains are in [`infra/litellm-config.yaml`](infra/litellm-config.yaml).

### Tier → model mapping

LiteLLM routes each tier through a fallback chain. First-choice is listed first; the proxy falls through on rate-limit or outage.

| Tier | Anthropic (1st) | OpenAI (fallback) | Google (fallback) | Local fallback |
|---|---|---|---|---|
| **HIGH** | `claude-opus-4-8` | `gpt-5` | `gemini-3-pro` | — |
| **MID** | `claude-sonnet-4-6` | `gpt-5-mini` | `gemini-flash` | — |
| **LOW** | `claude-haiku-4-5` | `gpt-5-nano` | — | `qwen3-32b` (Ollama) |

### Why these choices

- **Orchestrator and Exploit stay HIGH in `eco`** (and the AD specialist rides the Exploit tier, so it's HIGH too). These carry the load-bearing reasoning. Demoting Exploit in particular causes silent failure on hard boxes — wrong payload, a stage that won't chain, a path abandoned that would have worked.
- **`eco`'s floor is MID, never LOW.** `eco` saves against `max` by running the non-critical roles on MID (Sonnet), not by dropping to LOW (Haiku) — Haiku botched PostEx privesc triage, so LOW is reserved for the `test` profile.
- **Surface, PostEx, Analyst, and Researcher run MID in `eco`.** Surface is mostly tool orchestration; PostEx is shell loops once a shell is landed (privesc *triage* still passes through the HIGH orchestrator); Analyst is a one-shot report; Researcher's deep reads are expensive — escalate it with `--profile max` when a box needs a hard CVE dive.
- **`max` is for engagements you cannot afford to lose.** Real customer testing, novel targets, anything where reasoning quality matters more than per-step cost.
- **`test` exists so CI doesn't bankrupt anyone.** Don't point it at real targets; LOW-tier models miss things higher tiers catch.

> **Implementation note.** Subagent specs hand deepagents a `provider:model`
> *string* (e.g. `anthropic:claude-opus-4-8`), not a pre-built model object —
> deepagents resolves the string *and* looks up its `HarnessProfile` by it,
> which hides the heavy filesystem tools from the orchestrator's surface and
> keeps Anthropic prompt caching wired in. The lone exception is the
> exploit/postex thinking path below. See [`models.py`](src/agent/models.py),
> [`profile.py`](src/agent/profile.py), and `CLAUDE.md`.

### Adaptive thinking (exploit/postex)

Set `VOIDSTRIKE_THINKING_EFFORT` in `.env` (`low | medium | high | xhigh | max`)
to give the two reasoning-heavy subagents (Exploit, PostEx) adaptive thinking
per step; unset (the default) runs without it. With a level set,
[`model_arg_for(...)`](src/agent/models.py) hands those subagents a
thinking-enabled Anthropic model, with effort clamped to what the tier supports
(Sonnet maxes at `high`; Haiku / non-Anthropic tiers stay plain). Thinking makes
the model deliberate between actions (diagnose-before-retry) instead of
reflexively firing the next tool call — the reflex loop is what drives the
expensive retry detours. Start at `high` and tune from there.

### Budgeting

`budget_guard` middleware tracks spend per engagement, warns at 80%, hard-stops at 95%. Set `budget_usd` on the spec realistically:

- Single HTB easy box on `eco`: typically $0.50 – $2
- HTB hard box on `eco`: $3 – $10
- 10-host lab on `eco`: $20 – $60
- External engagement on `max`: budget per scope, not per box (often 5–10× the `eco` rate for the same surface)

The benchmark aggregator ([`benchmark/aggregate.py`](benchmark/aggregate.py)) tracks median cost per box across runs so drift shows up in the trend line.

## Architecture

```
┌────────── management-net ──────────┐
│  Next.js ─── FastAPI gateway       │
│              │                     │
│              ├── Postgres (episodes + checkpoints)
│              ├── Neo4j (derived graph)
│              ├── Redis (UI pubsub)
│              ├── ETL worker (log → graph)
│              ├── LiteLLM (model router)
│              └── MCP servers
└──────────────────┬─────────────────┘
                   │ docker socket
                   ▼
┌──────────── ops-net (isolated) ────┐
│  kali-sandbox ── targets/VPN ──    │
└────────────────────────────────────┘
```

The sandbox writes back to the management plane only via the `episodes` MCP server. No direct DB connection from inside the sandbox.

## Web dashboard

The CLI is the primary surface; the dashboard is for observing engagements that are already running. It's opt-in — the `web` service in docker-compose is behind a profile so headless runs don't pay the build cost.

### Bring it up

```bash
# Bring up the management stack plus the web service
docker compose -f infra/docker-compose.yml --profile web up -d

# Or, alongside dev targets
docker compose \
    -f infra/docker-compose.yml \
    -f infra/docker-compose.ops.yml \
    --profile web --profile dev-targets up -d
```

Then open <http://localhost:3000>.

### Pages

| Path | What it shows |
|---|---|
| `/` | Index + quick links |
| `/engagements` | List of every engagement the gateway knows about (filesystem-backed) |
| `/engagements/<id>` | Detail view — lab progress, active shells, findings (severity-colored), full episode timeline |
| `/engagements/<id>/shell` | Read-only stream of any tmux session in the engagement. Polls ~1.5s |
| `/engagements/<id>/graph` | Neo4j-derived projection: hosts, services with versions, credentials, CVEs |
| `/hitl` | Pending HITL approvals across all engagements. Accept / reject with optional guidance |
| `/stuck` | Pending `StuckReport` escalations. Type a hint, click "Resume with this guidance" |
| `/skills` | Proposed skills from the `skill_proposer` middleware. Markdown preview per draft |

The dashboard is intentionally minimal — monospace, dark theme, no client-side router beyond Next.js's built-in. Everything talks to the FastAPI gateway via `NEXT_PUBLIC_GATEWAY_URL` (defaults to `http://localhost:8000`).

### Local dev (iterating on the dashboard)

```bash
cd web
npm install
NEXT_PUBLIC_GATEWAY_URL=http://localhost:8000 npm run dev
```

`/engagements/<id>/shell` and `/hitl` are client components that poll the gateway; `/engagements/<id>` and `/engagements/<id>/graph` are server components that fetch at request time. If a page is blank, check the gateway is reachable (`curl http://localhost:8000/healthz`) — the dashboard pages catch fetch failures and render an empty state rather than erroring.

## Repo layout

```
src/
├── agent/              # orchestrator, modes, subagents, middleware, prompts
├── mcp_servers/        # surface, exploit, postex, browser, shell, episodes, research, ad
├── etl/                # episode → Neo4j projection
├── gateway/            # FastAPI gateway (CLI + dashboard talk to this)
├── cli/                # Typer CLI (the `voidstrike` command)
└── schemas/            # pydantic models

skills/                 # progressive-disclosure SKILL.md files
infra/                  # docker compose, Dockerfiles, postgres init, litellm config
benchmark/              # ci_easy.py + nightly_full.py
tests/unit/             # RoE gate, schemas, middleware state
docs/examples/          # spec templates
```

## RoE gate

The one piece the design refuses to compromise on. A deterministic middleware extracts hosts/IPs/URLs from every tool call's args, matches against `ipaddress.ip_network`, blocks anything off-list. The model never decides scope.

Tested in [`tests/unit/test_roe_gate.py`](tests/unit/test_roe_gate.py).

## Cyber safeguard / Verification Program

Anthropic models carry a **real-time cyber safeguard** — a server-side classifier
that can return `stop_reason: "refusal"` with `stop_details.category: "cyber"` on
offensive-security content (exploit delivery, reverse shells, RCE). On an
unverified org these refusals are **intermittent**: a run can land a shell and
then have ~10–15% of subsequent exploit turns refused, which manifests as empty
"truncated" turns and a subagent that never emits its structured result. The CLI
now surfaces each refusal explicitly (`⚠ model refused …`) instead of letting it
look like a silent stall.

This is **not** something the agent prompts its way around, and we don't try to —
it's a safety mechanism. The legitimate unblock for authorized offensive-security
use (pentest engagements, CTF labs, security research) is Anthropic's **Cyber
Verification Program**: apply to have your org/key allowlisted. The refusal's own
`explanation` field links the application form, and the program is documented at
<https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude>.
Until verified, expect intermittent refusals on the exploit/postex subagents.

## Development

```bash
# Set up venv (Python 3.11+)
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Unit tests (no Docker required)
.venv/bin/pytest tests/unit/

# Lint
.venv/bin/ruff check src/
.venv/bin/mypy src/
```

For the full integration loop, you need Docker + a VPN config.

## Build phases (where we are)

- [x] **Phase 0** — scaffolding, RoE gate with unit tests, VPN-in-sandbox infrastructure
- [x] **Phase 1** — `ctf` mode end-to-end (Surface, Exploit, browser, shell MCP, episodes MCP)
- [x] **Phase 2** — `lab` mode (breadth tracker), PostEx (SUID enum, kernel suggester, credential loot), ETL enrichment, dashboard pages
- [x] **Phase 3** — skill proposer with novelty detection, Analyst report builder w/ ATT&CK, signed-RoE validator, benchmark aggregator
- [x] **Phase 4** — AD specialist + BloodHound MCP, Researcher specialist, async parallel-enum coordinator, OAuth scaffolding

600+ fast unit tests (no Docker required) — `.venv/bin/pytest tests/unit/`.

## What this is not

Marketing-honest scope:

- **Not a red-team replacement.** No OPSEC against EDR. No social engineering. No closing the defensive loop.
- **Stuck detection is a UX feature, not a bug.** ~20-30% of boxes need a hint; the agent escalates a structured `StuckReport` so the operator can answer with one question instead of watching it grind for two hours.
- **Skills loop is bidirectional** — the agent proposes new tradecraft, the operator reviews and merges. Nothing auto-merges into the active skill tree.

## License

[MIT](LICENSE).
