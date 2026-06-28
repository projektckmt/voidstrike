# Operator runbook

## Bringing up the stack

```bash
cp .env.example .env
# edit .env with your API keys

# management plane only (sufficient for CTF mode + external VPN)
docker compose -f infra/docker-compose.yml up -d

# optionally, local dev targets (DVWA, Juice Shop) for the Phase-1 loop
docker compose -f infra/docker-compose.yml -f infra/docker-compose.ops.yml \
    --profile dev-targets up -d
```

Verify:

```bash
voidstrike init           # checks gateway health
docker compose logs -f gateway
```

## Running a CTF engagement

```yaml
# my-box.yaml
name: htb-blackfield
mode: ctf
targets: [10.10.10.192]
budget_usd: 5.0
profile: eco
vpn_config: ./htb-academy.ovpn  # resolved relative to this spec file
```

```bash
# `engage` reads vpn_config: from the spec and brings up the vpn sidecar
# automatically. Use --vpn only to override the spec's path.
voidstrike engage my-box.yaml
```

The CLI streams subagent output in real time. Ctrl-C from `voidstrike attach`
detaches and leaves the engagement running; Ctrl-C from a freshly launched
`voidstrike engage` pauses that run (resume with `voidstrike resume <id>`,
terminate with `voidstrike cancel <id>`). Reattach with `voidstrike attach
<engagement_id>`.

## Stuck escalation

After 15 tool calls without a `new_finding`, the agent pauses and emits a
`StuckReport`. In the CLI you'll see a structured prompt; respond with:

```bash
voidstrike approve <engagement_id> --decision respond \
    --guidance "The vhost is shop.htb. Try directory-busting that hostname."
```

In the dashboard, the stuck queue lists pending escalations with a response box.

## Reviewing proposed skills

After a successful engagement, the `skill_proposer` middleware drops a draft
`SKILL.md` to `skills/_proposed/`.

```bash
voidstrike skills review                # list pending proposals
voidstrike skills accept <name> --into exploit   # promote to active
```

Or via the dashboard at `/skills`.

## Engagement-mode checklist

Before starting an engagement-mode run:

1. Customer's signed RoE is on disk and referenced from `roe.signed_document_path`.
2. `roe.signed_by` and `roe.signed_at` are set.
3. `allowed_hosts` and `allowed_networks` match the scope document exactly.
4. `blocked_hosts` covers any out-of-scope items (jumphosts, partner infra).
5. `destructive_requires_approval: true` (default — leave it).
6. Budget cap is realistic for the scope and time.

The agent will refuse to start if 1–2 are missing. The deterministic RoE gate
enforces 3–4 at every tool call.

## VPN drop mid-engagement

The orchestrator pauses with a `StuckReport` describing the lost connection.
After restoring the tunnel out-of-band:

```bash
voidstrike approve <engagement_id> --decision respond \
    --guidance "VPN restored. Resume."
```

The agent retries from the last good state — tmux sessions are preserved.

## Cost overruns

`budget_guard` warns at 80% and hard-stops at 95%. If you want to raise the
cap mid-engagement, you'll need to write a new episode marking the budget
extension and restart with a fresh `--budget` (Phase 3 will expose this as a
CLI command).

## Running benchmarks

Measures agent performance against the [XBOW validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks)
corpus (104 web CTF boxes, pinned as the `benchmark/xbow` submodule). Each box
self-provisions: the runner builds it with the canonical `FLAG{sha256hex(NAME)}`,
attaches its web service to `voidstrike_ops-net` under the box's hostname, runs
an engagement, scores by exact flag-equality, then tears it down.

```bash
# one-time: pull the corpus
git submodule update --init benchmark/xbow

# management plane must be up (creates voidstrike_ops-net + gateway :8000)
docker compose -f infra/docker-compose.yml up -d

source .venv/bin/activate
python -m benchmark.ci_easy        # 45 level-1 XBOW boxes, eco profile (scored)
python -m benchmark.lab            # DVWA/Juice Shop smoke targets, eco (unscored)
python -m benchmark.nightly_full   # full 104-box corpus, max profile
python -m benchmark.aggregate      # roll up the pass-rate / cost trend
```

The runner shells out to `docker compose`, so run it on a host with Docker
access and reachability to the gateway. Knobs: `VOIDSTRIKE_GATEWAY` (default
`http://localhost:8000`), `PR_BUDGET_USD` (ci_easy spend cap, default 30),
`REGRESSION_TOLERANCE` (boxes ci_easy may drop vs `results/baseline.json`
before failing, default 2).

In CI this runs nightly (`.github/workflows/benchmark.yml`) or on demand via
**Actions → benchmark → Run workflow** (pick `ci_easy` or `nightly`) on the
self-hosted runner. To iterate on a single box:

```bash
python -c "import asyncio; from benchmark import xbow, ci_easy; \
b=[x for x in xbow.load(1) if x['name']=='XBEN-005-24'][0]; \
print(asyncio.run(ci_easy.run_benchmark(b)))"
```

## When the agent does something dumb

1. Read the episode log: `voidstrike episodes <engagement_id> --n 200`.
2. Identify the bad step. Was it bad tradecraft (skill gap) or bad selection
   (orchestrator triage)?
3. Skill gap → write or revise the relevant `SKILL.md`.
4. Orchestrator selection → revise the prompt in `src/agent/prompts/<mode>.py`.
5. Re-run.

This is the loop. The agent gets better when you fix what failed, not when you
add more middleware.
