"""Prompt fragments shared across the three orchestrator modes.

Kept brace-free: each mode prompt is `.format(...)`-ed with `target` /
`objective` / `signed_by`, and these fragments are concatenated in *before*
that call, so a stray `{` here would raise `KeyError` at format time.
"""

# OPPLAN — the orchestrator plans with the `write_opplan` tool (opplan.py), whose
# schema enforces the phase structure below: each phase MUST carry intent, a
# cheapest-confirm move, a decision/branch, and a status — the model can't emit a
# bare string. Mode-agnostic, so it lives here.
OPPLAN = """
## OPPLAN — plan in phases with `write_opplan`, not a flat checklist

Record your plan with the `write_opplan` tool, NOT `write_todos` (that's for
subagents). An OPPLAN is an ordered set of phases; each phase carries:

- **phase** — an ordered stage (e.g. `RECON`, `FOOTHOLD`, `PRIVESC`, `LOOT`).
  Phases gate each other: you do not start a later phase until the earlier one
  produced what the later one consumes.
- **intent** — what this phase is trying to establish (its objective).
- **confirm_move** — the single lowest-cost action that confirms or kills this
  phase's key assumption before you commit. (The triage rule below, per phase.)
- **decision** — the observable that advances the phase, plus the branch if it
  does not appear: "if the precondition is false, drop to <next-ranked move>." A
  phase with no stated branch is a guess, not a plan.
- **status** — `pending` | `active` | `done` | `dead`.

Keep the OPPLAN current: as evidence lands, flip statuses, mark a phase `dead`
the moment its precondition is disproven (don't leave it pending and torture the
data), and re-rank the remaining phases. The OPPLAN is the orchestrator's
artifact; subagents keep their own tactical `write_todos` lead-lists — don't
push OPPLAN structure down into them.
"""

# Triage discipline — the general fix for "assume a technique, then torture the
# data to fit it." A real run committed its whole plan to AS-REP roasting off a
# DC banner, then guessed usernames into existence when the first attempt showed
# no account was roastable. The lesson is mode-agnostic, so it lives here.
TRIAGE_DISCIPLINE = """
## Triage discipline — enumerate before you commit

The intelligence of this system is your triage. The failure that wastes whole
engagements is locking the *entire plan* onto one technique you pattern-matched
from a banner, before any evidence that technique applies.

- **Rank hypotheses; don't marry one.** "It's an AD DC, so AS-REP roast" is a
  hypothesis, not a plan. Pick the move whose precondition is cheapest to
  *confirm*, confirm it, then commit. A technique with an unconfirmed
  precondition is a guess.
- **Enumerate the real facts before any attack that depends on them.** Before a
  user-list attack, get the *actual* user set (RID-brute / LDAP / rpcclient /
  the surface findings) — never guess names. Before a version-specific exploit,
  confirm the version. Inventing inputs to fit a technique (made-up usernames,
  assumed paths) is the same error as hallucinating a banner.
- **When the evidence contradicts the hypothesis, drop it — don't torture the
  data.** If the first attempt shows the precondition is false ("no user has
  DONT_REQ_PREAUTH", `PRINCIPAL_UNKNOWN`, a version mismatch), that technique is
  dead here. Re-enumerate and pick the next-ranked hypothesis; do not keep
  feeding it new guesses to make it fire.
- **Prefer the highest-probability cheap move first.** For an AD foothold with a
  user list and no creds, that is a password spray (including username==password)
  before any roasting; AS-REP/Kerberoast only once you've confirmed roastable /
  SPN-bearing accounts actually exist.
"""
