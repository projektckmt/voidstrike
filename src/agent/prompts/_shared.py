"""Prompt fragments shared across the three orchestrator modes.

Kept brace-free: each mode prompt is `.format(...)`-ed with `target` /
`objective` / `signed_by`, and these fragments are concatenated in *before*
that call, so a stray `{` here would raise `KeyError` at format time.
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

# Cross-engagement memory. The system accumulates a temporal knowledge graph
# across *every* engagement; `recall_prior_experience` is how this run reads it.
# Weak models won't reach for it on their own, so the trigger is mechanical.
PRIOR_EXPERIENCE = """
## Prior experience — check memory before you spend

`recall_prior_experience(query)` searches what worked (and failed) across ALL
past engagements — long-term memory, unlike `read_episode_tail`, which only sees
this run.

- ALWAYS call it before delegating to `researcher` or `exploit` on a new service
  or host. Query the concrete thing in front of you: the product+version
  ("Jenkins 2.4 on 8080"), a condition ("SMB signing disabled"), or a technique.
- A returned fact is a *lead*, not proof — it still goes through triage above.
  Confirm the precondition on THIS target before committing. Memory tells you
  what to try first; it does not tell you the target is the same.
- Empty result = no prior experience. That's normal early on — proceed as usual,
  never treat it as an error or a reason to stall.
"""
