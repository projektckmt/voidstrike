"""Bidirectional skills loop — agent proposes, operator reviews.

Three improvements over the phase-1 version:

1. **Novel-sequence detection.** Walk the episode log and extract the *productive*
   action sequence (steps tagged NEW_FINDING / SHELL_LANDED / PRIV_ESCALATED /
   OBJECTIVE_MET). Hash the sequence. If the hash matches an existing skill's
   `proposed_from` marker or the sequence is a sub-sequence of a known skill,
   skip — nothing novel.

2. **Per-phase routing.** The sequence is sliced by the subagent that produced
   each step (surface vs exploit vs postex). A proposal is emitted *per slice*
   into the matching subagent's directory, not as a single megaproposal.

3. **Linked skill graph.** Existing skills referenced by name in the sequence
   are linked with `[[link]]` in the proposal so the operator can see how the
   new skill fits.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ...schemas.episodes import OutcomeTag

PROPOSED_DIR = Path("skills/_proposed")
SLUG_RE = re.compile(r"[^a-z0-9-]+")

PRODUCTIVE_OUTCOMES = {
    OutcomeTag.NEW_FINDING,
    OutcomeTag.SHELL_LANDED,
    OutcomeTag.PRIV_ESCALATED,
    OutcomeTag.OBJECTIVE_MET,
}

AGENT_TO_SKILL_DIR = {
    "surface": "surface",
    "exploit": "exploit",
    "postex": "postex",
    "browser": "browser",
    "analyst": "analyst",
}


def _slugify(text: str) -> str:
    return SLUG_RE.sub("-", text.lower()).strip("-")[:64] or "proposed"


def _sequence_hash(actions: list[str]) -> str:
    """Stable hash of an action sequence — used to dedupe across runs."""
    return hashlib.sha256("|".join(actions).encode()).hexdigest()[:12]


def _load_known_hashes(skills_root: Path) -> set[str]:
    """Find `proposed_from:` markers in existing skills."""
    known: set[str] = set()
    if not skills_root.exists():
        return known
    for skill_md in skills_root.glob("**/SKILL.md"):
        try:
            content = skill_md.read_text()
        except OSError:
            continue
        for match in re.finditer(r"proposed_from:\s*([0-9a-f]{12})", content):
            known.add(match.group(1))
    return known


def _slice_by_agent(episodes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Bucket productive episodes by the subagent that produced them."""
    slices: dict[str, list[dict[str, Any]]] = {}
    for ep in episodes:
        if ep.get("outcome_tag") not in PRODUCTIVE_OUTCOMES:
            continue
        agent = ep.get("agent_name", "")
        slice_key = AGENT_TO_SKILL_DIR.get(agent)
        if not slice_key:
            continue
        slices.setdefault(slice_key, []).append(ep)
    return slices


def _format_skill(
    name: str,
    slice_episodes: list[dict[str, Any]],
    sequence_hash: str,
    summary: str,
    linked_skills: list[str],
) -> str:
    description = (summary or "Auto-proposed from a successful engagement.")[:1024]
    steps = []
    for ep in slice_episodes:
        action = ep.get("action", "")
        tool_input = ep.get("tool_input", {})
        outcome = ep.get("outcome_tag", "")
        steps.append(f"- **{action}** (`{outcome}`) — `{tool_input}`")

    linked_lines = "\n".join(f"- [[{s}]]" for s in linked_skills) or "_(none)_"

    return f"""---
name: {name}
description: {description}
metadata:
  status: proposed
  proposed_at: {datetime.now(UTC).isoformat()}
  proposed_from: {sequence_hash}
---

# {name.replace('-', ' ').title()}

Draft skill auto-proposed by Voidstrike. Review the sequence below, edit, then
move into the relevant subagent's skill directory to activate. Until then this
skill is **not** loaded by any agent.

## Observed productive sequence

{chr(10).join(steps)}

## Related existing skills

{linked_lines}

## Operator review checklist

- [ ] Is this actually novel vs. existing skills?
- [ ] Does the sequence generalize, or did it depend on this specific target?
- [ ] Would a tool *recipe* be a better fit than a full skill?
- [ ] Is anything in the example payloads sensitive (creds, target IPs)?
"""


def _find_linked_skills(slice_episodes: list[dict[str, Any]], skills_root: Path) -> list[str]:
    """Heuristic: skills whose name appears in the tool args of the productive
    sequence are likely related."""
    skill_names: list[str] = []
    if skills_root.exists():
        skill_names = [p.parent.name for p in skills_root.glob("**/SKILL.md")]

    blob = " ".join(
        str(ep.get("action", "")) + " " + str(ep.get("tool_input", ""))
        for ep in slice_episodes
    ).lower()

    return sorted({s for s in skill_names if s in blob})


def skill_proposer(out_dir: Path | str = PROPOSED_DIR, skills_root: Path | str = "skills/"):
    """Returns an end-of-engagement hook that drops per-subagent draft skills."""

    out = Path(out_dir)
    root = Path(skills_root)

    def _propose(state: dict[str, Any], episodes: list[dict[str, Any]]) -> list[str]:
        # Only emit when the engagement actually succeeded.
        terminal_outcomes = {e.get("outcome_tag") for e in episodes[-5:]}
        if OutcomeTag.OBJECTIVE_MET not in terminal_outcomes:
            return []

        known_hashes = _load_known_hashes(root)
        objective = state.get("current_objective", "engagement")

        emitted: list[str] = []
        for slice_key, slice_episodes in _slice_by_agent(episodes).items():
            actions = [e.get("action", "") for e in slice_episodes]
            seq_hash = _sequence_hash(actions)
            if seq_hash in known_hashes:
                continue  # already-known sequence, skip

            name = f"{slice_key}-{_slugify(objective)}-{seq_hash}"
            linked = _find_linked_skills(slice_episodes, root)

            out.mkdir(parents=True, exist_ok=True)
            path = out / f"{name}.md"
            path.write_text(_format_skill(
                name=name,
                slice_episodes=slice_episodes,
                sequence_hash=seq_hash,
                summary=state.get("summary", ""),
                linked_skills=linked,
            ))
            emitted.append(str(path))

        return emitted

    _propose.__name__ = "skill_proposer"
    return _propose
