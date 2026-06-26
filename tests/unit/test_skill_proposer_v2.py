"""Improved skill proposer tests — per-agent slices + novelty detection."""

from __future__ import annotations

from pathlib import Path

from src.agent.middleware.skill_proposer import skill_proposer
from src.schemas.episodes import OutcomeTag


def test_no_emit_without_objective_met(tmp_path: Path) -> None:
    proposer = skill_proposer(out_dir=tmp_path / "proposed", skills_root=tmp_path / "skills")
    episodes = [
        {"agent_name": "surface", "action": "nmap_quick", "outcome_tag": OutcomeTag.NEW_FINDING, "tool_input": {}},
    ]
    assert proposer({"thread_id": "x"}, episodes) == []


def test_emit_per_subagent_slice(tmp_path: Path) -> None:
    proposer = skill_proposer(out_dir=tmp_path / "proposed", skills_root=tmp_path / "skills")
    episodes = [
        {"agent_name": "surface", "action": "surface__nmap_quick",
         "outcome_tag": OutcomeTag.NEW_FINDING, "tool_input": {"target": "10.0.0.1"}},
        {"agent_name": "exploit", "action": "exploit__deliver_via_web",
         "outcome_tag": OutcomeTag.SHELL_LANDED, "tool_input": {}},
        {"agent_name": "postex", "action": "postex__suid_enum",
         "outcome_tag": OutcomeTag.PRIV_ESCALATED, "tool_input": {}},
        {"agent_name": "postex", "action": "postex__loot_credentials",
         "outcome_tag": OutcomeTag.OBJECTIVE_MET, "tool_input": {}},
    ]
    paths = proposer({"thread_id": "abcd1234", "current_objective": "root"}, episodes)
    # Three slices: surface, exploit, postex
    assert len(paths) == 3
    names = {Path(p).name for p in paths}
    assert any(n.startswith("surface-") for n in names)
    assert any(n.startswith("exploit-") for n in names)
    assert any(n.startswith("postex-") for n in names)


def test_emit_when_objective_met_precedes_analyst_tail(tmp_path: Path) -> None:
    # Regression: the proposer runs at end-of-engagement, after the analyst's
    # reporting episodes. OBJECTIVE_MET (tagged when root was captured) must still
    # be detected even though it's no longer in the last few episodes.
    proposer = skill_proposer(out_dir=tmp_path / "proposed", skills_root=tmp_path / "skills")
    episodes = [
        {"agent_name": "postex", "action": "postex__suid_enum",
         "outcome_tag": OutcomeTag.OBJECTIVE_MET, "tool_input": {}},
        # 5+ analyst episodes after success — would push OBJECTIVE_MET out of [-5:].
        *[
            {"agent_name": "analyst", "action": "render_report",
             "outcome_tag": OutcomeTag.NEW_FINDING, "tool_input": {}}
            for _ in range(6)
        ],
    ]
    paths = proposer({"thread_id": "z", "current_objective": "root"}, episodes)
    assert any(Path(p).name.startswith("postex-") for p in paths)


def test_known_hash_dedupes(tmp_path: Path) -> None:
    """An existing skill marked with `proposed_from: <hash>` causes the
    matching slice to be skipped — we don't re-propose what's already in the
    tree."""
    import hashlib
    skills_root = tmp_path / "skills"
    skills_root.mkdir(parents=True)

    actions = ["surface__nmap_quick", "surface__httpx_fingerprint"]
    seq_hash = hashlib.sha256("|".join(actions).encode()).hexdigest()[:12]
    existing = skills_root / "surface" / "thing" / "SKILL.md"
    existing.parent.mkdir(parents=True)
    existing.write_text(f"---\nname: thing\nproposed_from: {seq_hash}\n---\n")

    proposer = skill_proposer(out_dir=tmp_path / "proposed", skills_root=skills_root)
    episodes = [
        {"agent_name": "surface", "action": "surface__nmap_quick",
         "outcome_tag": OutcomeTag.NEW_FINDING, "tool_input": {}},
        {"agent_name": "surface", "action": "surface__httpx_fingerprint",
         "outcome_tag": OutcomeTag.NEW_FINDING, "tool_input": {}},
        # Need OBJECTIVE_MET in the tail so the proposer runs at all.
        {"agent_name": "exploit", "action": "exploit__deliver_via_web",
         "outcome_tag": OutcomeTag.OBJECTIVE_MET, "tool_input": {}},
    ]
    paths = proposer({"thread_id": "x", "current_objective": "root"}, episodes)
    # Exploit slice still emits, but no surface- slice should.
    assert all(not Path(p).name.startswith("surface-") for p in paths)
