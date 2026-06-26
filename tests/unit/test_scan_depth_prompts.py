"""Prompt regressions for adaptive scan depth."""

from __future__ import annotations


def test_ctf_orchestrator_does_not_delegate_full_scan_by_default() -> None:
    from src.agent.prompts.ctf import CTF_ORCHESTRATOR_PROMPT

    prompt = CTF_ORCHESTRATOR_PROMPT.lower()
    assert "do **not** ask for a full tcp/all-ports scan" in prompt
    assert "quick nmap first" in prompt
    assert "escalation only" in prompt


def test_other_orchestrators_call_full_scans_escalations() -> None:
    from src.agent.prompts.engagement import ENGAGEMENT_ORCHESTRATOR_PROMPT
    from src.agent.prompts.lab import LAB_ORCHESTRATOR_PROMPT

    for raw in (LAB_ORCHESTRATOR_PROMPT.lower(), ENGAGEMENT_ORCHESTRATOR_PROMPT.lower()):
        prompt = " ".join(raw.split())
        assert "default full tcp/all-ports scans" in prompt or "request full tcp/all-ports scans" in prompt
        assert "quick" in prompt
        assert "low-signal" in prompt


def test_surface_prompt_disallows_initial_full_scan_todo() -> None:
    from src.agent.subagents.surface import SURFACE_PROMPT

    prompt = " ".join(SURFACE_PROMPT.lower().split())
    assert "never put a full scan in your initial todo as a default step" in prompt
    assert "run `surface__nmap_full` only if" in prompt
    assert "assignment explicitly requires exhaustive port coverage" not in prompt
