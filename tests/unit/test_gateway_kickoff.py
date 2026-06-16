"""Tests for the engagement kickoff message.

The operator's `notes` are delivered to the agent as an OPERATOR BRIEFING block
in the opening message — the channel for pre-engagement context like provided
credentials. Before this, `notes` was a dead field that never reached the agent.
"""

from __future__ import annotations

from src.gateway.main import _kickoff_text
from src.schemas.engagement import EngagementSpec


def _spec(notes: str = "") -> EngagementSpec:
    return EngagementSpec(
        name="t", mode="ctf", targets=["10.129.25.222"],
        objective="root flag", notes=notes,
    )


def test_always_includes_engagement_context():
    text = _kickoff_text(_spec(), "eng-1")
    assert "Begin engagement eng-1." in text
    assert "Target(s): 10.129.25.222" in text
    assert "Objective: root flag" in text
    assert "Mode: ctf" in text
    assert "Start with Surface." in text


def test_no_briefing_block_when_notes_empty():
    assert "OPERATOR BRIEFING" not in _kickoff_text(_spec(), "eng-1")
    assert "OPERATOR BRIEFING" not in _kickoff_text(_spec("   "), "eng-1")


def test_briefing_block_carries_provided_credentials():
    notes = "You start with credentials for alex.turner / Checkpoint2024!"
    text = _kickoff_text(_spec(notes), "eng-1")
    assert "OPERATOR BRIEFING" in text
    assert "alex.turner / Checkpoint2024!" in text
    # the agent is told to act on it and relay to subagents
    assert "relay" in text.lower()
    # context still present alongside the briefing
    assert "Start with Surface." in text


def test_briefing_is_verbatim_and_stripped():
    text = _kickoff_text(_spec("\n  internal host: dc01.corp.local  \n"), "eng-1")
    assert "internal host: dc01.corp.local" in text
