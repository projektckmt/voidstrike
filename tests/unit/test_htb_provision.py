"""Tests for the gateway's HTB provisioning helpers.

HTB spawn/submit/teardown moved server-side (the `voidstrike challenge` command
was folded into spec-driven `engage`). The flag-extraction and success-derivation
logic are pure and worth pinning here."""

from __future__ import annotations

from src.gateway.main import _htb_solved, _root_signal_in_event, _walk_record_flags


def _record_flag_event(flag: str) -> dict:
    """A `record_flag` tool call as it appears in a _safe(update) payload."""
    return {"model": {"messages": [
        {"tool_calls": [{"name": "record_flag", "args": {"flag": flag, "path": "/root/root.txt"}}]}
    ]}}


def test_walk_finds_nested_record_flags():
    ev = _record_flag_event("deadbeef")
    assert _walk_record_flags(ev) == ["deadbeef"]
    assert _walk_record_flags({"a": [{"b": ev}]}) == ["deadbeef"]
    assert _walk_record_flags({"name": "task", "args": {}}) == []


def test_walk_accepts_input_shaped_args():
    # Some tool-call dumps key args under `input` rather than `args`.
    assert _walk_record_flags({"name": "record_flag", "input": {"flag": "f2"}}) == ["f2"]


def test_walk_ignores_blank_flags():
    assert _walk_record_flags({"name": "record_flag", "args": {"flag": "  "}}) == []


def test_root_signal_detection():
    assert _root_signal_in_event({"tools": {"messages": [{"content": "objective_met: done"}]}})
    assert _root_signal_in_event({"x": "ROOT FLAG CAPTURED"})  # case-insensitive
    assert not _root_signal_in_event({"tools": {"messages": [{"content": "no luck"}]}})


def test_solved_via_root_signal_overrides_count():
    # Rooted wins even with zero flags / no expected count.
    assert _htb_solved([], rooted=True, expected_flags=None) is True
    assert _htb_solved([], rooted=True, expected_flags=2) is True


def test_solved_via_expected_flag_threshold():
    assert _htb_solved(["a", "b"], rooted=False, expected_flags=2) is True
    assert _htb_solved(["a"], rooted=False, expected_flags=2) is False  # short


def test_not_solved_without_count_or_root():
    # No root signal and expected_flags unset/zero → never solved by flag count.
    assert _htb_solved(["a", "b"], rooted=False, expected_flags=None) is False
    assert _htb_solved(["a", "b"], rooted=False, expected_flags=0) is False
