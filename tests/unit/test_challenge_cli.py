"""Tests for the `voidstrike challenge` CLI helpers (outcome parsing, token load).

The command itself needs HTB + a gateway, but the outcome-from-event-stream
parsing and token lookup are pure and worth pinning."""

from __future__ import annotations

import json

from src.cli.main import _htb_token, _outcome_from_events, _walk_record_flags


def _step_with_record_flag(flag: str) -> dict:
    return {
        "event": "step",
        "namespace": [],
        "data": {"model": {"messages": [
            {"tool_calls": [{"name": "record_flag", "args": {"flag": flag, "path": "/root/root.txt"}}]}
        ]}},
    }


def _write(path, events):
    path.write_text("\n".join(json.dumps(e) for e in events))


def test_walk_finds_nested_record_flags():
    ev = _step_with_record_flag("deadbeef")
    assert _walk_record_flags(ev) == ["deadbeef"]
    assert _walk_record_flags({"a": [{"b": ev}]}) == ["deadbeef"]
    assert _walk_record_flags({"name": "task", "args": {}}) == []


def test_outcome_collects_flags_and_detects_root(tmp_path):
    log = tmp_path / "run.jsonl"
    _write(log, [
        {"event": "_debug_meta", "engagement_id": "x"},
        _step_with_record_flag("userflag"),
        {"event": "step", "data": {"tools": {"messages": [{"content": "objective_met: root flag captured"}]}}},
        _step_with_record_flag("rootflag"),
        {"event": "end"},
    ])
    out = _outcome_from_events(log, expected_flags=2)
    assert out.flags == ["userflag", "rootflag"]
    assert out.success is True


def test_outcome_success_via_expected_flags_without_objective_text(tmp_path):
    log = tmp_path / "run.jsonl"
    _write(log, [_step_with_record_flag("a"), _step_with_record_flag("b")])
    assert _outcome_from_events(log, expected_flags=2).success is True
    assert _outcome_from_events(log, expected_flags=3).success is False  # only 2 captured


def test_outcome_dedupes_flags(tmp_path):
    log = tmp_path / "run.jsonl"
    _write(log, [_step_with_record_flag("dup"), _step_with_record_flag("dup")])
    assert _outcome_from_events(log, expected_flags=None).flags == ["dup"]


def test_outcome_ignores_events_before_last_debug_meta(tmp_path):
    """A reused/append debug-log: only the latest run's events count."""
    log = tmp_path / "run.jsonl"
    _write(log, [
        {"event": "_debug_meta"},
        _step_with_record_flag("stale"),       # previous run
        {"event": "_debug_meta"},              # new attach delimiter
        _step_with_record_flag("fresh"),
    ])
    assert _outcome_from_events(log, expected_flags=None).flags == ["fresh"]


def test_outcome_missing_file_is_empty(tmp_path):
    out = _outcome_from_events(tmp_path / "nope.jsonl", expected_flags=2)
    assert out.flags == [] and out.success is False


def test_htb_token_prefers_env(monkeypatch):
    monkeypatch.setenv("HTB_TOKEN", "envtok")
    assert _htb_token() == "envtok"


def test_htb_token_falls_back_to_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("HTB_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text('FOO=bar\nHTB_TOKEN="dotenvtok"\n')
    assert _htb_token() == "dotenvtok"


def test_htb_token_absent(monkeypatch, tmp_path):
    monkeypatch.delenv("HTB_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)
    assert _htb_token() == ""
