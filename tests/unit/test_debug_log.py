"""Tests for the --debug-log JSONL transcript sink.

The debug log is the machine-readable record an LLM analyzes after a run: one
JSON event per line, with a `_debug_meta` header per attach. These pin the file
shape and that logging never raises on bad input.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.cli.main import _open_debug_log, _write_debug


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_open_writes_meta_header(tmp_path: Path) -> None:
    log = tmp_path / "run.jsonl"
    fh = _open_debug_log(log, "eng-123")
    assert fh is not None
    fh.close()

    rows = _lines(log)
    assert rows[0]["event"] == "_debug_meta"
    assert rows[0]["engagement_id"] == "eng-123"
    assert "attached_at" in rows[0]


def test_write_debug_appends_one_json_line_per_event(tmp_path: Path) -> None:
    log = tmp_path / "run.jsonl"
    fh = _open_debug_log(log, "eng-1")
    _write_debug(fh, {"event": "step", "data": {"tool": "surface__ffuf"}})
    _write_debug(fh, {"event": "end"})
    fh.close()

    rows = _lines(log)
    assert [r["event"] for r in rows] == ["_debug_meta", "step", "end"]
    assert rows[1]["data"]["tool"] == "surface__ffuf"


def test_open_creates_parent_dirs(tmp_path: Path) -> None:
    log = tmp_path / "nested" / "deeper" / "run.jsonl"
    fh = _open_debug_log(log, "eng-1")
    assert fh is not None
    fh.close()
    assert log.exists()


def test_append_mode_preserves_prior_run(tmp_path: Path) -> None:
    log = tmp_path / "run.jsonl"
    fh = _open_debug_log(log, "eng-1")
    _write_debug(fh, {"event": "step", "n": 1})
    fh.close()
    # A re-attach / resume appends a new header + more events.
    fh2 = _open_debug_log(log, "eng-1")
    _write_debug(fh2, {"event": "step", "n": 2})
    fh2.close()

    rows = _lines(log)
    assert [r["event"] for r in rows] == ["_debug_meta", "step", "_debug_meta", "step"]


def test_write_debug_tolerates_none_and_unserializable(tmp_path: Path) -> None:
    # None sink (logging disabled) is a no-op; non-JSON values fall back to str.
    _write_debug(None, {"event": "step"})  # must not raise

    log = tmp_path / "run.jsonl"
    fh = _open_debug_log(log, "eng-1")
    _write_debug(fh, {"event": "step", "blob": object()})  # default=str handles it
    fh.close()
    rows = _lines(log)
    assert rows[-1]["event"] == "step"
