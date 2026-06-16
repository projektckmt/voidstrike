"""Lab-state tracker tests."""

from __future__ import annotations

from pathlib import Path

from src.agent import lab_state
from src.agent.lab_state import HostStatus, LabState


def test_round_trip(tmp_path: Path) -> None:
    state = LabState(engagement_id="e1")
    state.upsert("10.0.0.1", status=HostStatus.OWNED, reason="foothold")
    state.upsert("10.0.0.2", status=HostStatus.PENDING)
    lab_state.save(state, tmp_path)

    again = lab_state.load(tmp_path, "e1")
    assert again.hosts["10.0.0.1"].status == HostStatus.OWNED
    assert again.hosts["10.0.0.2"].status == HostStatus.PENDING


def test_progress_counts(tmp_path: Path) -> None:
    state = LabState(engagement_id="e1")
    state.upsert("10.0.0.1", status=HostStatus.OWNED)
    state.upsert("10.0.0.2", status=HostStatus.PENDING)
    state.upsert("10.0.0.3", status=HostStatus.PENDING)
    state.upsert("10.0.0.4", status=HostStatus.DEAD)

    counts = state.progress()
    assert counts["owned"] == 1
    assert counts["pending"] == 2
    assert counts["dead"] == 1


def test_load_missing_returns_empty(tmp_path: Path) -> None:
    state = lab_state.load(tmp_path, "never-seen")
    assert state.hosts == {}
    assert state.engagement_id == "never-seen"


def test_from_json_coerces_string_statuses() -> None:
    raw = """{
      "engagement_id": "e1",
      "hosts": {
        "10.0.0.1": {"address": "10.0.0.1", "status": "owned"},
        "10.0.0.2": {"address": "10.0.0.2", "status": "pending"}
      }
    }"""

    state = LabState.from_json(raw)

    assert state.hosts["10.0.0.1"].status == HostStatus.OWNED
    assert state.progress() == {"owned": 1, "pending": 1}


def test_progress_tolerates_legacy_string_status() -> None:
    state = LabState(engagement_id="e1")
    record = state.upsert("10.0.0.1", status=HostStatus.OWNED)
    record.status = "owned"  # type: ignore[assignment]

    assert state.progress() == {"owned": 1}
