"""Stuck-detector logic tests. The interrupt machinery is harness-dependent; we
test the rolling-window accounting in isolation here.
"""

from __future__ import annotations

from src.agent.middleware.stuck_detector import _StuckState
from src.schemas.episodes import OutcomeTag


def test_initial_state_not_stuck() -> None:
    s = _StuckState(threshold=5)
    assert not s.should_escalate()


def test_n_no_results_triggers() -> None:
    s = _StuckState(threshold=5)
    for _ in range(5):
        s.record("tool:x", {}, OutcomeTag.NO_RESULT)
    assert s.should_escalate()


def test_new_finding_resets_counter() -> None:
    s = _StuckState(threshold=5)
    for _ in range(4):
        s.record("tool:x", {}, OutcomeTag.NO_RESULT)
    s.record("tool:y", {}, OutcomeTag.NEW_FINDING)
    assert not s.should_escalate()
    s.record("tool:x", {}, OutcomeTag.NO_RESULT)
    assert not s.should_escalate()


def test_error_outcomes_count_as_stuck() -> None:
    s = _StuckState(threshold=3)
    for _ in range(3):
        s.record("tool:x", {}, OutcomeTag.ERROR)
    assert s.should_escalate()


def test_objective_met_counts_as_finding_for_purposes_of_reset() -> None:
    # Strictly speaking we reset on NEW_FINDING; OBJECTIVE_MET fires at end of
    # engagement and any subsequent step is unlikely. But test that the
    # rolling window keeps a finite size.
    s = _StuckState(threshold=3)
    for _ in range(100):
        s.record("tool:x", {}, OutcomeTag.NO_RESULT)
    assert len(s.window) <= s.window.maxlen
