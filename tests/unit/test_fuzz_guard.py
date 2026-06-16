"""Fuzz guard helpers."""

from __future__ import annotations

from src.agent.middleware.fuzz_guard import _ffuf_scope, _FuzzState


def test_ffuf_scope_groups_fuzz_variants_by_web_root() -> None:
    assert _ffuf_scope("http://10.0.0.1/FUZZ") == "http://10.0.0.1/"
    assert _ffuf_scope("http://10.0.0.1/FUZZ.php") == "http://10.0.0.1/"
    assert _ffuf_scope("http://10.0.0.1/app/FUZZ.php") == "http://10.0.0.1/app/"


def test_fuzz_state_blocks_after_empty_results() -> None:
    state = _FuzzState()
    for _ in range(3):
        state.record('{"ok": true, "results": []}')

    assert state.should_block(max_attempts=4, max_empty=3, max_missing=1)


def test_fuzz_state_blocks_after_missing_wordlist() -> None:
    state = _FuzzState()
    state.record('{"ok": false, "error": "wordlist not found"}')

    assert state.should_block(max_attempts=4, max_empty=3, max_missing=1)


def test_fuzz_state_blocks_after_attempt_budget_even_with_mixed_results() -> None:
    state = _FuzzState()
    for _ in range(4):
        state.record('{"ok": true, "results": [{"url": "http://t/a"}]}')

    assert state.should_block(max_attempts=4, max_empty=3, max_missing=1)
