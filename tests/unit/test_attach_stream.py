"""Tests for the CLI SSE attach loop's resilience to dropped streams.

Regression: a mid-engagement stream drop (gateway restart / proxy timeout)
surfaced as an unhandled `httpx.RemoteProtocolError` and crashed `voidstrike
engage` with a full traceback. The engagement keeps running on the gateway, so
the CLI must reconnect (suppressing the replayed backlog) or exit cleanly.
"""

from __future__ import annotations

import httpx

import src.cli.main as m


class _FakeResp:
    def __init__(self, lines):
        self._lines = lines

    def iter_lines(self):
        for ln in self._lines:
            if isinstance(ln, Exception):
                raise ln
            yield ln


class _FakeStream:
    """Stand-in for `httpx.stream(...)` used as a context manager."""

    def __init__(self, lines):
        self._lines = lines

    def __enter__(self):
        return _FakeResp(self._lines)

    def __exit__(self, *a):
        return False


def _patch_stream(monkeypatch, scripts):
    """Each connect consumes the next script; the last repeats."""
    calls = []

    def fake_stream(_method, url, **_kw):
        idx = min(len(calls), len(scripts) - 1)
        calls.append(url)
        return _FakeStream(scripts[idx])

    monkeypatch.setattr(m.httpx, "stream", fake_stream)
    monkeypatch.setattr(m.time, "sleep", lambda *_: None)  # no real backoff
    return calls


def test_attach_reconnects_after_drop_and_suppresses_backlog(monkeypatch) -> None:
    rendered = []
    monkeypatch.setattr(m, "_render_event", lambda e: rendered.append(e.get("event")))
    calls = _patch_stream(monkeypatch, [
        # 1st connect: one live event, then the stream drops mid-read.
        ['data: {"event": "step", "data": {}}', httpx.RemoteProtocolError("boom")],
        # reconnect: replayed backlog (must be suppressed), sentinel, then end.
        [
            'data: {"event": "step", "data": {"replayed": 1}}',
            'data: {"event": "subscribed"}',
            'data: {"event": "end"}',
        ],
    ])

    m._attach_stream("eng-1", on_interrupt="detach")  # must NOT raise

    assert len(calls) == 2, "should have reconnected exactly once"
    # The replayed backlog step is suppressed; we render the first live step,
    # then (after the sentinel) the terminal `end`.
    assert rendered == ["step", "end"], rendered


def test_attach_gives_up_cleanly_after_max_reconnects(monkeypatch) -> None:
    monkeypatch.setattr(m, "_render_event", lambda e: None)
    # Every connect immediately drops — never a terminal event.
    calls = _patch_stream(monkeypatch, [[httpx.RemoteProtocolError("down")]])

    m._attach_stream("eng-2", on_interrupt="detach")  # must NOT raise

    # 1 initial + _MAX_RECONNECTS attempts, then a clean give-up (no traceback).
    assert len(calls) == 11


def test_attach_keyboardinterrupt_still_detaches(monkeypatch) -> None:
    def boom(_e):
        raise KeyboardInterrupt
    monkeypatch.setattr(m, "_render_event", boom)
    _patch_stream(monkeypatch, [['data: {"event": "step", "data": {}}']])
    # Ctrl-C during render should be caught (interrupted path), not propagate.
    m._attach_stream("eng-3", on_interrupt="detach")
