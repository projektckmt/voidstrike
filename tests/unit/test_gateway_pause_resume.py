"""Tests for the pause/resume lifecycle on the gateway.

The pause/resume contract:
  - /pause cancels the asyncio task AND writes a `.paused` marker.
  - /resume reads the saved spec, removes the marker, spawns a new task.
  - /cancel terminates a paused engagement (no live task to cancel — just
    clear the marker + emit `cancelled`).
  - `_engagement_status` reports `paused` whenever the marker is present.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest


@pytest.fixture
def fresh_gateway(monkeypatch, tmp_path):
    """Reload gateway main with a clean engagement dir + empty task table."""
    monkeypatch.setenv("ENGAGEMENT_DIR", str(tmp_path))
    # Force the module to re-resolve ENGAGEMENT_DIR.
    import importlib
    from src.gateway import main as gateway_main
    importlib.reload(gateway_main)
    # Clear the in-memory task table in case other tests left state.
    gateway_main._engagement_tasks.clear()
    return gateway_main


class _DoneTask:
    """Stand-in for an asyncio.Task that already finished — `task.done()` true."""
    def done(self) -> bool: return True
    def cancelled(self) -> bool: return False
    def cancel(self) -> None: pass


class _LiveTask:
    """Stand-in for an asyncio.Task that's still running."""
    def __init__(self) -> None:
        self._cancelled = False
    def done(self) -> bool: return self._cancelled
    def cancelled(self) -> bool: return self._cancelled
    def cancel(self) -> None: self._cancelled = True


async def _noop_emit(*args, **kwargs) -> None:
    return None


# ---------------------------------------------------------------------------
# Marker / status helpers
# ---------------------------------------------------------------------------


def test_paused_marker_round_trip(fresh_gateway, tmp_path) -> None:
    gw = fresh_gateway
    eng = "eng-1"
    (tmp_path / eng).mkdir()
    marker = gw._paused_marker_path(eng)
    assert not marker.exists()
    marker.touch()
    assert gw._is_paused(eng)
    marker.unlink()
    assert not gw._is_paused(eng)


def test_status_reports_paused_when_marker_present(fresh_gateway, tmp_path) -> None:
    gw = fresh_gateway
    eng = "eng-2"
    (tmp_path / eng).mkdir()
    gw._paused_marker_path(eng).touch()
    # No live task, but marker is on disk → paused.
    assert gw._engagement_status(eng) == "paused"


def test_status_reports_running_even_with_stale_marker(fresh_gateway, tmp_path) -> None:
    # Defensive: if a marker is leftover from an earlier pause but a fresh
    # task is running, the live task wins.
    gw = fresh_gateway
    eng = "eng-3"
    (tmp_path / eng).mkdir()
    gw._paused_marker_path(eng).touch()
    gw._engagement_tasks[eng] = _LiveTask()
    assert gw._engagement_status(eng) == "running"


# ---------------------------------------------------------------------------
# /pause
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pause_writes_marker_and_cancels_task(
    fresh_gateway, tmp_path, monkeypatch,
) -> None:
    gw = fresh_gateway
    monkeypatch.setattr(gw, "_emit", _noop_emit)

    eng = "eng-pause"
    (tmp_path / eng).mkdir()
    task = _LiveTask()
    gw._engagement_tasks[eng] = task

    result = await gw.pause_engagement(eng)

    assert result["status"] == "pausing"
    assert task.cancelled()
    assert gw._paused_marker_path(eng).exists()


@pytest.mark.asyncio
async def test_pause_noop_on_unknown_engagement(fresh_gateway) -> None:
    result = await fresh_gateway.pause_engagement("does-not-exist")
    assert result["status"] == "not_running"


@pytest.mark.asyncio
async def test_pause_noop_on_finished_engagement(fresh_gateway, tmp_path) -> None:
    gw = fresh_gateway
    eng = "eng-finished"
    (tmp_path / eng).mkdir()
    gw._engagement_tasks[eng] = _DoneTask()
    result = await gw.pause_engagement(eng)
    assert result["status"] == "already_finished"
    assert not gw._paused_marker_path(eng).exists()


# ---------------------------------------------------------------------------
# /resume
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resume_requires_paused_marker(fresh_gateway, tmp_path) -> None:
    gw = fresh_gateway
    eng = "eng-cant-resume"
    eng_dir = tmp_path / eng
    eng_dir.mkdir()
    # spec.yaml present, but no `.paused` marker — gateway refuses.
    (eng_dir / "spec.yaml").write_text("name: x\n")
    result = await gw.resume_engagement(eng)
    assert result["status"] == "not_paused"


@pytest.mark.asyncio
async def test_resume_404_when_no_spec(fresh_gateway, tmp_path) -> None:
    gw = fresh_gateway
    eng = "eng-no-spec"
    (tmp_path / eng).mkdir()
    gw._paused_marker_path(eng).touch()
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        await gw.resume_engagement(eng)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_resume_clears_marker_and_spawns_task(
    fresh_gateway, tmp_path, monkeypatch,
) -> None:
    gw = fresh_gateway
    monkeypatch.setattr(gw, "_emit", _noop_emit)

    eng = "eng-resume"
    eng_dir = tmp_path / eng
    eng_dir.mkdir()
    (eng_dir / "spec.yaml").write_text("name: x\n")
    (eng_dir / "profile").write_text("max")
    gw._paused_marker_path(eng).touch()

    started: list[tuple[str, str, str, bool]] = []

    async def fake_run(spec_path, engagement_id, profile, *, resume=False):
        started.append((spec_path, engagement_id, profile, resume))

    monkeypatch.setattr(gw, "_run_engagement", fake_run)

    result = await gw.resume_engagement(eng)
    # Let the spawned task get a chance to run.
    await asyncio.sleep(0)

    assert result["status"] == "resuming"
    assert not gw._paused_marker_path(eng).exists()
    assert started
    spec_path, eng_id, profile, was_resume = started[0]
    assert eng_id == eng
    assert profile == "max"
    assert was_resume is True


@pytest.mark.asyncio
async def test_resume_refuses_if_already_running(fresh_gateway, tmp_path) -> None:
    gw = fresh_gateway
    eng = "eng-already-running"
    (tmp_path / eng).mkdir()
    (tmp_path / eng / "spec.yaml").write_text("name: x\n")
    gw._engagement_tasks[eng] = _LiveTask()
    result = await gw.resume_engagement(eng)
    assert result["status"] == "already_running"


# ---------------------------------------------------------------------------
# /cancel of a paused engagement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancel_clears_paused_marker(
    fresh_gateway, tmp_path, monkeypatch,
) -> None:
    gw = fresh_gateway
    monkeypatch.setattr(gw, "_emit", _noop_emit)

    eng = "eng-paused-cancel"
    (tmp_path / eng).mkdir()
    gw._paused_marker_path(eng).touch()
    # Pretend the live task is gone (the typical post-pause state).

    result = await gw.cancel_engagement(eng)

    assert result["status"] == "cancelled"
    assert not gw._paused_marker_path(eng).exists()


# ---------------------------------------------------------------------------
# Safety-net report.md writer
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_safety_net_skipped_when_report_exists(
    fresh_gateway, tmp_path, monkeypatch,
) -> None:
    gw = fresh_gateway
    monkeypatch.setattr(gw, "_emit", _noop_emit)

    eng = "eng-has-report"
    (tmp_path / eng).mkdir()
    real_report = tmp_path / eng / "report.md"
    real_report.write_text("# real analyst report\n")

    await gw._ensure_report_exists(eng, str(tmp_path / eng / "spec.yaml"))

    # File untouched.
    assert real_report.read_text() == "# real analyst report\n"


@pytest.mark.asyncio
async def test_safety_net_writes_stub_when_missing(
    fresh_gateway, tmp_path, monkeypatch,
) -> None:
    gw = fresh_gateway
    emitted: list[dict] = []

    async def capture_emit(eng_id, payload):
        emitted.append(payload)

    monkeypatch.setattr(gw, "_emit", capture_emit)

    eng = "eng-needs-stub"
    eng_dir = tmp_path / eng
    eng_dir.mkdir()
    (eng_dir / "flags.txt").write_text("2026-01-01 host=x path=y deadbeef\n")
    # Stub Postgres so we don't need a live connection.
    monkeypatch.setattr(gw, "_get_pg_pool", lambda: _RaisingPool())

    # Spec path doesn't exist; the function should still write a stub using
    # fallback values.
    await gw._ensure_report_exists(eng, str(eng_dir / "spec.yaml"))

    report = eng_dir / "report.md"
    assert report.exists()
    body = report.read_text()
    assert "deadbeef" in body
    assert any(p.get("event") == "report_fallback" for p in emitted)


class _RaisingPool:
    """Stand-in pool that fails on `.open()` so the safety net falls back
    to empty findings without ever attempting a real connection."""
    async def open(self):
        raise RuntimeError("no postgres in unit tests")
    def connection(self):
        raise RuntimeError("no postgres in unit tests")


# ---------------------------------------------------------------------------
# Shell session reset (called at engagement start)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reset_shell_sessions_logs_and_swallows_unreachable(
    fresh_gateway, monkeypatch, caplog,
) -> None:
    """If the shell MCP container is down, the gateway must not block the
    engagement — it should log and continue."""
    gw = fresh_gateway
    monkeypatch.setenv("MCP_SHELL_URL", "http://nowhere-12345.invalid:9/mcp")

    import logging
    with caplog.at_level(logging.WARNING, logger="voidstrike.gateway"):
        await gw._reset_shell_sessions("eng-x")

    assert any("shell reset failed" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_reset_shell_sessions_uses_admin_path(
    fresh_gateway, monkeypatch,
) -> None:
    """The admin endpoint sits beside /mcp, not under it. Verify URL shape."""
    import httpx
    captured: list[str] = []

    async def fake_post(self, url, **kw):
        captured.append(url)
        return httpx.Response(200, json={"ok": True, "killed": [], "count": 0})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    monkeypatch.setenv("MCP_SHELL_URL", "http://shell-mcp:8080/mcp")

    await fresh_gateway._reset_shell_sessions("eng-x")

    assert captured == ["http://shell-mcp:8080/admin/reset"]


@pytest.mark.asyncio
async def test_reset_shell_sessions_handles_trailing_slash(
    fresh_gateway, monkeypatch,
) -> None:
    import httpx
    captured: list[str] = []

    async def fake_post(self, url, **kw):
        captured.append(url)
        return httpx.Response(200, json={"ok": True, "killed": [], "count": 0})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    monkeypatch.setenv("MCP_SHELL_URL", "http://shell-mcp:8080/mcp/")
    await fresh_gateway._reset_shell_sessions("eng-x")
    assert captured == ["http://shell-mcp:8080/admin/reset"]
