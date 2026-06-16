"""Tests for engagement cancellation.

Gateway side: `/cancel` should mark a running task as cancelled, the
`_run_engagement` body should turn that into a clean `cancelled` event
instead of an error.

CLI side: Ctrl-C from `voidstrike engage` cancels the engagement on the
gateway; Ctrl-C from `voidstrike attach` only detaches the stream.
"""

from __future__ import annotations

import asyncio

import pytest

# ---------------------------------------------------------------------------
# Gateway: cancel endpoint behavior
# ---------------------------------------------------------------------------


def test_cancel_endpoint_when_no_task_running(monkeypatch) -> None:
    """If the engagement ID isn't known, the endpoint should return cleanly
    with `status: not_running`. We don't want the CLI's Ctrl-C path to
    fail on a 404 just because the engagement already wrapped up."""
    from src.gateway import main as gw

    async def _go():
        return await gw.cancel_engagement("nope-not-a-real-id")

    result = asyncio.run(_go())
    assert result["status"] == "not_running"


def test_cancel_endpoint_when_task_already_done(monkeypatch) -> None:
    """A task that's already completed should report `already_finished`,
    not be cancelled (cancel on a done task is a no-op in asyncio, but the
    status messaging matters for the operator)."""
    from src.gateway import main as gw

    async def _quick():
        return "done"

    async def _go():
        task = asyncio.create_task(_quick())
        await task
        gw._engagement_tasks["finished-eng"] = task
        result = await gw.cancel_engagement("finished-eng")
        gw._engagement_tasks.pop("finished-eng", None)
        return result

    result = asyncio.run(_go())
    assert result["status"] == "already_finished"


def test_cancel_endpoint_cancels_a_running_task(monkeypatch) -> None:
    """The happy path — running task gets cancelled, status is `cancelling`."""
    from src.gateway import main as gw

    # Stub _emit so the test doesn't try to talk to Redis.
    async def _noop_emit(*a, **kw):
        return None
    monkeypatch.setattr(gw, "_emit", _noop_emit)

    async def _long_running():
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            return

    async def _go():
        task = asyncio.create_task(_long_running())
        gw._engagement_tasks["live-eng"] = task
        # Give the task one tick to start.
        await asyncio.sleep(0)
        result = await gw.cancel_engagement("live-eng")
        # Let the cancellation propagate.
        try:
            await asyncio.wait_for(task, timeout=1.0)
        except (TimeoutError, asyncio.CancelledError):
            pass
        gw._engagement_tasks.pop("live-eng", None)
        return result, task

    result, task = asyncio.run(_go())
    assert result["status"] == "cancelling"
    assert task.cancelled() or task.done()


# ---------------------------------------------------------------------------
# Gateway: _run_engagement catches CancelledError
# ---------------------------------------------------------------------------


def test_run_engagement_emits_cancelled_event_on_cancel(monkeypatch, tmp_path) -> None:
    """When the orchestrator task is cancelled mid-stream, the gateway must
    emit a `cancelled` event (not an `error`) so the CLI knows the engagement
    stopped cleanly."""
    from src.gateway import main as gw

    emitted: list[dict] = []

    async def _capture_emit(engagement_id: str, payload: dict) -> None:
        emitted.append(payload)

    monkeypatch.setattr(gw, "_emit", _capture_emit)

    # Stub build_agent to yield an async generator that sleeps long enough
    # for the cancel to land.
    import contextlib
    import sys
    import types

    class _FakeAgent:
        async def astream(self, *a, **kw):
            await asyncio.sleep(60)  # blocks until cancelled
            yield {}

    @contextlib.asynccontextmanager
    async def _fake_build_agent(spec_path, profile=None):
        yield _FakeAgent()

    fake_agent_main = types.ModuleType("src.agent.main")
    fake_agent_main.build_agent = _fake_build_agent
    monkeypatch.setitem(sys.modules, "src.agent.main", fake_agent_main)

    # Minimal spec yaml so EngagementSpec.from_yaml works.
    spec_path = tmp_path / "spec.yaml"
    spec_path.write_text(
        "name: t\nmode: ctf\ntargets: [10.0.0.1]\nobjective: root\nprofile: test\n"
    )

    async def _go():
        task = asyncio.create_task(
            gw._run_engagement(str(spec_path), "eng-cancel-test", "test")
        )
        await asyncio.sleep(0.05)  # let it advance past the start emit
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            # _run_engagement catches and suppresses; this shouldn't fire.
            pytest.fail("CancelledError should have been caught inside "
                         "_run_engagement and turned into a `cancelled` event")

    asyncio.run(_go())
    events = [e["event"] for e in emitted]
    assert "cancelled" in events, f"events were: {events}"
    # The `end` event should always fire in the finally block.
    assert events[-1] == "end"
    # And no `error` event — cancellation is not an error.
    assert "error" not in events


# ---------------------------------------------------------------------------
# CLI: cancel command + Ctrl-C wiring
# ---------------------------------------------------------------------------


def test_cli_cancel_request_returns_status_string(monkeypatch) -> None:
    """`_request_cancel` is the helper Ctrl-C calls — must return the
    gateway's status string and never raise."""
    from src.cli import main as cli

    class _FakeResp:
        status_code = 200
        text = ""
        def json(self):
            return {"engagement_id": "x", "status": "cancelling"}

    monkeypatch.setattr(cli.httpx, "post", lambda *a, **kw: _FakeResp())
    status = cli._request_cancel("x")
    assert status == "cancelling"


def test_cli_cancel_request_handles_gateway_down(monkeypatch) -> None:
    """If the gateway is unreachable, `_request_cancel` must return a
    string explaining that — not propagate the exception."""
    import httpx as _httpx

    from src.cli import main as cli

    def _raise(*a, **kw):
        raise _httpx.ConnectError("connection refused")

    monkeypatch.setattr(cli.httpx, "post", _raise)
    status = cli._request_cancel("x")
    assert "unreachable" in status


def test_cli_cancel_request_handles_non_200(monkeypatch) -> None:
    from src.cli import main as cli

    class _FakeResp:
        status_code = 500
        text = "boom"
        def json(self):
            return {}

    monkeypatch.setattr(cli.httpx, "post", lambda *a, **kw: _FakeResp())
    status = cli._request_cancel("x")
    assert "500" in status


def test_cli_renderer_handles_cancelling_and_cancelled_events() -> None:
    """The CLI must render the new lifecycle events without crashing —
    these were added with this feature and missing them would mean the
    operator sees nothing useful when they Ctrl-C."""
    from src.cli.main import _render_event

    # Both calls must complete without raising.
    _render_event({"event": "cancelling", "reason": "operator"})
    _render_event({"event": "cancelled", "reason": "operator"})
