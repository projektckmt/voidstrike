"""Tests for the cancel-all flow.

Gateway: `/engagements/cancel_all` cancels every running task and returns a
summary. CLI: `voidstrike cancel --all` prompts for confirmation unless
`-y` is passed, then hits the endpoint and renders the result.
"""

from __future__ import annotations

import asyncio

import pytest

# ---------------------------------------------------------------------------
# Gateway: cancel_all_engagements
# ---------------------------------------------------------------------------


def test_cancel_all_with_no_running_returns_empty_list(monkeypatch) -> None:
    from src.gateway import main as gw

    async def _go():
        # Snapshot + restore to keep test isolation.
        snapshot = dict(gw._engagement_tasks)
        gw._engagement_tasks.clear()
        try:
            return await gw.cancel_all_engagements()
        finally:
            gw._engagement_tasks.update(snapshot)

    result = asyncio.run(_go())
    assert result == {"cancelled_count": 0, "total": 0, "engagements": []}


def test_cancel_all_cancels_every_running_task(monkeypatch) -> None:
    from src.gateway import main as gw

    async def _noop_emit(*a, **kw):
        return None

    monkeypatch.setattr(gw, "_emit", _noop_emit)

    async def _long():
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            return

    async def _go():
        snapshot = dict(gw._engagement_tasks)
        gw._engagement_tasks.clear()
        try:
            t1 = asyncio.create_task(_long())
            t2 = asyncio.create_task(_long())
            gw._engagement_tasks["eng-a"] = t1
            gw._engagement_tasks["eng-b"] = t2
            await asyncio.sleep(0)  # let them start
            result = await gw.cancel_all_engagements()
            for t in (t1, t2):
                try:
                    await asyncio.wait_for(t, timeout=1.0)
                except (TimeoutError, asyncio.CancelledError):
                    pass
            return result, t1, t2
        finally:
            gw._engagement_tasks.clear()
            gw._engagement_tasks.update(snapshot)

    result, t1, t2 = asyncio.run(_go())
    assert result["cancelled_count"] == 2
    assert result["total"] == 2
    statuses = sorted(e["status"] for e in result["engagements"])
    assert statuses == ["cancelling", "cancelling"]
    assert t1.cancelled() or t1.done()
    assert t2.cancelled() or t2.done()


def test_cancel_all_distinguishes_already_finished_tasks(monkeypatch) -> None:
    """A task already done before cancel_all runs gets `already_finished`,
    not `cancelling`."""
    from src.gateway import main as gw

    async def _noop_emit(*a, **kw):
        return None

    monkeypatch.setattr(gw, "_emit", _noop_emit)

    async def _instant():
        return "done"

    async def _long():
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            return

    async def _go():
        snapshot = dict(gw._engagement_tasks)
        gw._engagement_tasks.clear()
        try:
            finished = asyncio.create_task(_instant())
            running = asyncio.create_task(_long())
            await finished
            gw._engagement_tasks["done-one"] = finished
            gw._engagement_tasks["live-one"] = running
            result = await gw.cancel_all_engagements()
            try:
                await asyncio.wait_for(running, timeout=1.0)
            except (TimeoutError, asyncio.CancelledError):
                pass
            return result
        finally:
            gw._engagement_tasks.clear()
            gw._engagement_tasks.update(snapshot)

    result = asyncio.run(_go())
    assert result["total"] == 2
    assert result["cancelled_count"] == 1
    by_id = {e["engagement_id"]: e["status"] for e in result["engagements"]}
    assert by_id["done-one"] == "already_finished"
    assert by_id["live-one"] == "cancelling"


# ---------------------------------------------------------------------------
# CLI: voidstrike cancel --all
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = ""
    def json(self):
        return self._payload


def test_cli_cancel_requires_id_or_all(monkeypatch) -> None:
    import typer

    from src.cli import main as cli

    with pytest.raises(typer.Exit) as exc:
        cli.cancel(engagement_id=None, all_running=False, yes=False)
    assert exc.value.exit_code == 2


def test_cli_cancel_rejects_id_and_all_together(monkeypatch) -> None:
    import typer

    from src.cli import main as cli

    with pytest.raises(typer.Exit) as exc:
        cli.cancel(engagement_id="abc", all_running=True, yes=True)
    assert exc.value.exit_code == 2


def test_cli_cancel_all_short_circuits_when_nothing_running(monkeypatch) -> None:
    """If `GET /engagements?running=true` returns an empty list, we should
    NOT prompt and NOT hit the cancel_all endpoint."""
    from src.cli import main as cli

    calls: list[str] = []

    def _fake_get(url, params=None, timeout=None):
        calls.append(f"GET {url}")
        return _FakeResp({"engagements": []})

    def _fake_post(url, timeout=None):
        calls.append(f"POST {url}")
        return _FakeResp({})

    monkeypatch.setattr(cli.httpx, "get", _fake_get)
    monkeypatch.setattr(cli.httpx, "post", _fake_post)
    # Make confirm fail loudly if it's ever called.
    monkeypatch.setattr(cli.typer, "confirm",
                        lambda *a, **kw: pytest.fail("should not prompt when nothing is running"))

    cli._cancel_all(skip_confirm=False)

    assert any(c.startswith("GET ") for c in calls)
    assert not any(c.startswith("POST ") for c in calls)


def test_cli_cancel_all_prompts_unless_yes(monkeypatch) -> None:
    from src.cli import main as cli

    monkeypatch.setattr(cli.httpx, "get",
        lambda *a, **kw: _FakeResp({"engagements": [
            {"engagement_id": "abcdef0123", "name": "x", "mode": "ctf", "profile": "eco"},
        ]}))
    cancel_called: list[bool] = []
    monkeypatch.setattr(cli.httpx, "post",
        lambda *a, **kw: (cancel_called.append(True),
                          _FakeResp({"cancelled_count": 1, "total": 1, "engagements": []}))[1])

    # Operator declines the prompt → no POST.
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **kw: False)
    cli._cancel_all(skip_confirm=False)
    assert cancel_called == []

    # Operator accepts → POST goes out.
    monkeypatch.setattr(cli.typer, "confirm", lambda *a, **kw: True)
    cli._cancel_all(skip_confirm=False)
    assert cancel_called == [True]


def test_cli_cancel_all_with_yes_skips_prompt(monkeypatch) -> None:
    """With `-y`, the prompt must not be invoked at all."""
    from src.cli import main as cli

    monkeypatch.setattr(cli.httpx, "get",
        lambda *a, **kw: _FakeResp({"engagements": [
            {"engagement_id": "abcd", "name": "x", "mode": "ctf", "profile": "eco"},
        ]}))
    monkeypatch.setattr(cli.httpx, "post",
        lambda *a, **kw: _FakeResp({"cancelled_count": 1, "total": 1, "engagements": []}))
    monkeypatch.setattr(cli.typer, "confirm",
        lambda *a, **kw: pytest.fail("--yes must skip the prompt"))

    cli._cancel_all(skip_confirm=True)


def test_cli_cancel_all_handles_gateway_down_on_list(monkeypatch) -> None:
    """If the gateway is unreachable when we try to list, surface a clean
    Exit(1), not a stack trace."""
    import httpx as _httpx
    import typer

    from src.cli import main as cli

    def _raise(*a, **kw):
        raise _httpx.ConnectError("connection refused")

    monkeypatch.setattr(cli.httpx, "get", _raise)
    with pytest.raises(typer.Exit) as exc:
        cli._cancel_all(skip_confirm=True)
    assert exc.value.exit_code == 1
