"""Tests for `voidstrike ls` + the gateway's enriched `/engagements`."""

from __future__ import annotations

import asyncio

import pytest

# ---------------------------------------------------------------------------
# Gateway: status derivation
# ---------------------------------------------------------------------------


def test_status_running_when_task_is_active(monkeypatch, tmp_path) -> None:
    from src.gateway import main as gw

    async def _go():
        async def _long():
            await asyncio.sleep(60)
        task = asyncio.create_task(_long())
        try:
            gw._engagement_tasks["live"] = task
            monkeypatch.setattr(gw, "ENGAGEMENT_DIR", tmp_path)
            # Need the dir to exist so _engagement_status can look for report.md.
            (tmp_path / "live").mkdir(parents=True, exist_ok=True)
            assert gw._engagement_status("live") == "running"
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            gw._engagement_tasks.pop("live", None)

    asyncio.run(_go())


def test_status_finished_when_report_md_exists(monkeypatch, tmp_path) -> None:
    from src.gateway import main as gw

    monkeypatch.setattr(gw, "ENGAGEMENT_DIR", tmp_path)
    eng_dir = tmp_path / "abc"
    eng_dir.mkdir(parents=True)
    (eng_dir / "report.md").write_text("# Report")
    # No task entry → past-tense.
    assert gw._engagement_status("abc") == "finished"


def test_status_stopped_when_no_task_and_no_report(monkeypatch, tmp_path) -> None:
    from src.gateway import main as gw

    monkeypatch.setattr(gw, "ENGAGEMENT_DIR", tmp_path)
    (tmp_path / "abc").mkdir(parents=True)
    assert gw._engagement_status("abc") == "stopped"


def test_list_engagements_includes_status(monkeypatch, tmp_path) -> None:
    from src.gateway import main as gw

    monkeypatch.setattr(gw, "ENGAGEMENT_DIR", tmp_path)
    eng_dir = tmp_path / "finished-one"
    eng_dir.mkdir(parents=True)
    (eng_dir / "report.md").write_text("# done")
    (eng_dir / "spec.yaml").write_text(
        "name: htb-blue\nmode: ctf\ntargets: [10.129.1.221]\nprofile: eco\n"
    )

    async def _go():
        return await gw.list_engagements(running=False)

    data = asyncio.run(_go())
    [entry] = data["engagements"]
    assert entry["engagement_id"] == "finished-one"
    assert entry["status"] == "finished"
    assert entry["name"] == "htb-blue"
    assert entry["profile"] == "eco"


def test_list_engagements_running_filter_excludes_finished(monkeypatch, tmp_path) -> None:
    """`?running=true` must drop non-running entries."""
    from src.gateway import main as gw

    monkeypatch.setattr(gw, "ENGAGEMENT_DIR", tmp_path)
    (tmp_path / "done").mkdir(parents=True)
    (tmp_path / "done" / "report.md").write_text("")
    (tmp_path / "done" / "spec.yaml").write_text(
        "name: x\nmode: ctf\ntargets: [10.0.0.1]\n"
    )

    async def _go():
        return await gw.list_engagements(running=True)

    data = asyncio.run(_go())
    assert data["engagements"] == []


def test_list_engagements_surfaces_running_task_with_no_spec_dir(monkeypatch, tmp_path) -> None:
    """Edge case: an engagement task exists in memory but its dir got deleted
    or wasn't created. We still surface it so the operator can cancel."""
    from src.gateway import main as gw

    monkeypatch.setattr(gw, "ENGAGEMENT_DIR", tmp_path)

    async def _go():
        async def _long():
            await asyncio.sleep(60)
        task = asyncio.create_task(_long())
        try:
            gw._engagement_tasks["orphan"] = task
            result = await gw.list_engagements(running=False)
            return result
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            gw._engagement_tasks.pop("orphan", None)

    data = asyncio.run(_go())
    ids = [e["engagement_id"] for e in data["engagements"]]
    assert "orphan" in ids


# ---------------------------------------------------------------------------
# CLI: ls command formatting
# ---------------------------------------------------------------------------


def test_cli_ls_command_calls_gateway(monkeypatch, capsys) -> None:
    """The CLI's `ls` command should hit `GET /engagements` and render the
    response. We stub httpx and check the call was made with the right URL."""
    from src.cli import main as cli

    calls: list[dict] = []

    class _FakeResp:
        status_code = 200
        text = ""
        def json(self):
            return {
                "engagements": [
                    {
                        "engagement_id": "abcdef0123456789",
                        "status": "running",
                        "name": "htb-blue",
                        "mode": "ctf",
                        "profile": "eco",
                        "targets": ["10.129.1.221"],
                    },
                ]
            }

    def _fake_get(url, params=None, timeout=None):
        calls.append({"url": url, "params": params})
        return _FakeResp()

    monkeypatch.setattr(cli.httpx, "get", _fake_get)
    # Invoke the command function directly (Typer would normally do this).
    cli.ls(running=False)
    assert calls and calls[0]["url"].endswith("/engagements")
    # Without --running, no `running` param should be sent.
    assert calls[0]["params"] is None


def test_cli_ls_running_flag_passes_param(monkeypatch) -> None:
    from src.cli import main as cli

    calls: list[dict] = []

    class _FakeResp:
        status_code = 200
        text = ""
        def json(self):
            return {"engagements": []}

    def _fake_get(url, params=None, timeout=None):
        calls.append({"url": url, "params": params})
        return _FakeResp()

    monkeypatch.setattr(cli.httpx, "get", _fake_get)
    cli.ls(running=True)
    assert calls[0]["params"] == {"running": "true"}


def test_cli_ls_handles_gateway_down(monkeypatch) -> None:
    """If the gateway is unreachable, ls should exit cleanly (not raise)."""
    import httpx as _httpx
    import typer

    from src.cli import main as cli

    def _raise(*a, **kw):
        raise _httpx.ConnectError("connection refused")

    monkeypatch.setattr(cli.httpx, "get", _raise)
    with pytest.raises(typer.Exit) as exc:
        cli.ls(running=False)
    assert exc.value.exit_code == 1
