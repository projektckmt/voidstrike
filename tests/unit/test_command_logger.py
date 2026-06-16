"""Tests for command_logger — auto-recording target-facing tool calls.

The analyst's methodology section replays the episode log; without this the log
held only a few hand-written summaries. command_logger records every meaningful
tool call (verbatim command + output) so the methodology reads like a writeup.
The DB write is stubbed — these pin which calls get logged and what's captured.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from src.agent.middleware import command_logger
from src.agent.middleware.command_logger import _loggable, _stringify_output


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name, args, call_id="c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"name": tool_name, "args": args, "id": call_id},
    )


def _result(content, status="success"):
    return SimpleNamespace(content=content, name="t", status=status)


# --- loggability rule ------------------------------------------------------

def test_loggable_includes_offensive_tools():
    assert _loggable("shell__tmux_exec")
    assert _loggable("shell__tmux_send")
    assert _loggable("surface__nmap_quick")
    assert _loggable("exploit__msfvenom")
    assert _loggable("postex__linpeas")


def test_loggable_excludes_reads_plumbing_and_bookkeeping():
    assert not _loggable("shell__tmux_read")
    assert not _loggable("shell__tmux_list_sessions")
    assert not _loggable("shell__stabilize_shell")
    assert not _loggable("shell__tmux_new_session")
    assert not _loggable("episodes__write_episode")
    assert not _loggable("episodes__write_finding")
    assert not _loggable("episodes__read_engagement")
    # non-MCP tools (no `__`) — vfs/todo/task — never logged
    assert not _loggable("write_todos")
    assert not _loggable("task")
    assert not _loggable("read_file")


def test_stringify_output_handles_block_lists_and_caps():
    assert _stringify_output(_result("uid=0(root)")) == "uid=0(root)"
    blocks = _result([{"text": "a"}, {"text": "b"}])
    assert _stringify_output(blocks) == "ab"
    long = _result("x" * 20000)
    assert len(_stringify_output(long)) == 8000


# --- behaviour -------------------------------------------------------------

def _capture_inserts(monkeypatch):
    """Patch the stdlib asyncio.to_thread the middleware calls, capturing the
    args it would pass to the DB insert. Returns the list of captured rows."""
    rows = []

    async def fake_to_thread(fn, *a):
        rows.append(a)  # (url, eng, agent, action, tool_input, output, outcome, error)

    monkeypatch.setattr("asyncio.to_thread", fake_to_thread)
    return rows


async def _passthrough(request):
    return _result('{"ok": true, "output": "done"}')


def test_logs_offensive_call_with_verbatim_command_and_output(monkeypatch):
    rows = _capture_inserts(monkeypatch)
    guard = command_logger("eng-1", "postex")
    res = _run(guard.awrap_tool_call(
        _request("shell__tmux_exec",
                 {"session_name": "lsn", "command": "cat /etc/passwd"}),
        _passthrough,
    ))
    assert res.content == '{"ok": true, "output": "done"}'  # result passes through
    assert len(rows) == 1
    _url, eng, agent, action, tool_input, output, outcome, error = rows[0]
    assert eng == "eng-1"
    assert agent == "postex"
    assert action == "shell__tmux_exec"
    assert tool_input == {"session_name": "lsn", "command": "cat /etc/passwd"}
    assert "done" in output
    assert outcome == "no_result"
    assert error is None


def test_skips_read_and_plumbing_calls(monkeypatch):
    rows = _capture_inserts(monkeypatch)
    guard = command_logger("eng-1", "postex")
    for name in ("shell__tmux_read", "episodes__write_finding", "write_todos"):
        _run(guard.awrap_tool_call(_request(name, {"x": 1}), _passthrough))
    assert rows == []


def test_records_tool_level_error_as_error_episode(monkeypatch):
    rows = _capture_inserts(monkeypatch)
    guard = command_logger("eng-1", "surface")

    async def _err(request):
        return _result("BOOM: command failed", status="error")

    _run(guard.awrap_tool_call(
        _request("surface__nmap_quick", {"target": "10.10.10.5"}), _err))
    assert len(rows) == 1
    *_, outcome, error = rows[0]
    assert outcome == "error"
    assert error == "BOOM: command failed"


def test_disabled_when_no_engagement_id(monkeypatch):
    rows = _capture_inserts(monkeypatch)
    guard = command_logger(None, "postex")
    _run(guard.awrap_tool_call(
        _request("shell__tmux_exec", {"command": "id"}), _passthrough))
    assert rows == []


def test_db_failure_never_breaks_the_tool_call(monkeypatch):
    async def boom(fn, *a):
        raise RuntimeError("postgres down")

    monkeypatch.setattr("asyncio.to_thread", boom)
    guard = command_logger("eng-1", "postex")
    res = _run(guard.awrap_tool_call(
        _request("shell__tmux_exec", {"command": "id"}), _passthrough))
    assert res.content == '{"ok": true, "output": "done"}'  # call still succeeds
