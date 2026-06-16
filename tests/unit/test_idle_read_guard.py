"""Tests for the subagent idle-read guard.

Reproduces the real failure mode: postex issues a command into a tmux pane,
the command finishes, and the agent then spin-polls `shell__tmux_read` — each
read coming back `ok:True` with an empty incremental delta (`new_output:False`).
repeat_guard exempts this (the reads "succeed"); this guard must break it after
a threshold, reset so the session stays usable, never count non-read tools, and
never block a listener legitimately waiting for a callback.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from src.agent.middleware.idle_read_guard import idle_read_guard


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name: str, args: dict, call_id: str = "c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": args, "id": call_id},
    )


def _reader(payload: dict):
    """Handler returning a fixed tmux_read payload, counting invocations."""
    calls: list[dict] = []

    async def handler(request):
        calls.append(request.tool_call["args"])
        return SimpleNamespace(
            content=json.dumps(payload), name=request.tool.name, status="success"
        )

    return handler, calls


IDLE = {"ok": True, "output": "", "new_output": False, "timed_out": False}
FRESH = {"ok": True, "output": "uid=0(root)", "new_output": True, "timed_out": False}
LISTENER_WAITING = {"ok": True, "output": "", "new_output": False, "connection": None}
# A listener with a shell already landed: `connection` is populated and reads
# come back empty while the agent spin-reads the landed shell. This is the bug
# that shipped first — the guard exempted it because the `connection` key was
# present at all, instead of only when still waiting (connection is None).
LISTENER_LANDED = {
    "ok": True, "output": "", "new_output": False,
    "connection": {"peer_ip": "10.10.10.5", "peer_port": 49233},
}


def test_blocks_after_consecutive_idle_reads():
    guard = idle_read_guard(max_idle=6)
    handler, calls = _reader(IDLE)
    req = _request("shell__tmux_read", {"session_name": "kali_stage"})

    # First six idle reads reach the handler.
    for _ in range(6):
        res = _run(guard.awrap_tool_call(req, handler))
        assert "IDLE_READ_BLOCKED" not in getattr(res, "content", "")
    assert len(calls) == 6

    # The seventh is blocked before reaching the handler.
    res = _run(guard.awrap_tool_call(req, handler))
    assert len(calls) == 6
    assert res.status == "error"
    assert "IDLE_READ_BLOCKED" in res.content


def test_block_resets_so_session_stays_usable():
    guard = idle_read_guard(max_idle=3)
    handler, calls = _reader(IDLE)
    req = _request("shell__tmux_read", {"session_name": "s"})

    for _ in range(3):
        _run(guard.awrap_tool_call(req, handler))
    blocked = _run(guard.awrap_tool_call(req, handler))
    assert "IDLE_READ_BLOCKED" in blocked.content
    # After the one-shot nudge the counter resets — the next read runs again.
    res = _run(guard.awrap_tool_call(req, handler))
    assert "IDLE_READ_BLOCKED" not in res.content
    assert len(calls) == 4


def test_repeated_blocks_escalate_to_structured_return():
    guard = idle_read_guard(max_idle=2)
    handler, _ = _reader(IDLE)
    req = _request("shell__tmux_read", {"session_name": "s"})

    for _ in range(2):
        _run(guard.awrap_tool_call(req, handler))
    first = _run(guard.awrap_tool_call(req, handler))
    assert "IDLE_READ_BLOCKED" in first.content
    assert "Return your structured result now" not in first.content

    for _ in range(2):
        _run(guard.awrap_tool_call(req, handler))
    second = _run(guard.awrap_tool_call(req, handler))
    assert "IDLE_READ_BLOCKED" in second.content
    assert "Return your structured result now" in second.content


def test_tmux_send_clears_idle_streak():
    guard = idle_read_guard(max_idle=2)
    handler, calls = _reader(IDLE)
    read = _request("shell__tmux_read", {"session_name": "s"})
    send = _request("shell__tmux_send", {"session_name": "s", "command": "id"})

    for _ in range(2):
        _run(guard.awrap_tool_call(read, handler))
    _run(guard.awrap_tool_call(send, handler))
    res = _run(guard.awrap_tool_call(read, handler))
    assert "IDLE_READ_BLOCKED" not in getattr(res, "content", "")
    assert len(calls) == 4


def test_new_output_resets_the_counter():
    guard = idle_read_guard(max_idle=3)
    req = _request("shell__tmux_read", {"session_name": "s"})

    seq = [IDLE, IDLE, FRESH, IDLE, IDLE, IDLE]
    i = {"n": 0}

    async def handler(request):
        payload = seq[i["n"]]
        i["n"] += 1
        return SimpleNamespace(content=json.dumps(payload), name=request.tool.name, status="success")

    # Two idle, a fresh read resets, then three more idle — never reaches the
    # block because the fresh read in the middle cleared the streak.
    for _ in range(6):
        res = _run(guard.awrap_tool_call(req, handler))
        assert "IDLE_READ_BLOCKED" not in getattr(res, "content", "")


def test_waiting_listener_eventually_blocks():
    # A listener with `connection: null` and no new output is NOT exempt: a real
    # callback would produce output and reset the streak, so persistent empties
    # mean the payload never fired and the agent should act, not blind-poll.
    guard = idle_read_guard(max_idle=3)
    handler, _ = _reader(LISTENER_WAITING)
    req = _request("shell__tmux_read", {"session_name": "rev_listener"})

    for _ in range(3):
        res = _run(guard.awrap_tool_call(req, handler))
        assert "IDLE_READ_BLOCKED" not in getattr(res, "content", "")
    res = _run(guard.awrap_tool_call(req, handler))
    assert res.status == "error"
    assert "IDLE_READ_BLOCKED" in res.content


def test_landed_listener_still_blocks():
    # A listener with a shell landed (connection populated) being spin-read empty
    # must block — leaked through the first cut of the guard.
    guard = idle_read_guard(max_idle=6)
    handler, calls = _reader(LISTENER_LANDED)
    req = _request("shell__tmux_read", {"session_name": "shell_listener"})

    for _ in range(6):
        res = _run(guard.awrap_tool_call(req, handler))
        assert "IDLE_READ_BLOCKED" not in getattr(res, "content", "")
    res = _run(guard.awrap_tool_call(req, handler))
    assert len(calls) == 6
    assert res.status == "error"
    assert "IDLE_READ_BLOCKED" in res.content


def test_msf_listener_connection_null_blocks():
    # Regression for the reported `msf-main` spin: an msfconsole listener reports
    # `connection: null` forever (the server's detector only parses nc-style
    # callbacks), so empty reads must still accumulate and block.
    guard = idle_read_guard(max_idle=6)
    handler, calls = _reader(LISTENER_WAITING)  # ok=True, new_output=False, connection=None
    req = _request("shell__tmux_read", {"session_name": "msf-main"})

    for _ in range(6):
        _run(guard.awrap_tool_call(req, handler))
    res = _run(guard.awrap_tool_call(req, handler))
    assert len(calls) == 6
    assert res.status == "error"
    assert "IDLE_READ_BLOCKED" in res.content


def test_per_session_counters_are_independent():
    guard = idle_read_guard(max_idle=3)
    handler, _ = _reader(IDLE)

    # Reads on one session never increment another's counter: three idle reads
    # each, interleaved, stays under the per-session threshold for both.
    for _ in range(3):
        for sess in ("a", "b"):
            res = _run(guard.awrap_tool_call(_request("shell__tmux_read", {"session_name": sess}), handler))
            assert "IDLE_READ_BLOCKED" not in getattr(res, "content", "")


def test_non_read_tools_pass_through():
    guard = idle_read_guard(max_idle=2)
    handler, calls = _reader(IDLE)
    # tmux_send is not a read — must never be counted or blocked.
    for _ in range(10):
        res = _run(guard.awrap_tool_call(_request("shell__tmux_send", {"session_name": "s"}), handler))
        assert "IDLE_READ_BLOCKED" not in getattr(res, "content", "")
    assert len(calls) == 10


# A wedged PTY (line-wrap/redraw loop) re-emits ~the same garbled pane on every
# read, with only a few chars of freshly-echoed command differing — so each read
# is `new_output: True` yet makes no real progress. `new_output`-only idle
# detection misses this entirely (this was the connected.htb budget burn).
_GARBLE = (
    "[asterisk@connected html]$ sed -n '132,200p' /var/www/htsed -n '132,200p' "
    "/var/wwww/html/admin/libraries/Builtin/SystemUpdates.phpin/SystemUpdates.php"
    "ar/www/html/admin/libraries/Built\tpublic function startYumUpdate() {"
) * 3


def _churn_reader():
    """Handler whose output stays ~identical (only a tiny tail varies) and always
    reports new_output:True — the wedged-shell signature."""
    n = {"i": 0}

    async def handler(request):
        n["i"] += 1
        payload = {
            "ok": True,
            # A few fresh bytes each time (echoed command) on a constant body.
            "output": _GARBLE + f"\necho probe_{n['i']}",
            "new_output": True,
            "timed_out": False,
        }
        return SimpleNamespace(content=json.dumps(payload), name=request.tool.name, status="success")

    return handler


def _drive_until_blocked(guard, read_req, handler, *, send_req=None, cap=12):
    """Issue reads (optionally interleaving a send) until the guard blocks.
    Returns the blocking ToolMessage, or None if it never blocked within cap."""
    for _ in range(cap):
        res = _run(guard.awrap_tool_call(read_req, handler))
        if getattr(res, "status", "") == "error":
            return res
        if send_req is not None:
            _run(guard.awrap_tool_call(send_req, handler))
    return None


def test_wedged_shell_blocks_despite_new_output():
    guard = idle_read_guard(max_idle=6)
    req = _request("shell__tmux_read", {"session_name": "lsn"})
    # The first read seeds the comparison window, so churn blocks one read after
    # the idle path would — still well within max_idle+2.
    res = _drive_until_blocked(guard, req, _churn_reader(), cap=9)
    assert res is not None, "wedged-shell churn never blocked"
    assert "WEDGED_SHELL_BLOCKED" in res.content


def test_churn_streak_survives_tmux_send():
    # The recovery spiral was send,read,send,read,... — a fresh send must NOT
    # reset the churn streak (sending into a wedged shell changes nothing), or
    # the guard never accumulates and never fires.
    guard = idle_read_guard(max_idle=6)
    read = _request("shell__tmux_read", {"session_name": "lsn"})
    send = _request("shell__tmux_send", {"session_name": "lsn", "command": "id"})
    res = _drive_until_blocked(guard, read, _churn_reader(), send_req=send, cap=9)
    assert res is not None, "churn streak was wrongly reset by interleaved sends"
    assert "WEDGED_SHELL_BLOCKED" in res.content


def test_distinct_output_does_not_trip_churn():
    # Genuinely different output each read (a healthy enum sweep) must never be
    # mistaken for churn, regardless of new_output.
    guard = idle_read_guard(max_idle=4)
    distinct = [
        "uid=0(root) gid=0(root)",
        "Linux connected 3.10.0-1160.el7.x86_64",
        "total 48\ndrwxr-xr-x 2 root root 4096 etc passwd shadow",
        "tcp 0 0 0.0.0.0:22 LISTEN sshd",
        "/usr/bin/sudo /usr/bin/passwd /usr/bin/chsh suid binaries",
        "asterisk:x:999:999::/var/lib/asterisk:/bin/bash",
    ]
    seq = iter(distinct)

    async def handler(request):
        payload = {"ok": True, "output": next(seq), "new_output": True, "timed_out": False}
        return SimpleNamespace(content=json.dumps(payload), name=request.tool.name, status="success")

    req = _request("shell__tmux_read", {"session_name": "lsn"})
    for _ in range(len(distinct)):
        res = _run(guard.awrap_tool_call(req, handler))
        assert getattr(res, "status", "") != "error"
