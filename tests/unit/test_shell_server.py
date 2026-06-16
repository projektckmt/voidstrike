"""Tests for the shell MCP server's read helpers.

These cover the deterministic pieces that let the agent tell "the shell called
back" from "still only listening", and that keep re-reads from re-dumping the
whole scrollback. The tmux-driven tools themselves need a live tmux and are
exercised in integration, not here.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest

from src.mcp_servers.shell import server


def _run(coro):
    return asyncio.run(coro)


# --- connection detection -------------------------------------------------

def test_detect_connection_gnu_netcat_traditional():
    text = (
        "Listening on 0.0.0.0 4444\n"
        "connect to [10.10.16.91] from (UNKNOWN) [10.129.5.112] 41562\n"
    )
    conn = server._detect_listener_connection(text)
    assert conn == {"peer_ip": "10.129.5.112", "peer_port": 41562}


def test_detect_connection_openbsd_nc():
    text = "Listening on [0.0.0.0] (family 0, port 4444)\nConnection received on 10.129.5.112 41562\n"
    conn = server._detect_listener_connection(text)
    assert conn == {"peer_ip": "10.129.5.112", "peer_port": 41562}


def test_detect_connection_ncat():
    text = "Ncat: Listening on 0.0.0.0:4444\nNcat: Connection from 10.129.5.112:41562.\n"
    conn = server._detect_listener_connection(text)
    assert conn == {"peer_ip": "10.129.5.112", "peer_port": 41562}


def test_no_connection_while_only_listening():
    # The exact pane content from the stuck-loop trace: listener up, no callback.
    text = "rlwrap nc -lvnp 4444\nListening on 0.0.0.0 4444\n"
    assert server._detect_listener_connection(text) is None


# --- incremental delta ----------------------------------------------------

def test_incremental_delta_returns_only_new_suffix():
    prev = "Listening on 0.0.0.0 4444"
    cur = "Listening on 0.0.0.0 4444\nconnect to [10.10.16.91] from x 41562"
    assert server._incremental_delta(prev, cur) == "\nconnect to [10.10.16.91] from x 41562"


def test_incremental_delta_empty_when_nothing_new():
    buf = "Listening on 0.0.0.0 4444"
    assert server._incremental_delta(buf, buf) == ""


def test_incremental_delta_first_read_returns_full():
    assert server._incremental_delta("", "Listening on 0.0.0.0 4444") == "Listening on 0.0.0.0 4444"


def test_incremental_delta_falls_back_to_full_on_scrollback_roll():
    # current no longer starts with prev (old lines scrolled off the 2000 cap).
    prev = "line A\nline B"
    cur = "line B\nline C"
    assert server._incremental_delta(prev, cur) == cur


# --- listener-guard on tmux_send ------------------------------------------
#
# These are pure unit tests against the in-process registry and `_tmux`
# wrapper. We stub `_tmux` so the tests don't need a live tmux daemon.

@pytest.fixture(autouse=True)
def _clean_registry():
    server._REGISTRY.sessions.clear()
    yield
    server._REGISTRY.sessions.clear()


@pytest.fixture
def _stub_tmux_ok(monkeypatch):
    """Stub `_tmux` so send-keys "succeeds" without a real tmux server."""
    calls: list[tuple[str, ...]] = []

    async def fake_tmux(*args):
        calls.append(args)
        return (0, "", "")

    monkeypatch.setattr(server, "_tmux", fake_tmux)
    return calls


def test_tmux_send_refuses_listener_without_callback(_stub_tmux_ok):
    """The whole point of the guard: typing into a listener pane before a
    client connects is the most common exploit-subagent failure mode."""
    server._REGISTRY.sessions["lsn"] = server.SessionState(
        name="lsn", kind="listener", listening_on=4444,
    )
    result = _run(server.tmux_send("lsn", "whoami"))
    assert result["ok"] is False
    assert result["kind"] == "listener_no_callback"
    # And no send-keys was actually issued.
    assert not _stub_tmux_ok


def test_tmux_send_allows_listener_after_callback(_stub_tmux_ok):
    """Once `_detect_listener_connection` flips `callback_received`, the
    guard lifts and the agent can drive the landed shell."""
    state = server.SessionState(name="lsn", kind="listener", listening_on=4444)
    state.callback_received = True
    server._REGISTRY.sessions["lsn"] = state
    result = _run(server.tmux_send("lsn", "whoami"))
    assert result["ok"] is True
    assert any(a[0] == "send-keys" for a in _stub_tmux_ok)


def test_tmux_send_force_bypasses_listener_guard(_stub_tmux_ok):
    """`force=True` is the escape hatch — operator/agent needs to send
    Ctrl-C or restart the listener with new flags."""
    server._REGISTRY.sessions["lsn"] = server.SessionState(
        name="lsn", kind="listener", listening_on=4444,
    )
    result = _run(server.tmux_send("lsn", "\x03", force=True))
    assert result["ok"] is True
    assert any(a[0] == "send-keys" for a in _stub_tmux_ok)


def test_tmux_send_refuses_ctrlc_to_connected_listener(_stub_tmux_ok):
    """Regression: the agent sent `C-c` to the listener to 'clear a wedged
    pane' and killed the relayed target shell. Even after callback, a control
    keystroke to a listener pane must be refused (it hits nc, not the remote
    command)."""
    state = server.SessionState(name="lsn", kind="listener", listening_on=443)
    state.callback_received = True  # shell already landed — pre-callback guard lifted
    server._REGISTRY.sessions["lsn"] = state
    for key in ("C-c", "^C", "\x03", "C-d", "C-c C-c"):
        result = _run(server.tmux_send("lsn", key))
        assert result["ok"] is False, key
        assert result["kind"] == "listener_control_key", key
    assert not _stub_tmux_ok  # nothing was ever sent to tmux


def test_tmux_send_normal_command_to_connected_listener_still_works(_stub_tmux_ok):
    """The control-key guard must not block ordinary shell-driving commands
    on a landed shell."""
    state = server.SessionState(name="lsn", kind="listener", listening_on=443)
    state.callback_received = True
    server._REGISTRY.sessions["lsn"] = state
    result = _run(server.tmux_send("lsn", "cat /root/root.txt"))
    assert result["ok"] is True
    assert any(a[0] == "send-keys" for a in _stub_tmux_ok)


def test_tmux_send_ctrlc_allowed_with_force(_stub_tmux_ok):
    """force=True is the deliberate escape hatch to actually kill a listener."""
    state = server.SessionState(name="lsn", kind="listener", listening_on=443)
    state.callback_received = True
    server._REGISTRY.sessions["lsn"] = state
    result = _run(server.tmux_send("lsn", "C-c", force=True))
    assert result["ok"] is True


def test_is_control_keys_detector():
    assert server._is_control_keys("C-c")
    assert server._is_control_keys("^C")
    assert server._is_control_keys("\x03")
    assert server._is_control_keys("C-c C-c")
    assert not server._is_control_keys("whoami")
    assert not server._is_control_keys("cat /etc/passwd")
    assert not server._is_control_keys("")


def test_tmux_send_unguarded_for_generic_sessions(_stub_tmux_ok):
    """Kali-local staging sessions (kind=generic) are NEVER blocked, even
    if their pane happens to contain the word 'listening'."""
    server._REGISTRY.sessions["stage"] = server.SessionState(
        name="stage", kind="generic",
    )
    result = _run(server.tmux_send("stage", "curl -sSLO ..."))
    assert result["ok"] is True


def test_tmux_send_unknown_session_errors_cleanly(_stub_tmux_ok):
    result = _run(server.tmux_send("does-not-exist", "whoami"))
    assert result["ok"] is False
    assert "unknown session" in result["error"]


# --- callback / HTTP helpers ----------------------------------------------

def test_cookie_jar_parser_handles_http_only_lines(tmp_path):
    jar = tmp_path / "cj.txt"
    jar.write_text(
        "# Netscape HTTP Cookie File\n"
        "#HttpOnly_staging.silentium.htb\tFALSE\t/\tFALSE\t0\ttoken\tabc.def\n"
        "staging.silentium.htb\tFALSE\t/\tFALSE\t0\tconnect.sid\ts%3A123\n"
    )
    assert server._cookies_from_netscape_cookie_jar(str(jar)) == {
        "token": "abc.def",
        "connect.sid": "s%3A123",
    }


def test_compact_response_headers_omits_cookie_by_default():
    headers = httpx.Headers({
        "Content-Type": "application/json",
        "Set-Cookie": "connect.sid=secret",
        "X-Debug": "noisy",
    })

    compact = server._compact_response_headers(headers, include_headers=False)

    assert compact == {"content-type": "application/json"}


def test_compact_response_headers_can_return_full_headers():
    headers = httpx.Headers({
        "Content-Type": "application/json",
        "Set-Cookie": "connect.sid=secret",
    })

    full = server._compact_response_headers(headers, include_headers=True)

    assert full["content-type"] == "application/json"
    assert full["set-cookie"] == "connect.sid=secret"


def test_write_netscape_cookie_jar_returns_names_and_writes_file(tmp_path):
    jar = tmp_path / "sess.jar"
    cookies = [
        SimpleNamespace(
            name="connect.sid",
            value="s%3A123",
            domain="staging.silentium.htb",
            path="/",
            secure=False,
            expires=0,
        )
    ]

    names = server._write_netscape_cookie_jar(str(jar), cookies)

    assert names == ["connect.sid"]
    text = jar.read_text()
    assert "staging.silentium.htb\tFALSE\t/\tFALSE\t0\tconnect.sid\ts%3A123" in text


def test_callback_event_matching_uses_method_path_and_client():
    event = server.CallbackEvent(
        ts=1.0,
        method="GET",
        path="/MARKER-root",
        client="10.129.245.103",
    )
    assert server._event_matches(event, [r"MARKER-root"])
    assert server._event_matches(event, [r"10\.129\.245\.103"])
    assert not server._event_matches(event, [r"PORT-443-OPEN"])


@pytest.mark.asyncio
async def test_stabilize_shell_is_automation_safe(monkeypatch) -> None:
    """Regression: the old `stty raw -echo; fg` + `reset` dance corrupted a
    freshly-landed shell (CPR escape `;5R` injected into stdin). The upgrade
    must be pty.spawn + TERM/size only — no raw/fg/reset/Ctrl-Z."""
    sent: list[tuple] = []

    async def _fake_tmux(*args):
        sent.append(args)
        return 0, "", ""

    async def _fake_read(**kwargs):
        return {"ok": True, "output": "/ # ", "timed_out": False}

    monkeypatch.setattr(server, "_tmux", _fake_tmux)
    monkeypatch.setattr(server, "tmux_read", _fake_read)
    server._REGISTRY.sessions["shellX"] = server.SessionState(name="shellX", kind="shell")

    res = await server.stabilize_shell("shellX")
    assert res["ok"] is True

    # Flatten everything sent to tmux.
    payload = " ".join(str(a) for call in sent for a in call)
    # The corrupting operator-terminal commands must be gone.
    assert "raw -echo" not in payload
    assert "fg" not in payload
    assert "reset" not in payload
    assert "C-z" not in payload and "\x1a" not in payload
    # The safe upgrade must be present.
    assert "pty.spawn" in payload
    assert "TERM=xterm" in payload
    assert "stty rows" in payload  # window size, not raw


@pytest.mark.asyncio
async def test_stabilize_shell_unknown_session() -> None:
    res = await server.stabilize_shell("nope-not-a-session")
    assert res["ok"] is False


@pytest.mark.asyncio
async def test_stabilize_shell_reports_healthy_when_token_echoes(monkeypatch) -> None:
    """The health probe echoes a unique token; a live PTY returns it twice
    (command echo + command output), so `healthy` is True."""
    captured: dict[str, str] = {}

    async def _fake_tmux(*args):
        if args[0] == "send-keys" and args[3].startswith("echo VSHEALTH"):
            captured["token"] = args[3].split()[1]
        return 0, "", ""

    async def _fake_read(**kwargs):
        tok = captured.get("token", "")
        # PTY echoes the command AND its output -> token appears twice, at prompt.
        return {"ok": True, "output": f"$ echo {tok}\n{tok}\n$ ", "timed_out": False}

    monkeypatch.setattr(server, "_tmux", _fake_tmux)
    monkeypatch.setattr(server, "tmux_read", _fake_read)
    server._REGISTRY.sessions["live"] = server.SessionState(name="live", kind="shell")

    res = await server.stabilize_shell("live")
    assert res["healthy"] is True
    assert "hint" not in res


@pytest.mark.asyncio
async def test_stabilize_shell_reports_wedged_with_reestablish_hint(monkeypatch) -> None:
    """A wedged shell never cleanly executes the probe (token appears at most
    once, as the unexecuted command echo), so `healthy` is False and the result
    carries a re-establish hint instead of letting the agent keep polling."""
    captured: dict[str, str] = {}

    async def _fake_tmux(*args):
        if args[0] == "send-keys" and args[3].startswith("echo VSHEALTH"):
            captured["token"] = args[3].split()[1]
        return 0, "", ""

    async def _fake_read(**kwargs):
        tok = captured.get("token", "")
        # Wedged: the command echoes once but never runs, mangled by redraw.
        return {"ok": True, "output": f"echo {tok}garbled\x1b[Kno-prompt", "timed_out": True}

    monkeypatch.setattr(server, "_tmux", _fake_tmux)
    monkeypatch.setattr(server, "tmux_read", _fake_read)
    server._REGISTRY.sessions["dead"] = server.SessionState(name="dead", kind="shell")

    res = await server.stabilize_shell("dead")
    assert res["healthy"] is False
    assert "re-establish" in res["hint"].lower() or "re-fire" in res["hint"].lower()


@pytest.mark.asyncio
async def test_tmux_read_new_output_ignores_cosmetic_redraw(monkeypatch) -> None:
    """Regression (connected.htb budget burn): a wedged PTY re-renders the same
    visible line with different escape/whitespace bytes on every capture. That
    must NOT report `new_output: True`, or the idle-read guard never fires."""
    panes = iter([
        "[user@host ~]$ cat /etc/passwd\nroot:x:0:0:root:/root:/bin/bash\n$ ",
        # Same visible text, but redrawn with colour codes + extra spaces + CRs.
        "\x1b[0m[user@host ~]$ cat /etc/passwd\r\nroot:x:0:0:root:/root:/bin/bash  \n$ \x1b[K",
    ])

    async def _fake_tmux(*args):
        return 0, next(panes) + "\n", ""

    monkeypatch.setattr(server, "_tmux", _fake_tmux)
    server._REGISTRY.sessions["s"] = server.SessionState(name="s", kind="shell")

    first = await server.tmux_read("s", timeout_s=0.1, wait_for_prompt=False)
    assert first["new_output"] is True  # first read always has content
    second = await server.tmux_read("s", timeout_s=0.1, wait_for_prompt=False)
    assert second["new_output"] is False, "cosmetic redraw must not count as new output"


@pytest.mark.asyncio
async def test_tmux_read_bounds_scrollback_and_output(monkeypatch) -> None:
    """Cost fix: tmux_read must capture a BOUNDED scrollback (not the whole
    2000-line buffer) and tail-cap the returned output, so a busy session
    doesn't re-dump tens of KB on every read (quadratic token cost)."""
    captured_cmd = []

    async def _fake_tmux(*args):
        captured_cmd.append(args)
        # A pane far bigger than max_bytes.
        return 0, "X" * 200_000 + "\n$ ", ""

    monkeypatch.setattr(server, "_tmux", _fake_tmux)
    server._REGISTRY.sessions["s"] = server.SessionState(name="s", kind="shell")

    res = await server.tmux_read("s", timeout_s=0.1, wait_for_prompt=False)
    assert res["ok"] is True
    # Output is tail-capped to the (now small) default max_bytes.
    assert len(res["output"]) <= 12000
    # Capture used a bounded scrollback window, NOT -2000.
    cap = captured_cmd[0]
    assert "capture-pane" in cap
    si = cap.index("-S")
    assert cap[si + 1] == f"-{server._TMUX_SCROLLBACK_LINES}"
    assert cap[si + 1] != "-2000"


@pytest.mark.asyncio
async def test_tmux_read_connection_is_sticky_after_banner_scrolls_off(monkeypatch) -> None:
    """Regression (debug5): a landed reverse shell was misread as DROPPED once
    privesc output scrolled the netcat banner out of the capture window — the
    re-scan returned `connection: null` while the shell was still alive.
    `connection` must be sticky: latched on first detection, kept thereafter."""
    panes = iter([
        # 1st read: banner is visible -> connection detected + latched.
        "Listening on 0.0.0.0 4444\n"
        "connect to [10.10.16.91] from (UNKNOWN) [10.129.5.112] 41562\n"
        "wingftp@wingdata:~$ ",
        # 2nd read: banner has scrolled off; only command output + prompt remain.
        "uid=1000(wingftp) gid=1000(wingftp)\n"
        "drwxr-x--- ServerInterface.lua\n"
        "wingftp@wingdata:~$ ",
    ])

    async def _fake_tmux(*args):
        return 0, next(panes) + "\n", ""

    monkeypatch.setattr(server, "_tmux", _fake_tmux)
    server._REGISTRY.sessions["lsn"] = server.SessionState(
        name="lsn", kind="listener", listening_on=4444
    )

    first = await server.tmux_read("lsn", timeout_s=0.1)
    assert first["connection"] == {"peer_ip": "10.129.5.112", "peer_port": 41562}
    assert server._REGISTRY.sessions["lsn"].callback_received is True

    # Banner gone from the pane, but the shell is alive — connection stays latched.
    second = await server.tmux_read("lsn", timeout_s=0.1)
    assert second["connection"] == {"peer_ip": "10.129.5.112", "peer_port": 41562}, (
        "connection went null after the banner scrolled off — the false-drop bug"
    )


def test_tmux_read_docstring_is_present() -> None:
    """Regression: a `\"\"\"...\"\"\" % VAR` formatting expression on the docstring
    would null `__doc__`, stripping the MCP tool's description."""
    assert isinstance(server.tmux_read.__doc__, str)
    assert "recent pane" in server.tmux_read.__doc__


@pytest.mark.asyncio
async def test_tmux_exec_fuses_send_and_returns_command_output(monkeypatch) -> None:
    """The fused exec: one call snapshots the pane, sends the command, and
    returns just that command's output — halving the send+read round-trip that
    dominates long post-ex loops."""
    pane = {"text": "user@host:~$ "}

    async def _instant(_):
        return None

    async def _fake_tmux(*args):
        if args[0] == "capture-pane":
            return 0, pane["text"], ""
        if args[0] == "send-keys":
            command = args[3]  # ("send-keys","-t",name,command,"Enter")
            pane["text"] += command + "\nroot\nuser@host:~$ "
            return 0, "", ""
        return 0, "", ""

    monkeypatch.setattr(server.asyncio, "sleep", _instant)
    monkeypatch.setattr(server, "_tmux", _fake_tmux)
    server._REGISTRY.sessions["s"] = server.SessionState(name="s", kind="shell")

    res = await server.tmux_exec("s", "whoami", timeout_s=0.1)
    assert res["ok"] is True
    # The returned output is the command's result, not the stale baseline prompt.
    assert "root" in res["output"]
    assert res["new_output"] is True


@pytest.mark.asyncio
async def test_tmux_exec_honors_listener_guard(monkeypatch) -> None:
    """tmux_exec sends through tmux_send, so a listener that hasn't called back
    is still refused — no commands leak into nc's stdin."""
    async def _fake_tmux(*args):
        return 0, "listening...\n", ""

    monkeypatch.setattr(server, "_tmux", _fake_tmux)
    server._REGISTRY.sessions["lsn"] = server.SessionState(
        name="lsn", kind="listener", listening_on=4444,
    )
    res = await server.tmux_exec("lsn", "whoami")
    assert res["ok"] is False


@pytest.mark.asyncio
async def test_tmux_exec_unknown_session_errors_cleanly() -> None:
    res = await server.tmux_exec("nope", "whoami")
    assert res["ok"] is False
    assert "unknown session" in res["error"]
