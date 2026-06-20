"""Tests for the subagent no-progress guard.

Reproduces the real failure mode: a low-priv shell brute-guessing file paths —
`type "<path A>"`, `type "<path B>"`, ... — every call a distinct string, every
read fresh output, so neither repeat_guard nor idle_read_guard fires. The guard
must break the flail after N same-verb sends, leave a rotating enum sweep alone,
reset on a finding, and reset after the one-shot nudge so the session stays
usable.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from src.agent.middleware.no_progress_guard import _command_signature, no_progress_guard


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name: str, args: dict, call_id: str = "c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": args, "id": call_id},
    )


def _ok_handler():
    calls: list[dict] = []

    async def handler(request):
        calls.append({"name": request.tool.name, **request.tool_call["args"]})
        return SimpleNamespace(content='{"ok": true}', name=request.tool.name, status="success")

    return handler, calls


def _send(verb_path: str, session: str = "foothold_listener"):
    return _request("shell__tmux_send", {"session_name": session, "command": verb_path})


# --- deterministic helper --------------------------------------------------

def test_command_signature_single_verb():
    assert _command_signature('type "C:\\Users\\babis\\Desktop\\user.txt"') == ("type",)
    assert _command_signature("  whoami /priv ") == ("whoami",)
    assert _command_signature("Get-Content x") == ("get-content",)
    assert _command_signature("clear; curl -sSk http://target") == ("curl",)
    assert _command_signature("reset; clear; curl -sSk http://target") == ("curl",)
    assert _command_signature("timeout 3 bash -c 'id'") == ("bash",)
    assert _command_signature("env FOO=bar curl http://target") == ("curl",)
    assert _command_signature("") == ()


def test_command_signature_ignores_echo_markers_and_batches():
    # the reported false positive: a batched enum sweep delimited by `echo CN;`
    # markers is keyed by its real verbs, not by the leading `echo`.
    sig = _command_signature(
        "echo C1; cat /var/spool/cron/root 2>/dev/null; echo C2; "
        "ls -la /var/spool/cron/ 2>/dev/null; echo C3; cat /etc/cron.d/0hourly"
    )
    assert sig == ("cat", "ls")  # echo dropped, 2>&1-style redirs intact
    # a command that is only markers/plumbing carries no enumeration intent
    assert _command_signature("echo C1") == ()
    assert _command_signature("clear; echo done") == ()
    # pipelines contribute every meaningful verb
    assert _command_signature("grep -ri pass /etc | head -30") == ("grep", "head")


# --- behaviour -------------------------------------------------------------

def test_blocks_same_verb_flail_after_threshold():
    guard = no_progress_guard(max_sends=6)
    handler, calls = _ok_handler()

    # Six distinct `type` commands all reach the handler.
    for i in range(6):
        res = _run(guard.awrap_tool_call(_send(f'type "C:\\x\\f{i}.txt"'), handler))
        assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", "")
    assert len(calls) == 6

    # The seventh same-verb send is blocked before reaching the handler.
    res = _run(guard.awrap_tool_call(_send('type "C:\\x\\f7.txt"'), handler))
    assert len(calls) == 6
    assert res.status == "error"
    assert "NO_PROGRESS_BLOCKED" in res.content


def test_rotating_verbs_never_trip():
    guard = no_progress_guard(max_sends=6)
    handler, calls = _ok_handler()

    # A normal enum sweep rotates the verb — the streak never accumulates.
    verbs = ["whoami /priv", "hostname", "dir C:\\", "systeminfo", "net user",
             "reg query HKLM", "ipconfig /all", "tasklist", "whoami /groups"]
    for cmd in verbs:
        res = _run(guard.awrap_tool_call(_send(cmd), handler))
        assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", "")
    assert len(calls) == len(verbs)


def test_echo_delimited_enum_sweep_never_trips():
    # The reported false positive: every batched enum command leads with an
    # `echo CN;` marker. Keyed by real verbs the signatures differ, so distinct
    # enumeration work is never mistaken for a repeated `echo` flail.
    guard = no_progress_guard(max_sends=6)
    handler, calls = _ok_handler()

    batches = [
        "echo C1; cat /var/spool/cron/root; echo C2; ls -la /var/spool/cron/",
        "echo C1; cat /etc/cron.d/0hourly; echo C2; ls -la /etc/cron.d/",
        "echo C1; crontab -l; echo C2; ls -la /etc/cron.daily/",
        "echo C1; stat /usr/sbin/fwconsole; echo C2; getcap -r / 2>/dev/null",
        "echo C1; find / -writable -type f 2>/dev/null | head; echo C2; id",
        "echo C1; cat /etc/passwd; echo C2; sudo -n -l",
        "echo C1; ps aux; echo C2; ss -ltnp",
        "echo C1; uname -a; echo C2; cat /etc/os-release",
    ]
    for cmd in batches:
        res = _run(guard.awrap_tool_call(_send(cmd), handler))
        assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", ""), cmd
    assert len(calls) == len(batches)


def test_batched_sweep_same_verbset_still_flails():
    # ... but repeating the *same* verb-set on tweaked paths is still a flail.
    guard = no_progress_guard(max_sends=3)
    handler, _ = _ok_handler()
    for i in range(3):  # signature ('cat', 'ls') three times
        res = _run(guard.awrap_tool_call(
            _send(f"echo M; cat /a{i}; echo N; ls -la /b{i}"), handler))
        assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", "")
    blocked = _run(guard.awrap_tool_call(_send("echo M; cat /a4; echo N; ls -la /b4"), handler))
    assert blocked.status == "error"
    assert "NO_PROGRESS_BLOCKED" in blocked.content


def test_verb_change_resets_the_streak():
    guard = no_progress_guard(max_sends=3)
    handler, _ = _ok_handler()

    # Three `type`, then a different verb, then three more `type` — the switch
    # resets the streak so neither run reaches the block.
    for cmd in ['type "a"', 'type "b"', 'type "c"', "dir C:\\", 'type "d"', 'type "e"', 'type "f"']:
        res = _run(guard.awrap_tool_call(_send(cmd), handler))
        assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", "")


def test_finding_resets_all_sessions():
    guard = no_progress_guard(max_sends=3)
    handler, _ = _ok_handler()

    for cmd in ['type "a"', 'type "b"', 'type "c"']:
        _run(guard.awrap_tool_call(_send(cmd), handler))
    # A confirmed finding clears the flail window.
    _run(guard.awrap_tool_call(_request("episodes__write_finding", {"title": "creds"}), handler))
    # Three more same-verb sends are fine again — no block.
    for cmd in ['type "d"', 'type "e"', 'type "f"']:
        res = _run(guard.awrap_tool_call(_send(cmd), handler))
        assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", "")


def test_block_resets_so_session_stays_usable():
    guard = no_progress_guard(max_sends=3)
    handler, calls = _ok_handler()

    for cmd in ['type "a"', 'type "b"', 'type "c"']:
        _run(guard.awrap_tool_call(_send(cmd), handler))
    blocked = _run(guard.awrap_tool_call(_send('type "d"'), handler))
    assert "NO_PROGRESS_BLOCKED" in blocked.content
    # After the nudge the counter resets — the next send runs again.
    res = _run(guard.awrap_tool_call(_send('type "e"'), handler))
    assert "NO_PROGRESS_BLOCKED" not in res.content
    assert {"name": "shell__tmux_send", "session_name": "foothold_listener", "command": 'type "e"'} in calls


def test_per_session_streaks_are_independent():
    guard = no_progress_guard(max_sends=3)
    handler, _ = _ok_handler()

    # Same verb, two sessions, interleaved — neither reaches 4 in a row.
    for _ in range(3):
        for sess in ("s1", "s2"):
            res = _run(guard.awrap_tool_call(_send('type "x"', session=sess), handler))
            assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", "")


def test_iterative_tools_are_never_blocked():
    # Credential spraying / brute / probing run many times by design — not a
    # flail. sshpass with 20 different creds must all pass through.
    guard = no_progress_guard(max_sends=6)
    handler, calls = _ok_handler()
    for i in range(20):
        res = _run(guard.awrap_tool_call(
            _send(f"sshpass -p pw{i} ssh user@10.10.10.5"), handler))
        assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", ""), f"blocked at {i}"
    assert len(calls) == 20


def test_other_iterative_verbs_exempt():
    guard = no_progress_guard(max_sends=3)
    handler, _ = _ok_handler()
    for verb in ("hydra", "crackmapexec", "nc", "curl", "ssh", "nxc"):
        for _ in range(5):
            res = _run(guard.awrap_tool_call(_send(f"{verb} 10.10.10.5 -x foo"), handler))
            assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", ""), verb


def test_msfconsole_set_config_is_exempt():
    # The reported false positive: configuring a Metasploit module sends many
    # `set <OPT> <val>` lines in a row. Each is productive config, not a flail —
    # the whole sequence must pass through regardless of threshold.
    guard = no_progress_guard(max_sends=6)
    handler, calls = _ok_handler()
    config = [
        "set RHOSTS 10.129.31.113", "set VHOST cctv.htb", "set RPORT 80",
        "set TARGETURI /zm/", "set SSL false", "set LHOST 10.10.16.162",
        "set LPORT 4444", "set TARGET 0", "set FETCH_WRITABLE_DIR /tmp",
        "setg RHOSTS 10.129.31.113", "unset SSL",
    ]
    for cmd in config:
        res = _run(guard.awrap_tool_call(_send(cmd, session="msf-main"), handler))
        assert "NO_PROGRESS_BLOCKED" not in getattr(res, "content", ""), cmd
    assert len(calls) == len(config)


def test_iterative_interlude_does_not_reset_file_flail():
    # An exempt command between file-read sends doesn't mask the flail: the
    # `cat` streak still accumulates across an sshpass interlude.
    guard = no_progress_guard(max_sends=3)
    handler, _ = _ok_handler()
    for cmd in ('cat /a', 'cat /b', 'sshpass -p x ssh u@h', 'cat /c'):
        _run(guard.awrap_tool_call(_send(cmd), handler))
    res = _run(guard.awrap_tool_call(_send('cat /d'), handler))  # 4th cat
    assert res.status == "error"
    assert "NO_PROGRESS_BLOCKED" in res.content


def test_default_threshold_is_lenient():
    import inspect

    from src.agent.middleware.no_progress_guard import no_progress_guard as npg
    assert inspect.signature(npg).parameters["max_sends"].default == 8
