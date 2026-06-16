"""Shell MCP server — owns ALL stateful processes via named tmux sessions.

msfconsole, evil-winrm, sliver-client, long-running scans, and
landed shells all live as named tmux sessions held here. The agent calls
`tmux_send(session_name, cmd)` / `tmux_read(session_name, timeout)` with
automatic prompt detection.

This is the single most important MCP server. Without it, multi-step exploits
become unreliable.
"""

from __future__ import annotations

import asyncio
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import JSONResponse

app = FastMCP(
    "shell",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
)

# How many lines of pane scrollback `tmux_read` captures. Bounded on purpose:
# capturing the whole 2000-line buffer made each read return tens of KB on a
# busy session, and since every model turn re-sends the full conversation, those
# reads accumulated into quadratic token cost. A few hundred lines covers the
# prompt + recent output; the agent saw earlier output in earlier reads.
_TMUX_SCROLLBACK_LINES = 500

# Default prompt patterns. The agent can override per-session if the target shell
# has a weird prompt.
DEFAULT_PROMPT_PATTERNS = [
    r"\$\s*$",
    r"#\s*$",
    r">\s*$",
    r"\)\s*>\s*$",  # msfconsole / sliver
    r"meterpreter\s*>\s*$",
    r"\?\s*$",
]


class SessionState(BaseModel):
    name: str
    kind: str = "generic"  # generic | listener | shell | meterpreter | sliver | scan
    created_at: float = Field(default_factory=time.time)
    last_seen_at: float = Field(default_factory=time.time)
    notes: str = ""
    prompt_patterns: list[str] = Field(default_factory=lambda: list(DEFAULT_PROMPT_PATTERNS))
    listening_on: int | None = None
    bound_to_engagement: str | None = None
    # Last full pane capture, kept so each `tmux_read` can compute `new_output`
    # (and serve `incremental=True` callers) by diffing against the previous
    # read. Excluded from model_dump so it never bloats `tmux_list_sessions`.
    last_read_buffer: str = Field(default="", exclude=True)
    # Sticky flag set the first time `tmux_read` detects an inbound connection
    # on a listener session. Used by `tmux_send` to refuse writes to a listener
    # that hasn't received a callback yet — typing into nc's stdin before a
    # client connects is the single most common exploit-subagent failure mode
    # (the bytes get silently buffered and the agent thinks the command
    # executed on the target).
    callback_received: bool = False
    # The `{peer_ip, peer_port}` latched the first time a connection is detected,
    # kept so `tmux_read`/`tmux_exec` can keep reporting a landed shell as
    # connected even after the netcat banner scrolls out of the capture window.
    # Re-scanning the visible pane every read makes `connection` flip back to
    # null once the banner scrolls off — which the agent misreads as a dropped
    # shell while it's still very much alive (commands return new output). This
    # makes `connection` a sticky "has this listener ever landed a shell?" signal.
    # Surfaced in `tmux_list_sessions` (it's tiny) so the agent can recover the
    # live shell's session name instead of guessing variants when it loses track.
    connection: dict[str, Any] | None = None


@dataclass
class _SessionRegistry:
    sessions: dict[str, SessionState] = field(default_factory=dict)


_REGISTRY = _SessionRegistry()


@dataclass
class CallbackEvent:
    ts: float
    method: str
    path: str
    client: str
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class CallbackServerState:
    name: str
    port: int
    server: asyncio.AbstractServer
    docroot: str | None = None
    events: list[CallbackEvent] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)


_CALLBACK_SERVERS: dict[str, CallbackServerState] = {}


async def _tmux(*args: str) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        "tmux", *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def _session_exists(name: str) -> bool:
    rc, _, _ = await _tmux("has-session", "-t", name)
    return rc == 0


# tmux key-name / caret notation for a single control or meta keystroke
# (`C-c`, `C-d`, `C-\`, `^C`, `M-x`). `tmux send-keys C-c` injects a *real*
# Ctrl-C, not the literal text — see `_is_control_keys`.
_CONTROL_KEY_RE = re.compile(r"^(C-[a-zA-Z\\]|\^[A-Za-z\\]|M-[a-zA-Z])$")


def _is_control_keys(command: str) -> bool:
    """True if `command` is *only* control/meta keystrokes — tmux key-names
    (`C-c`, `^C`, `C-c C-c`) or raw control bytes (`\\x03`, `\\x04`, `\\x1a`).

    These are the hazard on a listener pane: `tmux send-keys C-c` delivers an
    actual Ctrl-C to the pane's foreground process (the `nc` listener), tearing
    down the relayed target shell. A normal command (`whoami`, `cat x`) never
    matches, so the post-callback shell-driving path is unaffected."""
    s = command.strip()
    if not s:
        return False
    # Raw control bytes (Ctrl-C = \x03, Ctrl-D = \x04, Ctrl-Z = \x1a, ...).
    if all(ord(ch) < 0x20 for ch in s):
        return True
    return all(_CONTROL_KEY_RE.match(t) for t in s.split())


@app.tool()
async def tmux_new_session(name: str, kind: str = "generic", initial_command: str | None = None, engagement_id: str | None = None) -> dict[str, Any]:
    """Create a new named tmux session. Returns the session record."""
    if await _session_exists(name):
        return {"ok": False, "error": f"session {name!r} already exists"}
    rc, _, err = await _tmux("new-session", "-d", "-s", name)
    if rc != 0:
        return {"ok": False, "error": err.strip()}
    state = SessionState(name=name, kind=kind, bound_to_engagement=engagement_id)
    _REGISTRY.sessions[name] = state
    if initial_command:
        await _tmux("send-keys", "-t", name, initial_command, "Enter")
    return {"ok": True, "session": state.model_dump()}


@app.tool()
async def tmux_send(session_name: str, command: str, force: bool = False) -> dict[str, Any]:
    """Send a command into the session. Does NOT wait for output — call `tmux_read`.

    Listener guard: if `session_name` is a listener that hasn't received an
    inbound connection yet, this refuses by default. Sending shell commands
    to a listener pane (the bash session running `nc -lvnp ...`) is the
    most common exploit-subagent confusion — the bytes get typed into nc's
    stdin, silently buffered, and the agent thinks the target executed
    them. Pass `force=True` only if you specifically need to type into the
    listener-side bash (e.g. to send `Ctrl-C` and restart with new flags).
    """
    if session_name not in _REGISTRY.sessions:
        return {"ok": False, "error": f"unknown session {session_name!r}"}
    state = _REGISTRY.sessions[session_name]
    is_listener = state.kind == "listener" or state.listening_on is not None
    if is_listener and not state.callback_received and not force:
        return {
            "ok": False,
            "error": (
                f"REFUSED: {session_name!r} is a listener and no client has "
                "called back yet. Typing commands here writes to nc's stdin "
                "(silently buffered, never executed). Wait for `tmux_read` "
                "to report a non-null `connection` field — that's the "
                "deterministic 'shell landed' signal. To send commands to a "
                "Kali-local shell (Ctrl-C the listener, restart with new "
                "flags, etc.), pass `force=True`."
            ),
            "kind": "listener_no_callback",
        }
    # Even *after* a callback, the pane's foreground process is still the
    # listener (`nc`) relaying the target shell — a control keystroke goes to
    # `nc`, not to the remote command. Ctrl-C / Ctrl-D here tears down the
    # listener and kills the relayed shell (unrecoverable without a fresh
    # payload). This is exactly how a rooted box gets lost when the agent tries
    # to "clear a wedged pane". Refuse unless the caller really means to kill it.
    if is_listener and _is_control_keys(command) and not force:
        return {
            "ok": False,
            "error": (
                f"REFUSED: {command!r} is a control keystroke and {session_name!r} "
                "is a listener pane. It would hit the listener (`nc`), not the "
                "remote command — Ctrl-C/Ctrl-D tears down the listener and kills "
                "the relayed target shell, which cannot be reopened without firing "
                "a new payload. If the pane looks 'wedged', it is almost always "
                "blocked behind a foreground `sleep`/long command on the TARGET — "
                "do not interrupt it from here. Never `sleep N` in the target shell "
                "to wait for a cron/background job; return and poll the result with "
                "short `tmux_exec` checks instead (see skills/postex/privesc-verify). "
                "Pass force=True ONLY if you intend to kill this listener."
            ),
            "kind": "listener_control_key",
        }
    rc, _, err = await _tmux("send-keys", "-t", session_name, command, "Enter")
    if rc != 0:
        return {"ok": False, "error": err.strip()}
    state.last_seen_at = time.time()
    return {"ok": True}


@app.tool()
async def tmux_read(
    session_name: str,
    timeout_s: float = 5.0,
    wait_for_prompt: bool = True,
    max_bytes: int = 12000,
    incremental: bool = False,
) -> dict[str, Any]:
    """Read output from the session.

    Returns the **recent pane** (the last few hundred lines, tail-capped to
    `max_bytes`) so a read is always self-explanatory — it shows the prompt and
    recent output. It deliberately does NOT re-dump the whole scrollback: a
    shell that has produced a lot of output would otherwise return tens of KB on
    *every* read, and since each model turn re-sends the full conversation, that
    accumulates into quadratic token cost over a long session. You've already
    seen earlier output in earlier reads; this returns what's new/current.

    Use the separate `new_output` field (not an empty `output`) to tell whether
    anything changed since your last read: `new_output: false` means the command
    has settled / nothing new arrived, so re-reading won't help — act instead.

    `incremental=True` returns only the new suffix since the last read (handy for
    a chatty listener), but still never returns an empty string — it falls back
    to the recent pane when there's no delta. For genuinely large output, bound
    the command itself (`| head`, `| grep`) rather than raising `max_bytes`.

    With `wait_for_prompt`, polls until a known prompt pattern appears at the
    tail or `timeout_s` elapses. A listener also stops waiting the moment an
    inbound connection is detected.

    For listener sessions the result includes `connection` — `{peer_ip,
    peer_port}` once a client has connected, or `null` while still only
    listening. This is the deterministic "did the shell call back?" signal, and
    it is **sticky**: once a callback lands it stays non-null for the life of the
    session, even after the netcat banner scrolls out of view. So `connection`
    answers "has this listener ever landed a shell?", NOT "is the shell alive
    right now?" — judge liveness of an established shell by whether commands
    still return output (`new_output`), not by `connection`.
    """
    if session_name not in _REGISTRY.sessions:
        return {"ok": False, "error": f"unknown session {session_name!r}"}
    state = _REGISTRY.sessions[session_name]
    is_listener = state.kind == "listener" or state.listening_on is not None

    deadline = time.time() + timeout_s
    full = ""
    connection: dict[str, Any] | None = None
    timed_out = False
    while True:
        # Bounded scrollback: re-capturing 2000 lines on every read is what made
        # long shell sessions blow up token cost (the full buffer re-sent each
        # turn). The recent window + max_bytes keeps each read small and ~O(1).
        rc, out, err = await _tmux(
            "capture-pane", "-p", "-t", session_name, "-S", f"-{_TMUX_SCROLLBACK_LINES}"
        )
        if rc != 0:
            return {"ok": False, "error": err.strip()}
        full = out.rstrip("\n")

        if is_listener:
            fresh = _detect_listener_connection(full)
            if fresh and not state.callback_received:
                # Latch the sticky flag AND the peer — once a client has
                # connected, the `tmux_send` guard lifts and the agent can drive
                # the landed shell. We never clear this back to False (a
                # disconnected shell stays "ex-landed" for diagnostic
                # purposes; if the agent needs a fresh listener it should
                # tear this one down).
                state.callback_received = True
                state.connection = fresh
            # Report the LATCHED connection, not a fresh re-scan. The netcat
            # banner scrolls out of the capture window once the agent runs a few
            # commands in the landed shell; re-scanning would then return null
            # and the agent would misread a live shell as a dropped one. Sticky.
            connection = state.connection or fresh

        # Stop early on a settled prompt, or — for a listener — as soon as a
        # client connects (a listening nc never shows a prompt, so prompt-waiting
        # alone would always time out here).
        if not wait_for_prompt or connection or _ends_with_prompt(full, state.prompt_patterns):
            break
        if time.time() >= deadline:
            timed_out = True
            break
        await asyncio.sleep(0.25)

    prev_buffer = state.last_read_buffer
    delta = _incremental_delta(prev_buffer, full)
    state.last_read_buffer = full
    state.last_seen_at = time.time()
    # `new_output` drives the idle-read guard and the model's "did anything
    # change?" judgement. Compare the *visible-text* projection, not raw bytes:
    # a pane that merely redrew its prompt line (cursor moves, line-wrap
    # re-render on a wedged PTY) must NOT count as new output, or the agent
    # spin-polls a dead shell forever (each redraw looks like fresh bytes).
    new_output = _normalize_pane(prev_buffer) != _normalize_pane(full)

    # Default to the full pane: an empty incremental delta on a settled pane was
    # confusing the model into spin-reading. `new_output` carries the "did
    # anything change since last read?" signal independently — the idle-read
    # guard and the model both rely on it. Even when `incremental=True` is asked
    # for, never return an empty string; fall back to the full pane.
    body = delta if (incremental and delta.strip()) else full
    result: dict[str, Any] = {
        "ok": True,
        "output": body[-max_bytes:],
        "new_output": new_output,
        "timed_out": timed_out,
    }
    if is_listener:
        result["connection"] = connection
    return result


@app.tool()
async def tmux_exec(
    session_name: str,
    command: str,
    timeout_s: float = 10.0,
    max_bytes: int = 12000,
    force: bool = False,
) -> dict[str, Any]:
    """Run a command in a landed shell and return ITS output — in ONE call.

    This is the fused `tmux_send` + `tmux_read`: it snapshots the pane, sends the
    command, waits for the prompt to settle, and returns just what that command
    produced. **Prefer this for running commands and reading their output** — it
    halves the round-trips of driving a shell (one tool step instead of a
    send + a separate read), which keeps long post-ex/exploit phases short.

    Batch related checks into one call (`whoami /priv; whoami /groups; net user`)
    to cut steps further. Fall back to separate `tmux_send` + `tmux_read` only
    for genuinely interactive flows where you must type *mid-command* (a `su` /
    sudo password prompt, an msfconsole sub-prompt).

    Returns `{ok, output, new_output, timed_out}` (plus `connection` for
    listeners). The listener guard from `tmux_send` applies.
    """
    if session_name not in _REGISTRY.sessions:
        return {"ok": False, "error": f"unknown session {session_name!r}"}
    state = _REGISTRY.sessions[session_name]

    # Snapshot the pane so the returned delta is exactly this command's output.
    rc, out, _ = await _tmux(
        "capture-pane", "-p", "-t", session_name, "-S", f"-{_TMUX_SCROLLBACK_LINES}"
    )
    if rc == 0:
        state.last_read_buffer = out.rstrip("\n")

    sent = await tmux_send(session_name, command, force=force)
    if not sent.get("ok"):
        return sent

    await asyncio.sleep(0.3)  # let the command start before we wait on the prompt
    return await tmux_read(
        session_name,
        timeout_s=timeout_s,
        wait_for_prompt=True,
        max_bytes=max_bytes,
        incremental=True,  # delta vs the snapshot = just this command's output
    )


def _ends_with_prompt(text: str, patterns: list[str]) -> bool:
    tail = text.rstrip().splitlines()[-1] if text.strip() else ""
    return any(re.search(p, tail) for p in patterns)


# Lines a listener prints when a client connects. Covers the three nc/ncat
# variants we ship: GNU netcat-traditional, OpenBSD nc -v, and Ncat (nmap).
_CONNECT_PATTERNS = [
    re.compile(r"connect to \[[^\]]+\] from .*?\[?([\d.]+)\]?[ :](\d+)", re.I),
    re.compile(r"Connection received on ([\d.]+)\s+(\d+)", re.I),
    re.compile(r"Ncat: Connection from ([\d.]+):(\d+)", re.I),
]


def _detect_listener_connection(text: str) -> dict[str, Any] | None:
    """Return `{peer_ip, peer_port}` for the first inbound connection a listener
    reports in `text`, or None if it's still only listening.

    This is the deterministic "did the shell call back?" signal — without it the
    agent can only guess from raw pane text and tends to spin re-firing payloads.
    """
    for pat in _CONNECT_PATTERNS:
        m = pat.search(text)
        if m:
            return {"peer_ip": m.group(1), "peer_port": int(m.group(2))}
    return None


def _incremental_delta(prev: str, current: str) -> str:
    """Return the portion of `current` that is new since `prev`.

    Pane output is append-only in the common case, so when `current` extends
    `prev` we return only the suffix. If the scrollback has rolled (the 2000-line
    cap dropped old lines, so `current` no longer starts with `prev`), we can't
    safely diff and fall back to returning the whole buffer.
    """
    if prev and current.startswith(prev):
        return current[len(prev):]
    return current


# Strip ANSI/OSC escape sequences and stray control bytes so a pane is compared
# by its *visible text*, not its raw byte stream. A wedged PTY whose readline
# keeps re-rendering the same line (line-wrap redraw at the wrong COLUMNS) emits
# new bytes on every capture; without normalizing, `new_output` reports True
# forever and the idle-read guard never fires — the corrupted-shell spin that
# burned a whole engagement's budget. \t (09) and \n (0a) are kept.
_ANSI_OSC_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"            # CSI sequences (colour, cursor moves)
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"   # OSC sequences (title, etc.)
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f]"        # other C0 control bytes
)


def _normalize_pane(text: str) -> str:
    """Visible-text projection of a pane capture, for change detection only.

    Drops escape sequences and collapses all whitespace so a cosmetic redraw
    compares equal to what was there before. Never returned to the model — the
    model always gets the raw `output`.
    """
    return " ".join(_ANSI_OSC_RE.sub("", text).replace("\r", "").split())


@app.tool()
async def tmux_list_sessions() -> dict[str, Any]:
    """List all known sessions and their state."""
    rc, out, _ = await _tmux("list-sessions", "-F", "#{session_name}")
    live = {line.strip() for line in out.splitlines() if line.strip()} if rc == 0 else set()
    # Reconcile registry with reality.
    for name in list(_REGISTRY.sessions):
        if name not in live:
            _REGISTRY.sessions.pop(name)
    return {"sessions": [s.model_dump() for s in _REGISTRY.sessions.values()]}


# Internal helper only — intentionally NOT an `@app.tool()`. The agent is not
# given session-killing (it tended to kill load-bearing sessions — listeners,
# landed shells — prematurely). `run_oneshot` still uses this to clean up its
# own throwaway pane; the gateway purges all sessions between engagements via
# `_reset_all_sessions`.
async def tmux_kill_session(session_name: str) -> dict[str, Any]:
    if session_name not in _REGISTRY.sessions:
        return {"ok": False, "error": f"unknown session {session_name!r}"}
    rc, _, err = await _tmux("kill-session", "-t", session_name)
    if rc != 0:
        return {"ok": False, "error": err.strip()}
    _REGISTRY.sessions.pop(session_name, None)
    return {"ok": True}


@app.tool()
async def start_listener(kind: str, port: int, session_name: str | None = None) -> dict[str, Any]:
    """Spin up a listener in a tmux session.

    `kind`: `nc` | `metasploit` | `sliver`
    Returns the session name and listener metadata. Verifies the listener is
    bound by checking for the prompt to settle.
    """
    if session_name is None:
        session_name = f"listener-{kind}-{port}"
    if await _session_exists(session_name):
        return {"ok": False, "error": f"session {session_name!r} already exists"}

    if kind == "nc":
        cmd = f"rlwrap nc -lvnp {port}"
    elif kind == "metasploit":
        # The agent will configure exploit/payload via send-keys after this lands.
        cmd = "msfconsole -q"
    elif kind == "sliver":
        cmd = "sliver-client"
    else:
        return {"ok": False, "error": f"unknown listener kind {kind!r}"}

    result = await tmux_new_session(
        name=session_name,
        kind="listener",
        initial_command=cmd,
    )
    if not result.get("ok"):
        return result

    _REGISTRY.sessions[session_name].listening_on = port

    # Wait briefly for the listener to bind.
    await asyncio.sleep(1.5)
    read_result = await tmux_read(
        session_name=session_name, timeout_s=4.0, wait_for_prompt=False, incremental=False
    )
    return {
        "ok": True,
        "session_name": session_name,
        "kind": kind,
        "port": port,
        "initial_output": read_result.get("output", ""),
    }


@app.tool()
async def start_callback_server(
    port: int,
    name: str | None = None,
    docroot: str | None = "/tmp",
) -> dict[str, Any]:
    """Start a tiny HTTP callback/file server and record every request.

    This is a structured replacement for `python3 -m http.server` when proving
    blind RCE or staging small files. Requests are logged in memory and can be
    queried with `wait_callback` / `callback_events`.

    `docroot` may be `null` to disable file serving. When enabled, only files
    under that directory are served; missing paths return 404 but are still
    recorded as callback evidence.
    """
    if name is None:
        name = f"callback-{port}"
    if name in _CALLBACK_SERVERS:
        return {"ok": False, "error": f"callback server {name!r} already exists"}

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        client = str(peer[0]) if peer else ""
        try:
            data = await asyncio.wait_for(reader.read(65536), timeout=5.0)
            text = data.decode(errors="replace")
            lines = text.splitlines()
            request_line = lines[0] if lines else ""
            parts = request_line.split()
            method = parts[0] if len(parts) >= 1 else ""
            raw_path = parts[1] if len(parts) >= 2 else "/"
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if not line.strip():
                    break
                key, sep, value = line.partition(":")
                if sep:
                    headers[key.strip().lower()] = value.strip()

            state = _CALLBACK_SERVERS.get(name)
            if state is not None:
                state.events.append(
                    CallbackEvent(
                        ts=time.time(),
                        method=method,
                        path=raw_path,
                        client=client,
                        headers=headers,
                    )
                )

            status = "404 Not Found"
            body = b"not found\n"
            content_type = "text/plain"
            if docroot:
                parsed = urllib.parse.urlparse(raw_path)
                rel = urllib.parse.unquote(parsed.path).lstrip("/")
                candidate = (Path(docroot) / rel).resolve()
                root = Path(docroot).resolve()
                if candidate.is_file() and root in candidate.parents:
                    body = candidate.read_bytes()
                    status = "200 OK"
                    content_type = "application/octet-stream"
            response = (
                f"HTTP/1.1 {status}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Type: {content_type}\r\n"
                "Connection: close\r\n\r\n"
            ).encode() + body
            writer.write(response)
            await writer.drain()
        except Exception:
            # Keep the callback server alive even for malformed probes.
            try:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    try:
        server = await asyncio.start_server(_handle, host="0.0.0.0", port=port)
    except OSError as exc:
        return {"ok": False, "error": f"could not bind callback server on port {port}: {exc}"}

    _CALLBACK_SERVERS[name] = CallbackServerState(
        name=name,
        port=port,
        server=server,
        docroot=docroot,
    )
    return {"ok": True, "name": name, "port": port, "docroot": docroot}


def _callback_event_dict(event: CallbackEvent, idx: int) -> dict[str, Any]:
    return {
        "index": idx,
        "ts": event.ts,
        "method": event.method,
        "path": event.path,
        "client": event.client,
        "headers": event.headers,
    }


def _event_matches(event: CallbackEvent, patterns: list[str]) -> bool:
    if not patterns:
        return True
    haystack = f"{event.method} {event.path} {event.client}"
    return any(re.search(pattern, haystack) for pattern in patterns)


@app.tool()
async def wait_callback(
    name: str,
    patterns: list[str] | None = None,
    timeout_s: float = 10.0,
    since_index: int = 0,
) -> dict[str, Any]:
    """Wait for a recorded callback request matching any regex pattern."""
    if name not in _CALLBACK_SERVERS:
        return {"ok": False, "error": f"unknown callback server {name!r}"}
    pats = patterns or []
    deadline = time.time() + timeout_s
    state = _CALLBACK_SERVERS[name]
    while True:
        for idx, event in enumerate(state.events[since_index:], start=since_index):
            if _event_matches(event, pats):
                return {
                    "ok": True,
                    "matched": True,
                    "event": _callback_event_dict(event, idx),
                    "event_count": len(state.events),
                }
        if time.time() >= deadline:
            return {
                "ok": True,
                "matched": False,
                "event_count": len(state.events),
                "events": [
                    _callback_event_dict(event, idx)
                    for idx, event in enumerate(state.events[since_index:], start=since_index)
                ],
            }
        await asyncio.sleep(0.25)


@app.tool()
async def callback_events(name: str, since_index: int = 0) -> dict[str, Any]:
    """Return callback/file-server request history."""
    if name not in _CALLBACK_SERVERS:
        return {"ok": False, "error": f"unknown callback server {name!r}"}
    state = _CALLBACK_SERVERS[name]
    return {
        "ok": True,
        "name": name,
        "port": state.port,
        "docroot": state.docroot,
        "event_count": len(state.events),
        "events": [
            _callback_event_dict(event, idx)
            for idx, event in enumerate(state.events[since_index:], start=since_index)
        ],
    }


def _cookies_from_netscape_cookie_jar(path: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return cookies
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#HttpOnly_"):
            line = line.removeprefix("#HttpOnly_")
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            cookies[parts[5]] = parts[6]
    return cookies


_DEFAULT_RESPONSE_HEADERS = {
    "content-type",
    "content-length",
    "location",
    "server",
}


def _compact_response_headers(headers: httpx.Headers, *, include_headers: bool) -> dict[str, str]:
    if include_headers:
        return dict(headers)
    return {
        key: value
        for key, value in headers.items()
        if key.lower() in _DEFAULT_RESPONSE_HEADERS
    }


def _write_netscape_cookie_jar(path: str, cookies: Any) -> list[str]:
    """Persist response cookies in curl/Netscape format and return cookie names."""
    names: list[str] = []
    lines = ["# Netscape HTTP Cookie File\n"]
    for cookie in cookies:
        names.append(cookie.name)
        domain = cookie.domain or ""
        include_subdomains = "TRUE" if domain.startswith(".") else "FALSE"
        cookie_path = cookie.path or "/"
        secure = "TRUE" if cookie.secure else "FALSE"
        expires = str(cookie.expires or 0)
        lines.append(
            "\t".join([
                domain,
                include_subdomains,
                cookie_path,
                secure,
                expires,
                cookie.name,
                cookie.value,
            ]) + "\n"
        )
    Path(path).write_text("".join(lines))
    return names


@app.tool()
async def http_json_request(
    url: str,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | list[Any] | None = None,
    cookie_jar: str | None = None,
    timeout_s: float = 20.0,
    max_body_chars: int = 8192,
    include_headers: bool = False,
) -> dict[str, Any]:
    """Send an HTTP request with a structured JSON body.

    Use this instead of shell-quoted `curl -d '{...}'` when the payload itself
    contains nested JavaScript, shell metacharacters, or quotes.
    """
    request_headers = dict(headers or {})
    cookies = _cookies_from_netscape_cookie_jar(cookie_jar) if cookie_jar else None
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout_s) as client:
            resp = await client.request(
                method.upper(),
                url,
                headers=request_headers,
                json=json_body,
                cookies=cookies,
            )
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"request to {url!r} failed: {type(exc).__name__}: {exc}"}

    cookie_names: list[str] = []
    if cookie_jar:
        response_cookies = list(resp.cookies.jar)
        if response_cookies:
            try:
                cookie_names = _write_netscape_cookie_jar(cookie_jar, response_cookies)
            except OSError as exc:
                return {"ok": False, "error": f"could not write cookie jar {cookie_jar!r}: {exc}"}

    return {
        "ok": True,
        "status_code": resp.status_code,
        "headers": _compact_response_headers(resp.headers, include_headers=include_headers),
        "cookie_jar": cookie_jar,
        "cookie_names": cookie_names,
        "body": resp.text[:max_body_chars],
        "body_truncated": len(resp.text) > max_body_chars,
        "elapsed_ms": int(resp.elapsed.total_seconds() * 1000),
    }


@app.tool()
async def stabilize_shell(session_name: str) -> dict[str, Any]:
    """Upgrade a raw reverse shell to a usable PTY — automation-safe.

    We deliberately do NOT run the classic interactive operator dance
    (`Ctrl-Z; stty raw -echo; fg; reset`). That sequence is for a *human's local
    terminal*: `stty raw -echo` puts the operator's tty in raw mode and `reset`
    reinitializes it. Driven through tmux send-keys there is no such operator
    tty — and `reset`/raw mode make the terminal emit a Cursor-Position-Report
    query (`ESC[6n`) whose response (`ESC[<row>;<col>R`) gets injected into the
    shell's stdin, surfacing as `;5R`-style garbage that corrupts the next
    command (`/bin/sh: syntax error: unexpected ";"`). Observed destabilizing a
    freshly-landed target shell.

    `pty.spawn` alone gives the things that actually matter for automation: a
    real TTY on the target (so `su`/`sudo`/job control/signals work) and correct
    Ctrl-C handling (tmux `C-c` → SIGINT to the foreground process, not killing
    the listener). We then just set TERM and a sane window size — no raw, no fg,
    no reset.
    """
    if session_name not in _REGISTRY.sessions:
        return {"ok": False, "error": f"unknown session {session_name!r}"}

    # 1. Upgrade to a PTY (python3, then python2 fallback).
    await _tmux(
        "send-keys", "-t", session_name,
        "python3 -c 'import pty; pty.spawn(\"/bin/bash\")' "
        "|| python -c 'import pty; pty.spawn(\"/bin/bash\")'",
        "Enter",
    )
    await asyncio.sleep(1.5)

    # 2. Minimal env — TERM=xterm (basic; avoids the fancy terminal queries that
    #    `xterm-256color` + `reset` trigger) and SHELL.
    await _tmux("send-keys", "-t", session_name, "export TERM=xterm SHELL=/bin/bash", "Enter")
    await asyncio.sleep(0.3)

    # 3. Set a sane window size so full-screen tools render — NOT raw mode.
    #    Errors are suppressed (some busybox stty lacks rows/columns).
    await _tmux("send-keys", "-t", session_name, "stty rows 50 columns 200 2>/dev/null", "Enter")
    await asyncio.sleep(0.3)

    # 4. Health probe: echo a unique token and confirm it comes back CLEANLY.
    #    A live PTY echoes the token twice — once as command input, once as the
    #    command's own output. A wedged shell (line-wrap redraw, dead pipe) shows
    #    it zero or one times, or mangled. This is the deterministic "is this
    #    shell actually usable?" signal — without it the agent can't tell a
    #    stabilized shell from a corrupted one and spin-polls the dead pane.
    token = f"VSHEALTH{int(time.time() * 1000) % 1_000_000}"
    await _tmux("send-keys", "-t", session_name, f"echo {token}", "Enter")
    await asyncio.sleep(0.5)
    final = await tmux_read(
        session_name=session_name, timeout_s=4.0, wait_for_prompt=True, incremental=False
    )
    out = final.get("output", "")
    healthy = _normalize_pane(out).count(token) >= 2 and not final.get("timed_out", True)
    result: dict[str, Any] = {
        "ok": True,
        "final_output": out,
        "stabilized": not final.get("timed_out", True),
        "healthy": healthy,
    }
    if not healthy:
        result["hint"] = (
            "Shell appears WEDGED — the health-probe token did not echo back "
            "cleanly. Do NOT keep driving this pane (re-reading/re-sending will "
            "not recover it). Re-establish a fresh shell: re-fire your payload "
            "to a NEW listener session, or hand back to the orchestrator with "
            "the evidence you already have."
        )
    return result


@app.tool()
async def run_oneshot(command: str, timeout_s: float = 60.0) -> dict[str, Any]:
    """Fire-and-forget command for stateless work that doesn't need a session.

    Useful for things the agent treats as a single sync call (`whoami`, etc.).
    Internally uses a throwaway tmux pane so output capture is consistent.
    """
    name = f"oneshot-{int(time.time() * 1000)}"
    res = await tmux_new_session(name=name, kind="generic")
    if not res.get("ok"):
        return res
    await tmux_send(name, command)
    read = await tmux_read(name, timeout_s=timeout_s, wait_for_prompt=True, incremental=False)
    await tmux_kill_session(name)
    return read


async def _reset_all_sessions() -> dict[str, Any]:
    """Kill every live tmux session and clear the registry.

    Called by the gateway at the start of each new engagement so the shell
    container doesn't carry listeners, msfconsole sessions, or landed shells
    from a previous engagement into the next one. Idempotent.
    """
    rc, out, _ = await _tmux("list-sessions", "-F", "#{session_name}")
    live = (
        [line.strip() for line in out.splitlines() if line.strip()]
        if rc == 0
        else []
    )
    killed: list[str] = []
    for name in live:
        kill_rc, _, _ = await _tmux("kill-session", "-t", name)
        if kill_rc == 0:
            killed.append(name)
    _REGISTRY.sessions.clear()
    callbacks = list(_CALLBACK_SERVERS)
    for state in list(_CALLBACK_SERVERS.values()):
        state.server.close()
        await state.server.wait_closed()
    _CALLBACK_SERVERS.clear()
    return {"ok": True, "killed": killed, "count": len(killed), "callbacks_closed": callbacks}


@app.custom_route("/admin/reset", methods=["POST"])
async def admin_reset(request: Request) -> JSONResponse:
    """Operator-facing reset endpoint. Not part of the MCP tool surface — the
    gateway calls this directly at engagement start so the agent can't
    accidentally trigger it mid-engagement via a hallucinated tool call."""
    result = await _reset_all_sessions()
    return JSONResponse(result)


def main() -> None:
    app.run(transport="streamable-http")


if __name__ == "__main__":
    main()
