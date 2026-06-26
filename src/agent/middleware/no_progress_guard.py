"""Guard against semantically-repetitive flailing in a shell session.

The real failure this catches: a low-priv foothold (e.g. an IIS service account)
that wants a file it can't read, and instead of recognising the permission wall
spams the *same kind* of command with different arguments —

    type "C:\\Users\\babis\\Desktop\\user.txt.xyz"      -> Access is denied
    type "C:\\Users\\babis\\Desktop\\randomXYZ\\x.txt"  -> path not found
    type "C:\\Users\\babis\\Desktop\\zz_no_dir\\f.txt"  -> path not found
    ... (forever)

Every call is a *different* command string and every read returns *fresh*
output, so this slips past both `repeat_guard` (needs identical failing calls)
and `idle_read_guard` (needs empty reads). `stuck_detector` is on the
orchestrator loop and never sees a subagent's tool calls. Nothing breaks it.

This middleware counts *consecutive* `shell__tmux_send` calls per session that
run the **same kind of command**. The "kind" is a *signature* — the sorted set
of meaningful verbs in the command, with trivial markers/plumbing (`echo`,
`printf`, `clear`, `cd`, ...) dropped — so a batched sweep is identified by its
real work, not the `echo CN;` section markers the model prefixes to it
(`echo C1; cat a; echo C2; ls b` -> `('cat', 'ls')`, NOT `echo`). After
`max_sends` consecutive same-signature sends it returns a directive telling the
model to stop guessing and either enumerate properly or hand back. Keying on the
signature is deliberate: a legitimate enum sweep rotates the work (`whoami` ->
`dir` -> `systeminfo` -> `reg query`) and never accumulates, while flailing
hammers one kind. A `write_finding` (real progress) resets every session's
counter.

Some tools, though, are *designed* to be run many times with varying arguments
— credential spraying (`sshpass`, `hydra`, `crackmapexec`), password cracking,
network probing (`nc`, `curl`). Running `sshpass` 8 times with 8 different
credentials is productive work, not a flail, so those verbs are exempted (see
`_ITERATIVE_VERBS`); otherwise the guard cuts off a legitimate spray. This guard
only targets the "guess the same thing with a tweaked path and get nowhere"
pattern (file-read / enumeration verbs), not iterative offensive tooling.
"""

from __future__ import annotations

import re

# Verbs that are *meant* to be run repeatedly with different args — credential
# testing/spraying, brute-force, cracking, and network probing. Repetition here
# is the intended workflow, not a stuck loop, so they never count toward the
# flail streak.
_ITERATIVE_VERBS = frozenset({
    # credential testing / spraying / brute-force
    "sshpass", "ssh", "hydra", "medusa", "ncrack", "patator", "crowbar", "kerbrute",
    "crackmapexec", "cme", "nxc", "netexec",
    "smbclient", "smbmap", "rpcclient", "evil-winrm", "wmiexec.py", "psexec.py",
    "mysql", "psql", "mssqlclient.py", "mssqlclient", "redis-cli", "mongo", "mongosh",
    "ldapsearch", "kinit", "getnpusers.py", "getuserspns.py",
    # password cracking
    "john", "hashcat",
    # network probing, run repeatedly by design
    "nc", "ncat", "curl", "wget", "ping",
})


# Configuration verbs for interactive consoles (msfconsole, sliver, ...) that
# are *meant* to be issued many times in a row with different args to set up a
# module before running it: `set RHOSTS ...`, `set VHOST ...`, `set LHOST ...`,
# `setg ...`, `unset ...`. Each line is a distinct, productive config step, not a
# flail — exempt them exactly like the iterative tools above so configuring a
# module across N sends never trips the guard.
_CONFIG_VERBS = frozenset({
    "set", "setg", "unset", "unsetg",
})


# Verbs that carry no enumeration intent — output markers and shell plumbing.
# The model routinely delimits a batched sweep with `echo CN;` section markers
# (`echo C1; cat a; echo C2; ls b`); keying the streak on the leading token then
# lumped every unrelated enum command together as one repeated `echo` and tripped
# the guard on legitimate work. These are dropped before computing the signature.
_TRIVIAL_VERBS = frozenset({
    "echo", "printf", "clear", "reset", "true", ":", "cd", "pwd", "export",
})

# Shell statement separators: `;`, `&&`, `||`, `|`. Deliberately NOT bare `&`,
# so a redirection like `2>&1` is left intact.
_SEGMENT_SEP = re.compile(r";|&&|\|\|?")


def _segment_verb(segment: str) -> str:
    """Leading token of one shell statement, lowercased, unwrapping `timeout`/`env`."""
    parts = segment.strip().split()
    if not parts:
        return ""
    first = parts[0].lower()
    if first == "timeout":
        for part in parts[1:]:
            if part.startswith("-") or part.replace(".", "", 1).isdigit():
                continue
            return part.lower()
    elif first == "env":
        for part in parts[1:]:
            if "=" in part:
                continue
            return part.lower()
    return first


def _command_signature(command: str) -> tuple[str, ...]:
    """The coarse 'kind' of a (possibly batched) command: the sorted set of its
    meaningful verbs, with trivial markers/plumbing dropped.

    A single flailed command -> a 1-verb signature (`('type',)`), so a real flail
    still accumulates. A batched sweep -> its full verb set (`('cat', 'ls')`), so
    two consecutive sweeps only count toward the same streak when they do the
    *same kind* of work — `echo` markers no longer collapse distinct commands
    into one streak. A command that is only markers/plumbing -> an empty tuple."""
    verbs: list[str] = []
    for segment in _SEGMENT_SEP.split(command):
        verb = _segment_verb(segment)
        if verb and verb not in _TRIVIAL_VERBS and verb not in verbs:
            verbs.append(verb)
    return tuple(sorted(verbs))


def no_progress_guard(max_sends: int = 8, grind_ceiling: int = 30):
    """Break loops where a subagent spams one kind of command with no finding.

    Two complementary counters, both reset by a confirmed `write_finding`:

    * **Per-session signature streak** (`max_sends`) — catches *hammering one
      kind* of command (the `type X.xyz`/`type Y/z.txt`/... permission-wall
      flail): N consecutive same-signature sends to a session.
    * **Cross-session grind ceiling** (`grind_ceiling`) — catches a grind that
      *rotates what it does* but still makes no progress. The expensive real
      failure (e.g. a scheduled-task privesc poked via powershell → schtasks →
      certipy → IEX → dir → ... for 100+ commands) changes its verb signature
      almost every send, so the streak counter resets to 1 each time and never
      trips. This counts *every* meaningful command across all sessions since the
      last finding; past the ceiling it nudges the model to hand back rather than
      keep churning. Iterative verbs (cred spray / cracking / probing) are
      exempt from BOTH counters so a legitimate long spray isn't cut off.

    Deterministic — the prompt can tell the model to step back and enumerate,
    but this stops the flail regardless. Attach one instance per subagent loop
    that drives `shell__tmux_send` (postex, exploit).
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    # session -> (signature, consecutive count)
    streaks: dict[str, tuple[tuple[str, ...], int]] = {}
    # meaningful commands sent (any session) since the last confirmed finding.
    grind = {"count": 0, "nudged_at": 0}

    class NoProgressGuard(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            tool_name = getattr(tool, "name", "") or ""

            # A confirmed finding means real progress — clear both windows.
            if tool_name == "episodes__write_finding":
                streaks.clear()
                grind["count"] = 0
                grind["nudged_at"] = 0
                return await handler(request)

            # tmux_exec is the fused send+read (the preferred command path); it
            # carries the same `command` arg, so a flail through exec must count
            # toward the same streak as one through send.
            if tool_name not in ("shell__tmux_send", "shell__tmux_exec"):
                return await handler(request)

            tool_call = getattr(request, "tool_call", {}) or {}
            args = tool_call.get("args", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""
            session = str(args.get("session_name", ""))
            signature = _command_signature(str(args.get("command", "")))

            # A command that's only markers/plumbing (a bare `echo`/`clear`/`cd`)
            # does no enumeration work — never count it toward a flail streak, and
            # don't reset an existing one.
            if not signature:
                return await handler(request)

            # Credential spraying / brute-force / probing tools — and interactive
            # console config verbs (msfconsole `set`/`setg`/...) — are meant to run
            # many times with different args; that's the workflow, not a flail.
            # Pass through without counting so we never cut off a legit spray or
            # the multi-`set` configuration of a Metasploit module.
            if any(verb in _ITERATIVE_VERBS or verb in _CONFIG_VERBS for verb in signature):
                return await handler(request)

            prev_sig, count = streaks.get(session, ((), 0))
            count = count + 1 if signature == prev_sig else 1

            if count > max_sends:
                # One-shot nudge then reset, so the session stays usable the
                # moment the model changes tack.
                streaks[session] = (signature, 0)
                kinds = ", ".join(f"`{verb}`" for verb in signature)
                return ToolMessage(
                    content=(
                        f"NO_PROGRESS_BLOCKED: the same command ({kinds}) has been sent "
                        f"to session {session!r} {max_sends} times in a row with no new finding. "
                        "Different arguments to the same command is not progress. "
                        "Stop and re-read the last outputs. If you have confirmed a "
                        "useful primitive (for example RCE) but the next phase is "
                        "failing, return a structured partial-success result with the "
                        "evidence and blocker. Otherwise change technique materially "
                        "before sending another command."
                    ),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                    status="error",
                )

            # Cross-session grind ceiling: many *different* commands, no finding.
            grind["count"] += 1
            if grind["count"] - grind["nudged_at"] > grind_ceiling:
                grind["nudged_at"] = grind["count"]
                return ToolMessage(
                    content=(
                        f"NO_PROGRESS_BLOCKED: {grind['count']} shell commands have run "
                        "with no confirmed finding recorded. Rotating *which* command you "
                        "run is not progress if none of it lands. Re-read what you already "
                        "know: if you have CONFIRMED the exploitation/privesc vector but "
                        "can't fire it, STOP and return your structured result now — a "
                        "partial-success (RCE/vector confirmed + blocker) or a "
                        "`research_needed` entry naming the exact vector. Only keep going "
                        "if you have a genuinely new, untried hypothesis."
                    ),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                    status="error",
                )

            streaks[session] = (signature, count)
            return await handler(request)

    return NoProgressGuard()
