"""Deterministic Rules-of-Engagement gate.

The model never decides whether a target is in scope. This middleware extracts the
target host/IP from every tool call and matches against the engagement allowlist
with `ipaddress.ip_network`. Anything off-list is blocked before the tool runs.

Per the plan §1.9 — "the one piece I'd refuse to compromise on."
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ...schemas.engagement import RulesOfEngagement

# Patterns that catch hosts/IPs anywhere in a tool's string arguments.
_IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_HOSTNAME_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)
_URL_PATTERN = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
_CIDR_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/\d{1,2}\b"
)

# Suffixes that look like a TLD to `_HOSTNAME_PATTERN` but are really file
# extensions the agent mentions in prose (e.g. "examine config.php"). Without
# this, the RoE gate flags every `<word>.php` / `<word>.html` reference as an
# off-scope host. Real TLDs aren't in this set — `.com`, `.htb`, `.lab`, etc.
# all still get treated as potential hosts.
_FILE_EXTENSION_TLDS = frozenset({
    # web / scripting
    "php", "html", "htm", "js", "mjs", "cjs", "ts", "tsx", "jsx", "css",
    "json", "xml", "yaml", "yml", "toml",
    "aspx", "asp", "jsp", "jspx", "cgi", "pl",
    "py", "pyc", "pyo", "rb", "go", "rs", "java", "class", "jar", "war",
    "sh", "bash", "zsh", "ps1", "bat", "cmd",
    # config / data / docs
    "env", "ini", "conf", "cnf", "cfg", "lock",
    "sql", "db", "sqlite", "mdb",
    "txt", "log", "md", "rst", "csv", "tsv",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    # binaries / archives / media
    "exe", "dll", "so", "dylib", "bin", "out", "elf",
    "zip", "tar", "gz", "tgz", "bz2", "rar", "7z", "iso", "img",
    "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "swf",
    # secrets-style
    "key", "pem", "pub", "crt", "cer", "csr", "p12", "pfx",
    # backups / temp
    "bak", "old", "tmp", "swp", "orig", "save",
})


class RoEViolation(Exception):
    """Raised when a tool call targets a host outside the engagement allowlist."""


@dataclass
class ExtractedTargets:
    hosts: set[str] = field(default_factory=set)
    networks: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)

    @property
    def all_targets(self) -> set[str]:
        # Hosts pulled out of URLs are already in `hosts`. Networks are kept separate.
        return self.hosts | self.networks


# Dict fields whose value is the agent's free-text reasoning, not a target.
# Bare hostname extraction is skipped under these fields to avoid matching
# code identifiers (`pty.spawn`, `os.path`), method calls
# (`socket.gethostbyname`), or path tokens in prose. URLs, IPs, and CIDRs are
# still extracted unconditionally — those are unambiguous targets even when
# they appear in prose.
_FREE_TEXT_FIELDS = frozenset({
    "description", "objective", "command", "code", "script",
    "payload", "prompt", "system_prompt", "instructions", "context",
    "reasoning", "notes", "summary", "rationale", "explanation", "guidance",
    "input",
})


def extract_targets(value: Any) -> ExtractedTargets:
    """Walk a tool's structured arguments and pull out everything that looks like a target.

    URLs, IPs, and CIDRs are always extracted. Bare hostname tokens are
    skipped inside `_FREE_TEXT_FIELDS` (task descriptions, objectives, code
    blocks, etc.) where they're overwhelmingly code identifiers rather than
    real hosts.
    """

    result = ExtractedTargets()
    _walk(value, result, in_free_text=False)
    # Expand URLs into the host they point at.
    for url in list(result.urls):
        try:
            parsed = urlparse(url)
            if parsed.hostname:
                result.hosts.add(parsed.hostname)
        except ValueError:
            continue
    return result


def _walk(value: Any, out: ExtractedTargets, *, in_free_text: bool) -> None:
    if isinstance(value, str):
        for match in _URL_PATTERN.findall(value):
            out.urls.add(match)
        # Strip the URLs we already matched so they don't double-count as hostnames.
        cleaned = _URL_PATTERN.sub(" ", value)
        for match in _CIDR_PATTERN.findall(cleaned):
            out.networks.add(match)
        cleaned = _CIDR_PATTERN.sub(" ", cleaned)
        for match in _IP_PATTERN.findall(cleaned):
            out.hosts.add(match)
        if not in_free_text:
            for match in _HOSTNAME_PATTERN.findall(cleaned):
                # Don't double-count IPs the hostname regex also catches.
                if _IP_PATTERN.fullmatch(match):
                    continue
                # Drop filename-like matches whose final segment is a known file
                # extension (`config.php`, `index.html`, `app.js`). They appear in
                # prose / tool args but are never hosts.
                suffix = match.rsplit(".", 1)[-1].lower()
                if suffix in _FILE_EXTENSION_TLDS:
                    continue
                out.hosts.add(match)
    elif isinstance(value, dict):
        for k, v in value.items():
            child_free_text = in_free_text or (
                isinstance(k, str) and k.lower() in _FREE_TEXT_FIELDS
            )
            _walk(v, out, in_free_text=child_free_text)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            _walk(v, out, in_free_text=in_free_text)


def _self_networks(roe: RulesOfEngagement) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in getattr(roe, "self_hosts", None) or []:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return nets


def _is_self_host(host: str, roe: RulesOfEngagement) -> bool:
    """True if `host` is the attacker's own infra (LHOST/VPN/staging), never a target."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in _self_networks(roe))


def _is_self_network(cidr: str, roe: RulesOfEngagement) -> bool:
    try:
        candidate = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return any(candidate.subnet_of(net) for net in _self_networks(roe))


def _host_is_allowed(host: str, roe: RulesOfEngagement) -> bool:
    if host in roe.blocked_hosts:
        return False
    # First try as IP, then fall back to hostname matching.
    try:
        ip = ipaddress.ip_address(host)
        for net in roe.parsed_networks():
            if ip in net:
                return True
        # An IP may also be in the explicit host list.
        return host in roe.allowed_hosts
    except ValueError:
        # Not an IP — must match allowed_hosts (with simple `*.foo.com` wildcards).
        for pattern in roe.allowed_hosts:
            if pattern == host:
                return True
            if pattern.startswith("*.") and host.endswith(pattern[1:]):
                return True
            if pattern == "*":
                return True
        return False


def _network_is_allowed(cidr: str, roe: RulesOfEngagement) -> bool:
    try:
        candidate = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    for net in roe.parsed_networks():
        if candidate.subnet_of(net):
            return True
    return False


# Tools that run purely in-process and never open a network connection to a
# target. Their arguments routinely carry hostnames/IPs as *prose* — most
# importantly `task`, the deepagents subagent-delegation tool, whose args are
# the subagent's free-text prompt (often referencing the local episode-log
# endpoint at 127.0.0.1). Gating these is wrong: no packet reaches any host
# here, and the spawned subagent's own tool calls are gated on their merits.
_UNGATED_TOOLS = frozenset({
    "task",          # deepagents subagent delegation
    "write_todos",   # in-process planning scratchpad
})


def check_roe(tool_input: Any, roe: RulesOfEngagement) -> tuple[bool, str | None]:
    """Return `(allowed, reason)` for a single tool call's arguments."""

    targets = extract_targets(tool_input)
    if not targets.all_targets:
        # No identifiable target — common for purely local tools (`searchsploit_lookup`,
        # `generate_payload`, etc.). Allow; the host-level enforcement happens at delivery time.
        return True, None

    for host in targets.hosts:
        # The attacker's own box (LHOST / VPN tun / staging server) is not a
        # target — referencing it (e.g. in a task description or a payload
        # LHOST) must never trip the gate.
        if _is_self_host(host, roe):
            continue
        if not _host_is_allowed(host, roe):
            return False, f"host {host!r} is not in the RoE allowlist"
    for cidr in targets.networks:
        if _is_self_network(cidr, roe):
            continue
        if not _network_is_allowed(cidr, roe):
            return False, f"network {cidr!r} is not in the RoE allowlist"
    return True, None


def roe_gate(roe: RulesOfEngagement):
    """Returns an `AgentMiddleware` instance that blocks off-scope tool calls.

    `check_roe`/`extract_targets` remain importable from this module without
    langchain — only the factory pulls langchain in. That keeps the unit tests
    runnable without the full deps installed.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    class RoEGate(AgentMiddleware):
        def __init__(self, roe_inner: RulesOfEngagement) -> None:
            super().__init__()
            self._roe = roe_inner

        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            tool_call = getattr(request, "tool_call", {}) or {}
            tool_name = getattr(tool, "name", None) or tool_call.get("name", "") or "<unknown>"
            # In-process tools (subagent delegation, planning) open no network
            # connection — never gate them on hostnames that appear in their prose.
            if tool_name in _UNGATED_TOOLS:
                return await handler(request)
            args = tool_call.get("args", {}) or {}
            allowed, reason = check_roe(args, self._roe)
            if allowed:
                return await handler(request)
            message = (
                f"BLOCKED by RoE gate: {reason}. "
                f"Tool: {tool_name}. "
                f"Allowed networks: {self._roe.allowed_networks}. "
                f"Allowed hosts: {self._roe.allowed_hosts}. "
                f"If this target should be in scope, update the engagement spec."
            )
            return ToolMessage(
                content=message,
                tool_call_id=tool_call.get("id", "") or "",
                name=tool_name,
                status="error",
            )

    return RoEGate(roe)
