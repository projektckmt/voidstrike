"""Structured extractors for the episode → graph projection.

Phase 2: the regex-based extractor in `log_to_graph` is enough for
engagement/host/CVE nodes. This module adds tool-specific parsers so we capture
service versions, observed paths, and harvested credentials with the precision
the analyst needs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as ET


@dataclass
class ExtractedFacts:
    hosts: set[str] = field(default_factory=set)
    services: list[dict[str, Any]] = field(default_factory=list)  # host/port/proto/service/version
    web_paths: list[dict[str, Any]] = field(default_factory=list)  # url/status/size
    credentials: list[dict[str, Any]] = field(default_factory=list)  # user/source/etc
    cves: set[str] = field(default_factory=set)
    suid_paths: list[str] = field(default_factory=list)


CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
HOST_PORT = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b")


def extract(episode: dict[str, Any]) -> ExtractedFacts:
    """Dispatch on `action` (the tool name) to the right parser."""
    facts = ExtractedFacts()
    output = episode.get("tool_output") or ""
    tool_input = episode.get("tool_input") or {}
    action = episode.get("action") or ""

    # Generic regex layer first.
    for ip, port in HOST_PORT.findall(output):
        facts.hosts.add(ip)
        facts.services.append({"host": ip, "port": int(port), "protocol": "tcp"})
    for cve in CVE.findall(output):
        facts.cves.add(cve)

    # Tool-specific layers.
    if "nmap" in action:
        _from_nmap_xml(output, facts)
    elif "httpx" in action:
        _from_httpx(output, facts)
    elif "ffuf" in action:
        _from_ffuf(output, facts)
    elif "suid_enum" in action:
        _from_suid(output, facts)
    elif "loot_credentials" in action:
        _from_loot(output, tool_input, facts)
    elif "subfinder" in action:
        _from_subfinder(output, facts)

    return facts


def _from_nmap_xml(output: str, facts: ExtractedFacts) -> None:
    # Current shape: surface MCP returns parsed JSON summary. Old episodes
    # in the DB may still hold raw XML — handle both.
    stripped = output.lstrip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return
        for host in payload.get("hosts", []) or []:
            addr = host.get("address") or ""
            if addr:
                facts.hosts.add(addr)
            for port in host.get("ports", []) or []:
                facts.services.append({
                    "host": addr,
                    "port": int(port.get("port") or 0),
                    "protocol": port.get("protocol") or "tcp",
                    "service": port.get("service"),
                    "version": port.get("version"),
                    "product": port.get("product"),
                    "banner": port.get("extrainfo") or "",
                })
        return

    if "<nmaprun" not in output:
        return
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return
    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue
        addr = addr_el.get("addr", "")
        if addr:
            facts.hosts.add(addr)
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port in ports_el.findall("port"):
            portid = int(port.get("portid", "0") or 0)
            proto = port.get("protocol", "tcp")
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            facts.services.append({
                "host": addr,
                "port": portid,
                "protocol": proto,
                "service": svc.get("name") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "banner": (svc.get("extrainfo") if svc is not None else "") or "",
            })


def _from_httpx(output: str, facts: ExtractedFacts) -> None:
    # httpx emits JSON-lines.
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = row.get("url") or row.get("input")
        if url:
            facts.web_paths.append({
                "url": url,
                "status": row.get("status_code") or row.get("status-code"),
                "title": row.get("title"),
                "tech": row.get("tech") or row.get("technologies") or [],
            })


def _from_ffuf(output: str, facts: ExtractedFacts) -> None:
    try:
        parsed = json.loads(output) if output else None
    except json.JSONDecodeError:
        return
    if not parsed:
        return
    for row in parsed.get("results", []):
        url = row.get("url")
        if not url:
            continue
        facts.web_paths.append({
            "url": url,
            "status": row.get("status"),
            "size": row.get("length"),
        })


def _from_suid(output: str, facts: ExtractedFacts) -> None:
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("/") and not line.endswith(":"):
            facts.suid_paths.append(line)


def _from_loot(output: str, tool_input: dict[str, Any], facts: ExtractedFacts) -> None:
    # Output is a JSON-ish structure from loot_credentials. We don't aggressively
    # parse — the analyst will. But we capture *that* creds were harvested.
    host = tool_input.get("host", "")
    if "PRIVATE KEY" in output or "BEGIN OPENSSH" in output:
        facts.credentials.append({
            "type": "ssh_key",
            "host": host,
            "source": "loot_credentials",
        })
    if "shadow:" in output or "$6$" in output or "$y$" in output:
        facts.credentials.append({
            "type": "hash",
            "host": host,
            "source": "/etc/shadow",
        })


def _from_subfinder(output: str, facts: ExtractedFacts) -> None:
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # Subdomain enumeration — record as hostnames.
        if "." in line and " " not in line:
            facts.hosts.add(line)
