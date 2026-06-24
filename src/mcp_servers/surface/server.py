"""Surface MCP server — recon + web testing tools.

Wraps Kali-resident binaries (nmap, httpx, ffuf, subfinder) as MCP tools. The
agent calls these; the wrapper handles flag construction, output parsing, and
the structured return shape.

All commands execute inside the sandbox via the local `shell` MCP server's
`run_oneshot` for short scans and via `tmux_new_session` for long ones.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse
from xml.etree import ElementTree as ET

from mcp.server.fastmcp import FastMCP

app = FastMCP(
    "surface",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
)


async def _exec(cmd: list[str], timeout_s: int | None = 600) -> dict[str, Any]:
    """Run a command in the sandbox shell. Returns rc/stdout/stderr.

    `timeout_s=None` waits for the process to exit (no wall-clock cap) — used by
    long scans like nuclei that should run to completion."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return {"ok": False, "error": f"command failed to start: {exc}", "rc": 127}
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except TimeoutError:
        proc.kill()
        return {"ok": False, "error": "timeout", "rc": -1}
    return {
        "ok": proc.returncode == 0,
        "rc": proc.returncode,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }


@app.tool()
async def nmap_quick(target: str, top_ports: int = 1000, scripts: str = "default") -> dict[str, Any]:
    """Fast nmap pass — top ports + default scripts. Use first."""
    cmd = ["nmap", "-Pn", "-T4", "--top-ports", str(top_ports), "-sV", "-sC", "-oX", "-", target]
    res = await _exec(cmd, timeout_s=600)
    if not res["ok"]:
        return res
    return _summarize_nmap_xml(res["stdout"], stderr=res["stderr"])


@app.tool()
async def nmap_full(target: str, scripts: str = "default,vuln", reason: str = "") -> dict[str, Any]:
    """All-ports nmap.

    Slow — use only after quick scan gives little signal, a target hint points
    at hidden/non-default ports, or prior focused enumeration stalls. `reason`
    should briefly explain that necessity.
    """
    cmd = ["nmap", "-Pn", "-p-", "-T4", "-sV", "-sC", "--script", scripts, "-oX", "-", target]
    res = await _exec(cmd, timeout_s=1800)
    if not res["ok"]:
        return res
    return _summarize_nmap_xml(res["stdout"], stderr=res["stderr"])


# Caps below keep nmap_full --script vuln output well under deepagents'
# 20k-token eviction threshold. Raw XML for a comprehensive scan easily
# exceeds 80k tokens; that triggers FilesystemMiddleware to dump the result
# to /large_tool_results/<id>, which the agent can't read back because the
# fs tools are excluded by HarnessProfile.
_SCRIPT_OUTPUT_MAX_CHARS = 800
_MAX_SCRIPTS_PER_PORT = 6


def _summarize_nmap_xml(xml: str, stderr: str = "") -> dict[str, Any]:
    """Parse nmap XML into a compact structured summary."""
    if not xml or "<nmaprun" not in xml:
        return {"ok": True, "hosts": [], "raw_stderr": stderr}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        return {"ok": False, "error": f"nmap XML parse failed: {exc}", "raw_stderr": stderr}

    hosts: list[dict[str, Any]] = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        addr = addr_el.get("addr", "") if addr_el is not None else ""
        host_scripts = _collect_scripts(host_el.find("hostscript"))
        ports: list[dict[str, Any]] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                svc = port_el.find("service")
                entry: dict[str, Any] = {
                    "port": int(port_el.get("portid", "0") or 0),
                    "protocol": port_el.get("protocol", "tcp"),
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                    "extrainfo": svc.get("extrainfo") if svc is not None else None,
                }
                scripts = _collect_scripts(port_el)
                if scripts:
                    entry["scripts"] = scripts
                ports.append(entry)
        hosts.append({"address": addr, "ports": ports, "scripts": host_scripts})
    return {"ok": True, "hosts": hosts, "raw_stderr": stderr}


def _collect_scripts(parent: ET.Element | None) -> list[dict[str, str]]:
    """Extract <script id=... output=...> children, truncating long outputs."""
    if parent is None:
        return []
    out: list[dict[str, str]] = []
    for script in parent.findall("script"):
        text = script.get("output", "") or ""
        if len(text) > _SCRIPT_OUTPUT_MAX_CHARS:
            text = text[:_SCRIPT_OUTPUT_MAX_CHARS] + "... [truncated]"
        out.append({"id": script.get("id", ""), "output": text})
        if len(out) >= _MAX_SCRIPTS_PER_PORT:
            out.append({"id": "...", "output": "[additional scripts omitted]"})
            break
    return out


_CURL_BODY_MAX_CHARS = 50_000


@app.tool()
async def curl(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: str | dict[str, Any] | None = None,
    follow_redirects: bool = True,
    max_time_s: int = 15,
    insecure: bool = True,
) -> dict[str, Any]:
    """Custom HTTP request via curl. Returns structured response.

    For one-off probes that `httpx_fingerprint` / `ffuf` can't shape — testing
    specific endpoints, custom headers (auth bypass / SSRF), POST bodies,
    inspecting redirect chains, etc.

    `data` accepts either a raw string body or a JSON object (dict) — a dict is
    JSON-encoded and sent with `Content-Type: application/json` unless you set
    that header yourself. So `data={"email": "x"}` and `data='{"email":"x"}'`
    both work; you don't have to pre-stringify a JSON body.

    `insecure=True` (default) skips TLS verification — common in offensive
    recon. `follow_redirects=True` follows 3xx; the returned `final_url`
    differs from `url` when redirects fired.
    """
    req_headers = dict(headers or {})
    body: str | None
    if isinstance(data, dict):
        body = json.dumps(data)
        if not any(k.lower() == "content-type" for k in req_headers):
            req_headers["Content-Type"] = "application/json"
    else:
        body = data

    cmd = ["curl", "-sS", "-i", "--max-time", str(max_time_s), "-X", method.upper()]
    if follow_redirects:
        cmd.append("-L")
    if insecure:
        cmd.append("-k")
    for k, v in req_headers.items():
        cmd.extend(["-H", f"{k}: {v}"])
    if body is not None:
        cmd.extend(["-d", body])
    # Write the effective URL on stderr so we can distinguish it from
    # multi-hop response bodies in the same stream.
    cmd.extend(["-w", "\n__VS_CURL_META__\n%{url_effective}\n%{time_total}\n"])
    cmd.append(url)

    res = await _exec(cmd, timeout_s=max_time_s + 5)
    if not res["ok"] and not res.get("stdout"):
        return {"ok": False, "error": (res.get("stderr") or "curl failed").strip(), "rc": res.get("rc")}

    stdout = res.get("stdout", "")
    # Split off the metadata trailer we appended via -w.
    body_part, _, meta_part = stdout.partition("\n__VS_CURL_META__\n")
    final_url = url
    time_total_ms: int | None = None
    if meta_part:
        meta_lines = [line for line in meta_part.splitlines() if line.strip()]
        if meta_lines:
            final_url = meta_lines[0].strip() or url
        if len(meta_lines) >= 2:
            try:
                time_total_ms = int(float(meta_lines[1]) * 1000)
            except ValueError:
                pass

    # `body_part` contains one or more `HTTP/x ... \r\n<headers>\r\n\r\n<body>`
    # blocks when redirects fired. Keep the FINAL one.
    final_block = body_part
    blocks = re.split(r"(?=^HTTP/\S+\s+\d+)", body_part, flags=re.MULTILINE)
    blocks = [b for b in blocks if b.strip()]
    if blocks:
        final_block = blocks[-1]

    head, sep, body = final_block.partition("\r\n\r\n")
    if not sep:
        head, sep, body = final_block.partition("\n\n")
    header_lines = head.splitlines()
    status_line = header_lines[0] if header_lines else ""
    status_match = re.match(r"HTTP/\S+\s+(\d+)\s*(.*)?", status_line)
    status = int(status_match.group(1)) if status_match else 0
    reason = status_match.group(2).strip() if status_match else ""
    resp_headers: dict[str, str] = {}
    for line in header_lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            resp_headers[k.strip()] = v.strip()

    truncated = len(body) > _CURL_BODY_MAX_CHARS
    if truncated:
        body = body[:_CURL_BODY_MAX_CHARS] + "\n... [truncated]"

    return {
        "ok": True,
        "status": status,
        "reason": reason,
        "headers": resp_headers,
        "body": body,
        "body_truncated": truncated,
        "final_url": final_url,
        "redirected": final_url != url,
        "time_total_ms": time_total_ms,
        "hop_count": len(blocks) if blocks else 1,
    }


_WEB_INTAKE_BODY_SAMPLE_CHARS = 1200
_WEB_INTAKE_ITEM_CAP = 40


class _WebIntakeHTMLParser(HTMLParser):
    """Small signal extractor for HTML landing pages."""

    def __init__(self) -> None:
        super().__init__()
        self.title = ""
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.meta: dict[str, str] = {}
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "a" and attr.get("href") and len(self.links) < _WEB_INTAKE_ITEM_CAP:
            self.links.append(attr["href"])
        elif tag == "script" and attr.get("src") and len(self.scripts) < _WEB_INTAKE_ITEM_CAP:
            self.scripts.append(attr["src"])
        elif tag == "form" and len(self.forms) < _WEB_INTAKE_ITEM_CAP:
            self.forms.append({
                "method": (attr.get("method") or "GET").upper(),
                "action": attr.get("action") or "",
                "inputs": [],
            })
        elif tag in {"input", "textarea", "select", "button"} and self.forms:
            name = attr.get("name") or attr.get("id") or attr.get("type") or tag
            if name and len(self.forms[-1]["inputs"]) < 30:
                self.forms[-1]["inputs"].append({
                    "name": name,
                    "type": attr.get("type") or tag,
                })
        elif tag == "meta":
            key = attr.get("name") or attr.get("property")
            content = attr.get("content")
            if key and content and len(self.meta) < _WEB_INTAKE_ITEM_CAP:
                self.meta[key.lower()] = content

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and data.strip():
            self.title = (self.title + " " + data.strip()).strip()


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def _base_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def _absolute_paths(base: str, values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value.startswith(("mailto:", "tel:", "javascript:", "#")):
            continue
        absolute = urljoin(base, value)
        parsed = urlparse(absolute)
        path = urlunparse(("", "", parsed.path or "/", "", parsed.query, ""))
        if path not in seen:
            seen.add(path)
            out.append(path)
        if len(out) >= _WEB_INTAKE_ITEM_CAP:
            break
    return out


_INTERESTING_PATH_RE = re.compile(
    r"(admin|api|auth|backup|config|dashboard|debug|graphql|login|reset|upload|wp-admin)",
    re.I,
)


def _interesting_paths(paths: list[str]) -> list[str]:
    return [path for path in paths if _INTERESTING_PATH_RE.search(path)][:_WEB_INTAKE_ITEM_CAP]


def _web_technologies(headers: dict[str, str], body: str, parser: _WebIntakeHTMLParser) -> list[str]:
    tech: list[str] = []
    for name in ("Server", "X-Powered-By", "X-Generator"):
        value = _header(headers, name)
        if value:
            tech.append(f"{name}: {value}")
    if parser.meta.get("generator"):
        tech.append(f"generator: {parser.meta['generator']}")

    signatures = {
        "WordPress": ("wp-content", "wp-includes"),
        "Drupal": ("drupal-settings-json", "/sites/default/"),
        "Laravel": ("csrf-token", "laravel"),
        "Next.js": ("__NEXT_DATA__", "/_next/"),
        "React": ("react-dom", "data-reactroot"),
        "Vue": ("__vue__", "vue.js"),
        "GraphQL": ("graphql", "__schema"),
        "Swagger/OpenAPI": ("swagger-ui", "openapi"),
    }
    lower = body.lower()
    for label, needles in signatures.items():
        if any(needle.lower() in lower for needle in needles):
            tech.append(label)
    return sorted(dict.fromkeys(tech))


def _body_hints(body: str) -> dict[str, bool]:
    lower = body.lower()
    return {
        "has_login": bool(re.search(r"\b(log ?in|sign ?in|password)\b", lower)),
        "has_upload": "upload" in lower or "multipart/form-data" in lower,
        "has_api_hint": "/api/" in lower or "api/" in lower,
        "has_graphql_hint": "graphql" in lower,
        "has_password_reset": "forgot" in lower and "password" in lower,
    }


def _cookie_names(headers: dict[str, str]) -> list[str]:
    raw = _header(headers, "Set-Cookie")
    if not raw:
        return []
    names = []
    for chunk in raw.split(";"):
        if "=" not in chunk:
            continue
        name = chunk.split("=", 1)[0].strip()
        if name and name.lower() not in {"path", "domain", "expires", "max-age", "samesite"}:
            names.append(name)
    return sorted(dict.fromkeys(names))


def _robots_summary(body: str) -> dict[str, Any]:
    interesting: list[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if re.match(r"(?i)^(allow|disallow|sitemap):", line):
            interesting.append(line)
        if len(interesting) >= _WEB_INTAKE_ITEM_CAP:
            break
    return {"entries": interesting, "truncated": len(interesting) >= _WEB_INTAKE_ITEM_CAP}


@app.tool()
async def web_intake(url: str, max_time_s: int = 10) -> dict[str, Any]:
    """One-shot HTTP surface intake for a web root.

    Fetches the landing page plus common metadata endpoints and returns compact
    recon signal: status, title, headers, cookies, tech hints, forms, links,
    scripts, robots/sitemap hints, and favicon hash. This is read-only and is
    meant to replace many one-off `surface__curl` probes.
    """
    main = await curl(url=url, max_time_s=max_time_s)
    if not main.get("ok"):
        return main

    final_url = str(main.get("final_url") or url)
    base = _base_url(final_url)
    headers = dict(main.get("headers") or {})
    body = str(main.get("body") or "")

    parser = _WebIntakeHTMLParser()
    try:
        parser.feed(body)
    except Exception:
        # HTMLParser is forgiving, but malformed edge cases should not throw
        # away the HTTP facts we already collected.
        pass

    paths = _absolute_paths(final_url, [*parser.links, *parser.scripts])
    form_actions = _absolute_paths(final_url, [str(f.get("action") or "") for f in parser.forms])
    all_paths = sorted(dict.fromkeys([*paths, *form_actions]))

    robots_url = urljoin(base, "robots.txt")
    sitemap_url = urljoin(base, "sitemap.xml")
    favicon_url = urljoin(base, "favicon.ico")
    robots = await curl(url=robots_url, max_time_s=max(3, min(max_time_s, 8)))
    sitemap = await curl(url=sitemap_url, max_time_s=max(3, min(max_time_s, 8)))
    favicon = await curl(url=favicon_url, max_time_s=max(3, min(max_time_s, 8)))

    robots_probe: dict[str, Any] = {"status": robots.get("status"), "url": robots_url}
    if robots.get("ok") and int(robots.get("status") or 0) < 400:
        robots_probe.update(_robots_summary(str(robots.get("body") or "")))

    sitemap_probe: dict[str, Any] = {"status": sitemap.get("status"), "url": sitemap_url}
    if sitemap.get("ok") and int(sitemap.get("status") or 0) < 400:
        sitemap_body = str(sitemap.get("body") or "")
        locs = re.findall(r"<loc>\s*([^<]+)\s*</loc>", sitemap_body, flags=re.I)
        sitemap_probe["locs"] = locs[:_WEB_INTAKE_ITEM_CAP]

    favicon_probe: dict[str, Any] = {"status": favicon.get("status"), "url": favicon_url}
    if favicon.get("ok") and int(favicon.get("status") or 0) < 400:
        favicon_body = str(favicon.get("body") or "")
        favicon_probe["sha256_16"] = hashlib.sha256(favicon_body.encode(errors="replace")).hexdigest()[:16]
        favicon_probe["bytes_seen"] = len(favicon_body)

    return {
        "ok": True,
        "url": url,
        "final_url": final_url,
        "status": main.get("status"),
        "title": parser.title[:200],
        "server": _header(headers, "Server"),
        "content_type": _header(headers, "Content-Type"),
        "redirected": main.get("redirected"),
        "hop_count": main.get("hop_count"),
        "technologies": _web_technologies(headers, body, parser),
        "cookie_names": _cookie_names(headers),
        "forms": parser.forms[:_WEB_INTAKE_ITEM_CAP],
        "paths": all_paths[:_WEB_INTAKE_ITEM_CAP],
        "interesting_paths": _interesting_paths(all_paths),
        "scripts": _absolute_paths(final_url, parser.scripts),
        "body_hints": _body_hints(body),
        "body_sample": body[:_WEB_INTAKE_BODY_SAMPLE_CHARS],
        "probes": {
            "robots": robots_probe,
            "sitemap": sitemap_probe,
            "favicon": favicon_probe,
        },
    }


_TRIAGE_EVIDENCE_CHARS = 1200


def _compact_evidence(text: str) -> str:
    text = "\n".join(line.rstrip() for line in text.splitlines() if line.strip())
    if len(text) > _TRIAGE_EVIDENCE_CHARS:
        return text[:_TRIAGE_EVIDENCE_CHARS] + "\n... [truncated]"
    return text


def _service_port(entry: dict[str, Any]) -> int | None:
    try:
        return int(entry.get("port") or entry.get("portid") or 0)
    except (TypeError, ValueError):
        return None


def _normalize_services(services: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not services:
        return [
            {"port": 21, "service": "ftp"},
            {"port": 139, "service": "netbios-ssn"},
            {"port": 445, "service": "microsoft-ds"},
            {"port": 873, "service": "rsync"},
            {"port": 2049, "service": "nfs"},
            {"port": 6379, "service": "redis"},
            {"port": 9200, "service": "elasticsearch"},
        ]
    normalized: list[dict[str, Any]] = []
    for entry in services:
        port = _service_port(entry)
        if port is None:
            continue
        normalized.append({
            "port": port,
            "protocol": entry.get("protocol") or "tcp",
            "service": str(entry.get("service") or entry.get("name") or "").lower(),
            "product": entry.get("product"),
            "version": entry.get("version"),
        })
    return normalized


def _service_matches(service: dict[str, Any], *needles: str) -> bool:
    haystack = " ".join(
        str(service.get(key) or "").lower()
        for key in ("service", "product", "version")
    )
    port = _service_port(service)
    return any(needle in haystack for needle in needles) or any(
        str(port) == needle for needle in needles
    )


async def _triage_exec(kind: str, port: int, cmd: list[str], timeout_s: int) -> dict[str, Any]:
    res = await _exec(cmd, timeout_s=timeout_s)
    stdout = str(res.get("stdout") or "")
    stderr = str(res.get("stderr") or res.get("error") or "")
    return {
        "kind": kind,
        "port": port,
        "ok": res.get("ok", False),
        "rc": res.get("rc"),
        "evidence": _compact_evidence(stdout or stderr),
        "skipped": res.get("rc") == 127,
    }


async def _triage_ftp(target: str, port: int, timeout_s: int) -> dict[str, Any]:
    check = await _triage_exec(
        "ftp_anonymous",
        port,
        [
            "curl", "-sS", "--max-time", str(timeout_s),
            "--user", "anonymous:anonymous@", f"ftp://{target}:{port}/",
        ],
        timeout_s + 2,
    )
    evidence = check.get("evidence", "")
    check["exposed"] = bool(check["ok"] and evidence and "Login incorrect" not in evidence)
    check["summary"] = (
        "anonymous FTP appears accessible"
        if check["exposed"] else "anonymous FTP not confirmed"
    )
    return check


async def _triage_smb(target: str, port: int, timeout_s: int) -> dict[str, Any]:
    # `smbclient -L` by IP speaks over 445; using 139 fails with
    # NT_STATUS_RESOURCE_NAME_NOT_FOUND. Always list via 445 regardless of which
    # SMB port matched. (For deeper SMB recon the agent should use `smb_enum`.)
    check = await _triage_exec(
        "smb_anonymous",
        445,
        ["smbclient", "-L", f"//{target}", "-N", "-p", "445", "-g"],
        timeout_s + 2,
    )
    evidence = str(check.get("evidence") or "")
    check["exposed"] = bool(check["ok"] and re.search(r"^(Disk|IPC|Printer)\|", evidence, re.M))
    check["summary"] = (
        "anonymous SMB share listing returned data"
        if check["exposed"] else "anonymous SMB share listing not confirmed"
    )
    return check


async def _triage_nfs(target: str, port: int, timeout_s: int) -> dict[str, Any]:
    check = await _triage_exec("nfs_exports", port, ["showmount", "-e", target], timeout_s + 2)
    evidence = str(check.get("evidence") or "")
    check["exposed"] = bool(check["ok"] and "Export list" in evidence and "/" in evidence)
    check["summary"] = "NFS exports are listed" if check["exposed"] else "NFS exports not confirmed"
    return check


async def _triage_redis(target: str, port: int, timeout_s: int) -> dict[str, Any]:
    check = await _triage_exec(
        "redis_unauthenticated_info",
        port,
        ["redis-cli", "-h", target, "-p", str(port), "--no-auth-warning", "INFO", "server"],
        timeout_s + 2,
    )
    evidence = str(check.get("evidence") or "")
    check["exposed"] = bool(check["ok"] and "redis_version:" in evidence)
    check["summary"] = (
        "Redis INFO is accessible without authentication"
        if check["exposed"] else "unauthenticated Redis INFO not confirmed"
    )
    return check


async def _triage_rsync(target: str, port: int, timeout_s: int) -> dict[str, Any]:
    check = await _triage_exec(
        "rsync_modules",
        port,
        ["rsync", "--list-only", f"--timeout={timeout_s}", f"rsync://{target}:{port}/"],
        timeout_s + 2,
    )
    evidence = str(check.get("evidence") or "")
    check["exposed"] = bool(check["ok"] and evidence)
    check["summary"] = "rsync module listing returned data" if check["exposed"] else "rsync modules not confirmed"
    return check


async def _triage_elasticsearch(target: str, port: int, timeout_s: int) -> dict[str, Any]:
    url = f"http://{target}:{port}/"
    res = await curl(url=url, max_time_s=timeout_s)
    body = str(res.get("body") or "")
    exposed = bool(res.get("ok") and res.get("status") == 200 and (
        '"cluster_name"' in body or '"tagline"' in body or "You Know, for Search" in body
    ))
    return {
        "kind": "elasticsearch_root",
        "port": port,
        "ok": res.get("ok", False),
        "status": res.get("status"),
        "exposed": exposed,
        "summary": (
            "Elasticsearch root endpoint returned cluster metadata"
            if exposed else "Elasticsearch root metadata not confirmed"
        ),
        "evidence": _compact_evidence(body),
    }


@app.tool()
async def service_triage(
    target: str,
    services: list[dict[str, Any]] | None = None,
    timeout_s: int = 8,
) -> dict[str, Any]:
    """Run safe service-specific exposure checks against discovered services.

    Pass the `ports` list from `surface__nmap_quick` / `surface__nmap_full`.
    If `services` is omitted, the tool probes a short common-service set. It
    checks only read-only anonymous/default exposure signals: FTP anonymous
    listing, SMB null listing, NFS exports, rsync modules, unauthenticated Redis
    INFO, and Elasticsearch root metadata.
    """
    checks: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for service in _normalize_services(services):
        port = _service_port(service)
        if port is None:
            continue
        scheduled: list[tuple[str, Any]] = []
        if _service_matches(service, "ftp", "21"):
            scheduled.append(("ftp", _triage_ftp))
        if _service_matches(service, "smb", "microsoft-ds", "netbios", "445", "139"):
            scheduled.append(("smb", _triage_smb))
        if _service_matches(service, "nfs", "2049"):
            scheduled.append(("nfs", _triage_nfs))
        if _service_matches(service, "redis", "6379"):
            scheduled.append(("redis", _triage_redis))
        if _service_matches(service, "rsync", "873"):
            scheduled.append(("rsync", _triage_rsync))
        if _service_matches(service, "elasticsearch", "9200"):
            scheduled.append(("elasticsearch", _triage_elasticsearch))

        for kind, probe in scheduled:
            key = (kind, port)
            if key in seen:
                continue
            seen.add(key)
            checks.append(await probe(target, port, timeout_s))

    exposures = [
        {
            "kind": check.get("kind"),
            "port": check.get("port"),
            "summary": check.get("summary"),
            "evidence": check.get("evidence"),
        }
        for check in checks
        if check.get("exposed")
    ]
    return {
        "ok": True,
        "target": target,
        "checks": checks,
        "exposures": exposures,
        "exposure_count": len(exposures),
    }


@app.tool()
async def httpx_fingerprint(targets: list[str]) -> dict[str, Any]:
    """Run httpx over a list of URLs/hosts; return JSON fingerprint per target.

    Calls the binary as `httpx-toolkit`, not `httpx`. Kali renamed
    ProjectDiscovery's `httpx` to avoid a collision with the Python `httpx`
    library — and we pull Python httpx as a project dep, which lands a `httpx`
    CLI in the venv's bin/ that shadows the Go binary on PATH. Calling the
    short name fails with `No such option '-s'` (Python httpx parses `-silent`
    as a short flag).
    """
    cmd = [
        "httpx-toolkit",
        "-silent",
        "-json",
        "-status-code", "-title", "-tech-detect", "-server",
        "-l", "/dev/stdin",
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate("\n".join(targets).encode())
    if proc.returncode != 0:
        return {"ok": False, "rc": proc.returncode, "stderr": stderr.decode(errors="replace")}
    results: list[dict[str, Any]] = []
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return {"ok": True, "results": results}


# Severity ordering for sorting/capping nuclei output (worst first).
_NUCLEI_SEVERITY_RANK = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5,
}
# Cap returned findings so a chatty template run can't blow past deepagents'
# ~20k-token eviction threshold (which would dump the result to a file the
# agent can't read back). The full set still ran; we keep the worst N.
_NUCLEI_MAX_FINDINGS = 60

# nuclei stderr substrings that mean "the filter selected no templates" rather
# than a genuine tool failure — a bad/invented tag, or templates not installed.
_NUCLEI_NO_TEMPLATES_MARKERS = (
    "no templates provided",
    "no templates were found",
    "no templates found",
    "could not find templates",
    "no valid templates",
)


def _nuclei_templates_present() -> bool:
    """True if a nuclei template store exists on disk with at least one template.

    Lets us tell "your tag/severity filter matched nothing" (templates present)
    apart from "the template set isn't installed" (a real infra failure) — the
    two produce the same 'no templates provided' stderr. Short-circuits on the
    first `.yaml` found.

    The authoritative location is whatever `~/.config/nuclei/.templates-config.json`
    declares (`nuclei v3.8` defaults to `~/.local/nuclei-templates`, NOT the old
    `~/.config/nuclei/nuclei-templates`); we read that first, then fall back to
    the known default dirs."""
    home = Path(os.path.expanduser("~"))
    candidates: list[Path] = []
    env = os.environ.get("NUCLEI_TEMPLATES_DIR", "").strip()
    if env:
        candidates.append(Path(env))
    # The config json is the source of truth for where templates were installed.
    try:
        cfg = json.loads((home / ".config" / "nuclei" / ".templates-config.json").read_text())
        declared = cfg.get("nuclei-templates-directory")
        if declared:
            candidates.append(Path(declared))
    except (OSError, ValueError):
        pass
    candidates += [
        home / ".local" / "nuclei-templates",        # nuclei v3.8+ default
        Path("/root/.local/nuclei-templates"),
        home / ".config" / "nuclei" / "nuclei-templates",  # older default
        home / "nuclei-templates",
    ]
    for d in candidates:
        try:
            if d.is_dir() and next(d.rglob("*.yaml"), None) is not None:
                return True
        except OSError:
            continue
    return False


def _parse_nuclei_jsonl(text: str) -> list[dict[str, Any]]:
    """Parse nuclei `-jsonl` output (one JSON object per line) into compact findings."""
    findings: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = j.get("info") or {}
        classification = info.get("classification") or {}
        findings.append({
            "template_id": j.get("template-id") or j.get("templateID"),
            "name": info.get("name"),
            "severity": (info.get("severity") or "unknown").lower(),
            "type": j.get("type"),
            "matched_at": j.get("matched-at") or j.get("matched_at"),
            "cve": classification.get("cve-id"),
        })
    return findings


@app.tool()
async def nuclei(
    target: str,
    severity: str = "",
    tags: str | None = None,
    templates: str | None = None,
    max_runtime_s: int | None = None,
) -> dict[str, Any]:
    """Template-based vulnerability scan with ProjectDiscovery `nuclei`.

    Runs nuclei's community templates against `target` (a URL or host) and
    returns the matches as compact structured findings. This is recon-grade
    signal — known-CVE checks, exposed panels/configs, default creds,
    misconfigurations — not exploitation. Hand confirmed leads to `exploit`.

    **The scan runs to completion by default** — a full all-severity run takes
    several minutes, and cutting it short returns only the fast early detections
    and misses the high-value CVE templates that run after them, so normally just
    let it finish. Use `max_runtime_s` only to bound a known-slow/flapping host
    (you'll get whatever matched before the cap).

    **Bare `target` = full all-severity sweep** (like `nuclei -u <target>`): use
    it to fingerprint an unknown host root — it picks up `info`/`low` tech and
    exposure hits, not just CVEs, but takes minutes. **Once you know what you're
    scanning, scope it** with `tags=`/`severity=` so you run the relevant template
    family instead of the whole set — that's the normal way to cut runtime when
    the target is a specific endpoint or an already-fingerprinted stack.

    - `severity`: comma list to filter (e.g. `critical,high,medium`). Default is
      empty = all severities. A floor (e.g. `high,critical`) is a safe way to cut
      runtime when you don't have a precise tag.
    - `tags`: scope to a vuln class or technology you've identified (`cve`,
      `exposure`, `misconfig`, `apache`, `cgi`, `tomcat`, `wordpress`, `rce`,
      `lfi`). nuclei tags are a FIXED vocabulary — product/framework names like
      `nextjs`, `nodejs`, `react` are NOT tags and match ZERO templates. If unsure
      a tag is real, don't guess — use a `severity=` floor or `max_runtime_s=`
      cap, or leave it unset for the full sweep.
    - `templates`: an explicit template id/path/dir to run instead of the
      default set (e.g. a single `http/cves/2025/CVE-2025-57819.yaml`).
    - `max_runtime_s`: overall wall-clock budget in seconds. Default (unset) =
      run to completion (recommended). Set it (e.g. `900`) only to cap a
      slow/flapping host; partial findings collected before the cap are still
      returned.

    Findings are sorted worst-severity-first and capped at
    `_NUCLEI_MAX_FINDINGS`; the scan still runs in full.
    """
    fd, out_path = tempfile.mkstemp(prefix="nuclei-", suffix=".jsonl")
    os.close(fd)
    cmd = [
        "nuclei",
        "-target", target,
        "-jsonl", "-o", out_path,  # one JSON object per match → file
        "-silent",                 # no banner / progress noise
        "-no-color",
        "-disable-update-check",   # don't block on the self-update probe
        # Don't abandon a host after N connection errors. HTB/lab boxes flap
        # under scan load; the default (skip host after 30 errors) makes nuclei
        # silently drop the rest of the template set — exiting 0 with only the
        # fast early detections, missing later CVE templates entirely.
        "-no-mhe",
        # Raise the per-request timeout from nuclei's default 10s. Targets are
        # VPN-routed and high-latency, and heavyweight RCE templates (e.g.
        # CVE-2025-55182/React2Shell, whose POST makes the server spawn a process
        # and redirect — the template itself asks for @timeout 15s) routinely
        # need >10s. At the default they `i/o timeout`, never match, and the host
        # gets marked unresponsive — the vuln is missed despite being present.
        "-timeout", "30",
        "-retries", "2",   # ride out transient VPN blips
        # Skip `code`-protocol templates. They run code locally (need the `-code`
        # flag + a `go`/python engine on the host) and never apply to remote
        # target scanning — but they emit a "no valid engine found" parse warning
        # per template at load. Excluding the type removes that noise and the
        # ~780 inapplicable templates; HTTP/network CVE templates are unaffected.
        "-exclude-type", "code",
    ]
    if severity.strip():
        cmd += ["-severity", severity]
    if tags:
        cmd += ["-tags", tags]
    if templates:
        cmd += ["-t", templates]

    try:
        # No wall-clock cap by default — let the scan run to completion (a short
        # cap returns only the fast early detections and misses the CVE templates
        # that run after them; the transport's sse_read_timeout is the backstop).
        # The caller may pass `max_runtime_s` to bound a slow/flapping host —
        # partial findings written to the -o file before the cap are still
        # returned below (the file is read regardless of exit status).
        res = await _exec(cmd, timeout_s=max_runtime_s)
        # Prefer the file (authoritative); fall back to stdout.
        try:
            file_text = Path(out_path).read_text(errors="replace")
        except OSError:
            file_text = ""
        findings = _parse_nuclei_jsonl(file_text) or _parse_nuclei_jsonl(res.get("stdout") or "")
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass

    # nuclei exits non-zero on a real error (bad target, no templates selected);
    # with matches it still exits 0. If it failed AND produced nothing, work out
    # which kind of failure it is.
    if not res.get("ok") and not findings:
        stderr = (res.get("stderr") or "").strip()
        low = stderr.lower()
        if any(m in low for m in _NUCLEI_NO_TEMPLATES_MARKERS):
            # Same stderr, two very different causes — disambiguate by whether a
            # template store actually exists on disk.
            if not _nuclei_templates_present():
                # Infra failure: nuclei is non-functional until templates exist.
                # Return ok:False so the agent stops re-tuning tags and surfaces it.
                return {
                    "ok": False,
                    "rc": res.get("rc"),
                    "error": (
                        "nuclei templates are NOT installed — every scan will match 0 "
                        "templates. Run `nuclei -update-templates` in the surface-mcp "
                        "container (or rebuild its image, which pre-fetches them). This "
                        "is an environment problem, not a bad `tags`/`severity` filter."
                    ),
                    "stderr": stderr[:300],
                }
            # Templates present → the tags/severity filter genuinely matched
            # nothing. Benign empty with guidance; not a tool failure.
            return {
                "ok": True,
                "target": target,
                "finding_count": 0,
                "findings": [],
                "note": (
                    "nuclei selected 0 templates — your tags/severity filter matched "
                    "nothing (templates ARE installed). `nextjs` is not a real nuclei "
                    "tag; retry without `tags`, or use real ones (e.g. `tags='cve'`, "
                    "`tags='exposure'`) or `severity` only."
                ),
                "stderr": stderr[:300],
            }
        return {
            "ok": False,
            "rc": res.get("rc"),
            # Fold stderr into the message so the cause is visible in the CLI's
            # one-line error render, not buried in a field nothing prints.
            "error": f"nuclei failed: {stderr[:400] or res.get('error', 'unknown error')}",
            "stderr": stderr[:600],
        }

    findings.sort(key=lambda f: _NUCLEI_SEVERITY_RANK.get(f["severity"], 5))
    capped = findings[:_NUCLEI_MAX_FINDINGS]
    return {
        "ok": True,
        "target": target,
        "finding_count": len(findings),
        "truncated": len(findings) > len(capped),
        "findings": capped,
    }


@app.tool()
async def subfinder(domain: str) -> dict[str, Any]:
    """Passive subdomain enumeration for engagement-mode external scope."""
    res = await _exec(["subfinder", "-silent", "-d", domain], timeout_s=120)
    if not res["ok"]:
        return res
    subs = [line.strip() for line in res["stdout"].splitlines() if line.strip()]
    return {"ok": True, "subdomains": subs}


@app.tool()
async def ffuf(
    url: str,
    wordlist: str | None = None,
    extensions: list[str] | None = None,
    match_status: str = "200,204,301,302,307,401,403",
    threads: int = 40,
    rate: int = 0,
) -> dict[str, Any]:
    """Directory/file fuzzing with ffuf — substitutes the wordlist into a `FUZZ`
    placeholder in the URL *path*, e.g. `http://host/FUZZ`. This is NOT the tool
    for subdomain/vhost enumeration (that fuzzes the Host header, not the path —
    use `vhost_enum`).

    `wordlist` defaults to `/usr/share/seclists/Discovery/Web-Content/big.txt`
    (~20k entries) — good coverage without grinding. Pass `common.txt` (~4-5k) for
    a fast smoke pass on a slow/rate-limited target, or a larger list
    (`directory-list-2.3-medium.txt` ~220k, `raft-large-words.txt`) for thorough
    coverage when big.txt found surface but the app clearly has more."""
    if wordlist is None:
        wordlist = _default_ffuf_wordlist()
    if "FUZZ" not in url:
        wl = wordlist.lower()
        looks_like_vhost = any(
            s in wl for s in ("subdomain", "/dns/", "vhost", "namelist", "bitquark")
        )
        error = (
            "url must contain a `FUZZ` placeholder. `ffuf` fuzzes the URL path for "
            "directory/file discovery — e.g. url='http://"
            f"{(url.split('//', 1)[-1].split('/', 1)[0] or 'TARGET')}/FUZZ'. "
            "It does NOT do subdomain/vhost fuzzing: those substitute into the Host "
            "header, not the path. For vhosts/subdomains call "
            "`surface__vhost_enum(base_url=...)` instead — it has no FUZZ in the URL "
            "because it sets `Host: FUZZ.<target>` for you."
        )
        result: dict[str, Any] = {"ok": False, "error": error}
        if looks_like_vhost:
            result["hint"] = (
                f"Your wordlist ({wordlist}) is a subdomain/DNS list — you want "
                "`surface__vhost_enum`, not `ffuf`."
            )
        return result
    resolved_wordlist = _resolve_wordlist(wordlist)
    if resolved_wordlist is None:
        return {
            "ok": False,
            "error": "wordlist not found",
            "wordlist": wordlist,
            "hint": (
                "Install the `seclists` package in the Kali image or pass an "
                "existing wordlist such as /usr/share/wordlists/dirb/common.txt."
            ),
        }
    cmd_base = [
        "ffuf",
        "-u", url,
        "-w", resolved_wordlist,
        "-mc", match_status,
        "-t", str(threads),
        # Auto-calibration: ffuf probes random paths first and auto-filters the
        # wildcard/catch-all response. Without this, a server that 301/403s every
        # path matches the whole wordlist (thousands of entries) → the result is
        # offloaded to /large_tool_results and the agent can't act on it.
        "-ac",
        # Ignore wordlist comments — harmless on our comment-free default
        # (big.txt), but skips the `#` header lines if the agent passes a
        # dirbuster directory-list-2.3 file via `wordlist=`.
        "-ic",
        "-s",
    ]
    if extensions:
        # ffuf concatenates each extension directly to the wordlist entry — without
        # a leading dot, `-e php` produces `indexphp` instead of `index.php`. Normalize.
        normalized = [e if e.startswith(".") else f".{e}" for e in extensions]
        cmd_base.extend(["-e", ",".join(normalized)])
    if rate:
        cmd_base.extend(["-rate", str(rate)])

    return await _run_ffuf(cmd_base, timeout_s=1200)


@app.tool()
async def vhost_enum(
    base_url: str,
    wordlist: str = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    filter_size: int | None = None,
) -> dict[str, Any]:
    """vhost / Host-header fuzzing — needed for boxes with name-based virtualhosting.

    Follows redirects (`-r`) on purpose: many boxes answer the bare root with a
    same-size redirect (e.g. nginx's 178-byte 301) for *every* Host, which
    defeats size-based auto-calibration — so a real vhost like
    `staging.example.htb` looks identical to the wildcard and gets filtered.
    Following redirects compares the final page content instead, so a distinct
    vhost (a different app behind the redirect) actually stands out.

    Auto-calibration (`-ac`) handles the wildcard filter for you; you normally do
    NOT need `filter_size` — only pass it if `-ac` is under-filtering a noisy box.
    """
    host = base_url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass  # a hostname, as expected
    else:
        return {
            "ok": False,
            "error": f"vhost_enum needs a domain base_url, not an IP ({host!r})",
            "hint": "Host-header fuzzing varies a subdomain of a real domain "
                    "(`Host: FUZZ.example.htb`); an IP has no subdomains. Map the "
                    "domain with surface__add_hosts_entry and pass base_url=http://<domain>.",
        }

    resolved_wordlist = _resolve_wordlist(wordlist)
    if resolved_wordlist is None:
        return {
            "ok": False,
            "error": "wordlist not found",
            "wordlist": wordlist,
            "hint": "Install the `seclists` package in the Kali image or pass an existing wordlist.",
        }
    cmd_base = [
        "ffuf",
        "-u", base_url,
        "-H", f"Host: FUZZ.{host}",
        "-w", resolved_wordlist,
        # Auto-calibrate the wildcard response, and follow redirects so same-size
        # redirects don't mask a distinct vhost (see docstring).
        "-ac",
        "-r",
        "-s",
    ]
    if filter_size is not None:
        cmd_base.extend(["-fs", str(filter_size)])
    result = await _run_ffuf(cmd_base, timeout_s=1200)
    if result.get("ok") and not result.get("results"):
        result["hint"] = (
            "No vhost responded differently from the wildcard. That can mean: the "
            "name isn't in this wordlist (try a larger DNS list), the box serves a "
            "uniform default for unknown Hosts, or the real vhost was already found "
            "via page content / a redirect. Don't conclude there are no vhosts from "
            "one wordlist."
        )
    return result


async def _run_ffuf(cmd_base: list[str], *, timeout_s: int) -> dict[str, Any]:
    """Run ffuf with JSON output written to a tempfile (not stdout).

    Why not `-o /dev/stdout`: ffuf's silent mode (`-s`) suppresses the banner
    and progress, but it STILL prints each discovered URL to stdout as
    plaintext. Combined with `-of json -o /dev/stdout` the stdout ends up
    being a mix of plaintext discovery lines + the trailing JSON file
    dump — and `json.loads(stdout)` raises `JSONDecodeError`, dropping
    every match. Writing the JSON to a tempfile and reading it back avoids
    the stdout pollution entirely.
    """
    with tempfile.NamedTemporaryFile(prefix="ffuf-", suffix=".json", delete=False) as tf:
        out_path = tf.name
    try:
        cmd = [*cmd_base, "-of", "json", "-o", out_path]
        res = await _exec(cmd, timeout_s=timeout_s)
        if not res["ok"]:
            return _ffuf_error(res)
        try:
            with open(out_path, encoding="utf-8") as fh:
                content = fh.read()
        except OSError as exc:
            return {"ok": False, "error": f"failed to read ffuf output: {exc}"}
        if not content.strip():
            return {"ok": True, "results": [], "config": {}}
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            return {
                "ok": False,
                "error": f"ffuf wrote unparseable JSON: {exc}",
                "raw": content[:500],
            }
        return _shape_ffuf_results(parsed.get("results", []) or [])
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


# ffuf returns a verbose object per match (~15 fields each). With a wildcard
# catch-all that matches the whole wordlist, the raw array blows past
# deepagents' ~20k-token eviction threshold and gets dumped to
# /large_tool_results. `-ac` removes most of the noise; this trims each entry to
# the actionable fields and caps the count as a hard backstop.
_FFUF_RESULT_CAP = 150


def _compact_ffuf_result(r: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "fuzz": (r.get("input") or {}).get("FUZZ"),
        "url": r.get("url"),
        "status": r.get("status"),
        "length": r.get("length"),
        "words": r.get("words"),
        "lines": r.get("lines"),
    }
    if r.get("redirectlocation"):
        out["redirect"] = r["redirectlocation"]
    return out


def _shape_ffuf_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    shaped = [_compact_ffuf_result(r) for r in results]
    total = len(shaped)
    out: dict[str, Any] = {
        "ok": True,
        "results": shaped[:_FFUF_RESULT_CAP],
        "total_matches": total,
        "truncated": total > _FFUF_RESULT_CAP,
    }
    if total > _FFUF_RESULT_CAP:
        out["hint"] = (
            f"{total} matches (showing first {_FFUF_RESULT_CAP}). This many hits usually "
            "means a wildcard/catch-all response — tighten `match_status`, pick a more "
            "specific wordlist, or filter by size; don't treat every hit as real."
        )
    return out


# First-pass ffuf wordlist: SecLists' big.txt (~20k entries) — a solid balance of
# coverage vs. speed for the default sweep, bigger than `common.txt` (~4-5k)
# without the ~220k cost of directory-list-2.3-medium. The agent can pass a
# smaller list (`common.txt`) for a fast smoke pass, or a larger one
# (directory-list-2.3-medium, raft-large) for thorough coverage, via `wordlist=`
# — see the surface prompt's web-fuzzing budget. Tried in order; first that
# exists wins (smaller lists remain as fallbacks if big.txt isn't installed).
_FFUF_DEFAULT_WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/big.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
)


def _default_ffuf_wordlist() -> str:
    """Pick the first available default wordlist (raft-medium, else a common list)
    for the initial ffuf pass."""
    for wl in _FFUF_DEFAULT_WORDLISTS:
        if Path(wl).is_file():
            return wl
    return _FFUF_DEFAULT_WORDLISTS[0]  # none found → surfaces a clear 'not found'


def _resolve_wordlist(wordlist: str) -> str | None:
    """Resolve common SecLists path variants and reject missing files early."""
    candidates = [Path(wordlist)]
    if wordlist.startswith("/usr/share/wordlists/seclists/"):
        candidates.append(Path(wordlist.replace("/usr/share/wordlists/seclists/", "/usr/share/seclists/", 1)))
    if wordlist.startswith("/usr/share/SecLists/"):
        candidates.append(Path(wordlist.replace("/usr/share/SecLists/", "/usr/share/seclists/", 1)))

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return str(candidate)
    return None


def _ffuf_error(res: dict[str, Any]) -> dict[str, Any]:
    """Return concise ffuf failures; ffuf prints full usage to stdout on bad input."""
    stderr = str(res.get("stderr") or "").strip()
    stdout = str(res.get("stdout") or "").strip()
    message = stderr or (stdout.splitlines()[0] if stdout else "ffuf failed")
    return {
        "ok": False,
        "rc": res.get("rc"),
        "error": message,
        "stderr": stderr,
    }


# /etc/hosts path is overridable for tests; in the sandbox it's the real file.
_ETC_HOSTS = os.environ.get("ETC_HOSTS_PATH", "/etc/hosts")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def _hosts_mapped_to(content: str, ip: str) -> set[str]:
    """Hostnames already mapped to `ip` in /etc/hosts content."""
    out: set[str] = set()
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        tokens = line.split()
        if tokens and tokens[0] == ip:
            out.update(tokens[1:])
    return out


@app.tool()
async def add_hosts_entry(ip: str, hostnames: list[str]) -> dict[str, Any]:
    """Map vhost/hostname(s) to an IP in the sandbox's /etc/hosts.

    Web recon tools (httpx, ffuf, curl) resolve names via /etc/hosts, so a
    discovered vhost like `silentium.htb` won't load until it's mapped to the
    target IP. Call this once after finding a vhost on an in-scope box, then
    fuzz / curl / fingerprint it by name. Idempotent and append-only — it never
    rewrites or removes existing lines.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": f"invalid IP address: {ip!r}"}

    cleaned: list[str] = []
    for raw in hostnames or []:
        host = str(raw).strip().rstrip(".")
        if not host or not _HOSTNAME_RE.match(host):
            return {"ok": False, "error": f"invalid hostname: {raw!r}"}
        cleaned.append(host)
    if not cleaned:
        return {"ok": False, "error": "no hostnames provided"}

    try:
        with open(_ETC_HOSTS, encoding="utf-8") as fh:
            existing = fh.read()
    except OSError as exc:
        return {"ok": False, "error": f"cannot read {_ETC_HOSTS}: {exc}"}

    mapped = _hosts_mapped_to(existing, ip)
    to_add = [h for h in cleaned if h not in mapped]
    already = [h for h in cleaned if h in mapped]

    if to_add:
        try:
            with open(_ETC_HOSTS, "a", encoding="utf-8") as fh:
                if existing and not existing.endswith("\n"):
                    fh.write("\n")
                fh.write(f"{ip}\t{' '.join(to_add)}\n")
        except OSError as exc:
            return {"ok": False, "error": f"cannot write {_ETC_HOSTS}: {exc}"}

    return {
        "ok": True,
        "ip": ip,
        "added": to_add,
        "already_present": already,
        # Honest scope note: surface tools (httpx/ffuf/curl) run in THIS
        # container, so this mapping is what they resolve against. The browser
        # and shell/exploit containers keep their own /etc/hosts.
        "note": (
            "Applied to the surface sandbox (httpx/ffuf/curl). For the browser or "
            "Kali-shell containers, map the host there too."
        ),
    }


_SMB_ADMIN_SHARES = {"IPC$", "ADMIN$", "C$", "PRINT$"}


@app.tool()
async def smb_enum(
    target: str,
    port: int = 445,
    max_shares: int = 20,
    max_files_per_share: int = 80,
) -> dict[str, Any]:
    """Anonymous SMB enumeration for Windows/AD targets (ports 445/139).

    The recon path for a large class of boxes: an anonymously-readable share
    holding a loot file (a script/config/Excel-macro with creds), or a null
    session that leaks the user list. This lists shares, tests anonymous READ
    access to each non-admin share, lists the contents of readable ones (so you
    SEE the loot file), and enumerates domain users over a null session.

    Read-only. Hand any creds/loot found to the exploit subagent.
    """
    # 1. Share listing. `smbclient -L` by IP speaks over 445 — using 139 fails
    #    with NT_STATUS_RESOURCE_NAME_NOT_FOUND, so always list via 445.
    listed = await _exec(
        ["smbclient", "-L", f"//{target}", "-N", "-p", "445", "-g"], timeout_s=40
    )
    if not listed.get("ok") and not listed.get("stdout"):
        return {
            "ok": False,
            "error": (listed.get("error") or listed.get("stderr") or "smbclient -L failed").strip(),
            "hint": "Anonymous share listing was refused. The box may require auth; "
                    "once you have creds, re-run or hand to exploit. enum4linux-ng / "
                    "rpcclient with creds may still enumerate.",
        }

    shares: list[dict[str, Any]] = []
    for line in (listed.get("stdout") or "").splitlines():
        parts = line.split("|")
        if len(parts) >= 2 and parts[0] in ("Disk", "IPC", "Printer"):
            shares.append({
                "name": parts[1],
                "type": parts[0],
                "comment": parts[2] if len(parts) > 2 else "",
            })

    # 2. Per-share anonymous read test + content listing (skip admin shares).
    readable: dict[str, list[str]] = {}
    for sh in shares[:max_shares]:
        name = sh["name"]
        if name.upper() in _SMB_ADMIN_SHARES or sh["type"] != "Disk":
            sh["access"] = "skipped"
            continue
        probe = await _exec(
            ["smbclient", f"//{target}/{name}", "-N", "-p", "445", "-c", "recurse ON; ls"],
            timeout_s=25,
        )
        if probe.get("ok"):
            sh["access"] = "read"
            files = [ln.strip() for ln in (probe.get("stdout") or "").splitlines() if ln.strip()]
            readable[name] = files[:max_files_per_share]
        else:
            sh["access"] = "denied"

    # 3. Null-session user enumeration (cheap, one rpcclient call).
    users: list[str] = []
    ru = await _exec(["rpcclient", "-U", "", "-N", target, "-c", "enumdomusers"], timeout_s=25)
    if ru.get("ok"):
        users = re.findall(r"user:\[([^\]]+)\]", ru.get("stdout") or "")

    anon_readable = [s["name"] for s in shares if s.get("access") == "read"]
    return {
        "ok": True,
        "target": target,
        "shares": shares,
        "anonymous_readable_shares": anon_readable,
        "readable_share_contents": readable,
        "null_session_users": users[:200],
        "note": (
            "Anonymously readable shares often hold the foothold (creds in a "
            "config/script/Excel-macro). Pull interesting files and pass any creds "
            "to exploit. A populated user list enables password spraying / AS-REP / "
            "kerberoast."
        ),
    }


# AS-REP roastable: userAccountControl & DONT_REQ_PREAUTH (0x400000).
_UAC_DONT_REQ_PREAUTH = 0x400000
# Disabled account: userAccountControl & ACCOUNTDISABLE (0x2).
_UAC_ACCOUNTDISABLE = 0x2


def _ldif_entries(stdout: str) -> list[dict[str, list[str]]]:
    """Parse `ldapsearch` LDIF output into a list of {attr: [values]} entries.

    Entries are separated by blank lines. Handles base64 values (`attr:: b64`)
    and folded continuation lines (a line starting with a single space appends
    to the previous attribute value).
    """
    entries: list[dict[str, list[str]]] = []
    cur: dict[str, list[str]] = {}
    last: tuple[str, int] | None = None  # (attr, index-in-list) for fold continuation
    for raw in stdout.splitlines():
        if not raw.strip() or raw.startswith("#"):
            if cur:
                entries.append(cur)
                cur, last = {}, None
            continue
        if raw.startswith(" ") and last is not None:  # folded continuation
            attr, idx = last
            cur[attr][idx] += raw[1:]
            continue
        if ":" not in raw:
            continue
        attr, _, val = raw.partition(":")
        attr = attr.strip()
        if val.startswith(":"):  # base64-encoded value (`attr:: ...`)
            try:
                val = base64.b64decode(val[1:].strip()).decode("utf-8", "replace")
            except (binascii.Error, ValueError):
                val = val[1:].strip()
        else:
            val = val.strip()
        cur.setdefault(attr, []).append(val)
        last = (attr, len(cur[attr]) - 1)
    if cur:
        entries.append(cur)
    return entries


def _domain_from_base_dn(base_dn: str) -> str:
    """`DC=megabank,DC=local` -> `megabank.local`."""
    return ".".join(re.findall(r"DC=([^,]+)", base_dn, flags=re.IGNORECASE))


@app.tool()
async def ldap_enum(
    target: str,
    base_dn: str = "",
    username: str = "",
    password: str = "",
    port: int = 389,
    max_users: int = 500,
) -> dict[str, Any]:
    """LDAP enumeration of an Active Directory domain (ports 389/636).

    Pulls the *real* domain user/group set so the agent never guesses account
    names. Reads the rootDSE anonymously to learn the naming context (domain),
    then enumerates `person` users and groups — flagging AS-REP-roastable
    accounts (`DONT_REQ_PREAUTH`) and kerberoastable accounts (a
    `servicePrincipalName`). Anonymous bind first; pass `username`/`password`
    for the authoritative authenticated dump when null bind is refused (modern
    AD usually requires it).

    Read-only. Use the enumerated user list to drive password spraying /
    AS-REP / kerberoast in exploit — do not invent usernames.
    """
    host = f"ldap://{target}:{port}"

    # 1. rootDSE (anonymous) — learn the default naming context / domain.
    root = await _exec(
        ["ldapsearch", "-x", "-H", host, "-s", "base", "-b", "",
         "defaultNamingContext", "rootDomainNamingContext"],
        timeout_s=25,
    )
    if not base_dn:
        for e in _ldif_entries(root.get("stdout") or ""):
            ctx = e.get("defaultNamingContext") or e.get("rootDomainNamingContext")
            if ctx:
                base_dn = ctx[0]
                break
    if not base_dn:
        return {
            "ok": False,
            "target": target,
            "error": "Could not determine the base DN from the rootDSE.",
            "rootdse_stderr": (root.get("stderr") or root.get("error") or "").strip()[:400],
            "hint": "Pass `base_dn` explicitly (e.g. DC=domain,DC=local), or the host "
                    "may not speak LDAP / port is filtered. Confirm 389/636 are open.",
        }

    domain = _domain_from_base_dn(base_dn)

    # 2. Bind args: anonymous, or simple bind via UPN (user@domain).
    bind = ["-x"]
    bind_mode = "anonymous"
    if username:
        upn = username if "@" in username or "\\" in username else (
            f"{username}@{domain}" if domain else username
        )
        bind = ["-x", "-D", upn, "-w", password]
        bind_mode = "authenticated"

    # 3. Enumerate person users with the attributes needed for triage.
    user_search = await _exec(
        ["ldapsearch", *bind, "-H", host, "-b", base_dn,
         "(&(objectClass=user)(objectCategory=person))",
         "sAMAccountName", "userAccountControl", "servicePrincipalName"],
        timeout_s=60,
    )
    out = user_search.get("stdout") or ""
    if not user_search.get("ok") and "sAMAccountName" not in out:
        err = (user_search.get("stderr") or user_search.get("error") or "").strip()
        refused = bind_mode == "anonymous" and (
            "successful bind must be completed" in err.lower()
            or "operations error" in err.lower()
            or "in order to perform" in err.lower()
        )
        return {
            "ok": False,
            "target": target,
            "base_dn": base_dn,
            "domain": domain,
            "bind": bind_mode,
            "error": err[:400] or "LDAP user search returned no entries.",
            "hint": ("Anonymous bind was refused (normal on modern AD). Re-run with "
                     "`username`/`password` once you have any valid credential — that "
                     "gives the authoritative user dump.") if refused else
                    "Search failed; check creds / base_dn / connectivity.",
        }

    users: list[str] = []
    asrep_roastable: list[str] = []
    kerberoastable: list[str] = []
    disabled: list[str] = []
    for e in _ldif_entries(out):
        sam = (e.get("sAMAccountName") or [""])[0]
        if not sam:
            continue
        users.append(sam)
        try:
            uac = int((e.get("userAccountControl") or ["0"])[0])
        except ValueError:
            uac = 0
        if uac & _UAC_ACCOUNTDISABLE:
            disabled.append(sam)
        if uac & _UAC_DONT_REQ_PREAUTH:
            asrep_roastable.append(sam)
        if e.get("servicePrincipalName"):
            kerberoastable.append(sam)
        if len(users) >= max_users:
            break

    # 4. Group names (cheap, light) — useful for privilege triage.
    groups: list[str] = []
    grp = await _exec(
        ["ldapsearch", *bind, "-H", host, "-b", base_dn,
         "(objectClass=group)", "sAMAccountName"],
        timeout_s=45,
    )
    if grp.get("ok"):
        for e in _ldif_entries(grp.get("stdout") or ""):
            sam = (e.get("sAMAccountName") or [""])[0]
            if sam:
                groups.append(sam)

    return {
        "ok": True,
        "target": target,
        "base_dn": base_dn,
        "domain": domain,
        "bind": bind_mode,
        "users": users,
        "user_count": len(users),
        "asrep_roastable": asrep_roastable,
        "kerberoastable": kerberoastable,
        "disabled_users": disabled,
        "groups": groups[:200],
        "note": (
            "This is the REAL user set — never guess account names. With no creds, "
            "the highest-probability foothold is a password spray (try username==password "
            "first). Only AS-REP-roast the accounts in `asrep_roastable` (empty = AS-REP is "
            "dead on this box) and kerberoast `kerberoastable` once you hold a valid credential. "
            "An anonymous bind that returned nothing usually means you must re-run authenticated."
        ),
    }


def main() -> None:
    app.run(transport="streamable-http")


if __name__ == "__main__":
    main()
