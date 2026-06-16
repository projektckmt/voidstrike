"""Research MCP server - compact CVE/POC intelligence tools.

The researcher subagent should not spend expensive model turns manually
wandering NVD, GitHub, and raw POC repositories. These tools collapse the common
research loop into small structured results the model can verify and hand to
the exploit subagent.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from mcp.server.fastmcp import FastMCP

app = FastMCP(
    "research",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
)

HTTP_TIMEOUT = float(os.environ.get("RESEARCH_HTTP_TIMEOUT", "20"))
MAX_FETCH_CHARS = 12000


def _headers() -> dict[str, str]:
    headers = {"User-Agent": "voidstrike-research/0.1"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    nvd_key = os.environ.get("NVD_API_KEY")
    if nvd_key:
        headers["apiKey"] = nvd_key
    return headers


def _cve_ids(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for match in re.findall(r"CVE-\d{4}-\d{4,}", value, flags=re.I):
            cve = match.upper()
            if cve not in out:
                out.append(cve)
    return out


def _first_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if isinstance(values, list) and values:
            item = values[0]
            cvss = item.get("cvssData") or {}
            return {
                "version": cvss.get("version"),
                "base_score": cvss.get("baseScore"),
                "severity": item.get("baseSeverity") or cvss.get("baseSeverity"),
                "vector": cvss.get("vectorString"),
            }
    return {}


def _english_description(cve: dict[str, Any]) -> str:
    for desc in cve.get("descriptions") or []:
        if desc.get("lang") == "en" and desc.get("value"):
            return str(desc["value"])
    return ""


def _summarize_nvd_item(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve") or {}
    refs = []
    # NVD 2.0: `cve.references` is a flat list of {url, source, tags}. (The old
    # `references.referenceData` shape was the retired 1.0 API.)
    for ref in cve.get("references") or []:
        if not isinstance(ref, dict):
            continue
        url = ref.get("url")
        if url:
            refs.append({
                "url": url,
                "source": ref.get("source"),
                "tags": ref.get("tags") or [],
            })
    descriptions = _english_description(cve)
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": descriptions[:1000],
        "cvss": _first_cvss(cve.get("metrics") or {}),
        "weaknesses": [
            d.get("value")
            for w in cve.get("weaknesses") or []
            for d in (w.get("description") or [])
            if d.get("lang") == "en" and d.get("value")
        ][:5],
        "references": refs[:10],
    }


def _nvd_query_params(product: str | None, version: str | None, cve_id: str | None) -> dict[str, Any]:
    if cve_id:
        return {"cveId": cve_id}
    query = " ".join(part for part in (product, version) if part).strip()
    return {"keywordSearch": query}


@app.tool()
async def cve_lookup(
    product: str | None = None,
    version: str | None = None,
    cve_id: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Look up CVEs via NVD and return compact structured entries.

    Pass `cve_id` for an exact lookup, or `product`/`version` for a keyword
    search. The output is intentionally capped: CVE id, description, CVSS,
    weaknesses, and top references.
    """
    if not cve_id and not product:
        return {"ok": False, "error": "need either cve_id or product"}

    params = _nvd_query_params(product, version, cve_id)
    params["resultsPerPage"] = max(1, min(int(limit), 20))

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"NVD lookup failed: {type(exc).__name__}: {exc}"}

    vulns = data.get("vulnerabilities") or []
    return {
        "ok": True,
        "source": "nvd",
        "query": params,
        "total_results": data.get("totalResults"),
        "results": [_summarize_nvd_item(item) for item in vulns[: params["resultsPerPage"]]],
    }


def _github_advisory_summary(item: dict[str, Any]) -> dict[str, Any]:
    vulnerabilities = item.get("vulnerabilities") or []
    return {
        "ghsa_id": item.get("ghsa_id"),
        "cve_id": item.get("cve_id"),
        "url": item.get("html_url"),
        "summary": item.get("summary"),
        "severity": item.get("severity"),
        "published_at": item.get("published_at"),
        "updated_at": item.get("updated_at"),
        "withdrawn_at": item.get("withdrawn_at"),
        "cvss": item.get("cvss") or {},
        "cwes": item.get("cwes") or [],
        "affected": [
            {
                "package": (v.get("package") or {}).get("name"),
                "ecosystem": (v.get("package") or {}).get("ecosystem"),
                "vulnerable_version_range": v.get("vulnerable_version_range"),
                "patched_versions": v.get("patched_versions"),
            }
            for v in vulnerabilities[:10]
            if isinstance(v, dict)
        ],
        "references": item.get("references") or [],
    }


def _looks_vendor_reference(ref: dict[str, Any]) -> bool:
    tags = " ".join(str(tag) for tag in ref.get("tags") or []).lower()
    source = str(ref.get("source") or "").lower()
    url = str(ref.get("url") or "").lower()
    haystack = f"{tags} {source} {url}"
    keywords = (
        "vendor", "advisory", "release", "changelog", "security",
        "patch", "commit", "github.com",
    )
    return any(keyword in haystack for keyword in keywords)


async def _nvd_reference_search(
    client: httpx.AsyncClient,
    *,
    product: str | None,
    version: str | None,
    cve_id: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    params = _nvd_query_params(product, version, cve_id)
    params["resultsPerPage"] = max(1, min(limit, 20))
    resp = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)
    resp.raise_for_status()
    refs: list[dict[str, Any]] = []
    for item in (resp.json().get("vulnerabilities") or []):
        cve = item.get("cve") or {}
        cve_name = cve.get("id")
        for ref in cve.get("references") or []:  # NVD 2.0: flat list, not referenceData
            if isinstance(ref, dict) and ref.get("url") and _looks_vendor_reference(ref):
                refs.append({
                    "cve": cve_name,
                    "url": ref.get("url"),
                    "source": ref.get("source"),
                    "tags": ref.get("tags") or [],
                })
    return refs[:limit]


@app.tool()
async def vendor_advisory_search(
    product: str | None = None,
    version: str | None = None,
    cve_id: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Find primary-source advisories/release notes for a product/version or CVE.

    Uses GitHub Security Advisories when `cve_id` or package-like `product` is
    available, plus NVD reference metadata filtered for vendor/advisory/patch
    links. Returns compact URLs and affected ranges; it does not fetch pages.
    """
    if not cve_id and not product:
        return {"ok": False, "error": "need either cve_id or product"}

    limit = max(1, min(int(limit), 20))
    github_params: dict[str, Any] = {"per_page": limit}
    if cve_id:
        github_params["cve_id"] = cve_id
    elif product:
        github_params["affects"] = product

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            gh_resp = await client.get("https://api.github.com/advisories", params=github_params)
            github_advisories: list[dict[str, Any]] = []
            if gh_resp.status_code < 400:
                data = gh_resp.json()
                if isinstance(data, list):
                    github_advisories = [_github_advisory_summary(item) for item in data[:limit]]

            nvd_refs = await _nvd_reference_search(
                client,
                product=product,
                version=version,
                cve_id=cve_id,
                limit=limit,
            )
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"vendor advisory search failed: {type(exc).__name__}: {exc}"}

    return {
        "ok": True,
        "query": {"product": product, "version": version, "cve_id": cve_id},
        "github_advisories": github_advisories,
        "nvd_references": nvd_refs,
    }


@app.tool()
async def epss_lookup(cve_ids: list[str]) -> dict[str, Any]:
    """Look up FIRST EPSS exploit probability for CVE ids."""
    ids = _cve_ids(cve_ids)
    if not ids:
        return {"ok": False, "error": "need at least one CVE id"}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": ",".join(ids)},
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"EPSS lookup failed: {type(exc).__name__}: {exc}"}

    rows = data.get("data") or []
    return {
        "ok": True,
        "source": "first-epss",
        "requested": ids,
        "date": data.get("date"),
        "results": [
            {
                "cve": row.get("cve"),
                "epss": row.get("epss"),
                "percentile": row.get("percentile"),
                "date": row.get("date"),
            }
            for row in rows
            if isinstance(row, dict)
        ],
    }


def _kev_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve": item.get("cveID"),
        "vendor_project": item.get("vendorProject"),
        "product": item.get("product"),
        "vulnerability_name": item.get("vulnerabilityName"),
        "date_added": item.get("dateAdded"),
        "short_description": item.get("shortDescription"),
        "required_action": item.get("requiredAction"),
        "due_date": item.get("dueDate"),
        "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
        "notes": item.get("notes"),
    }


@app.tool()
async def cisa_kev_lookup(cve_ids: list[str] | None = None, query: str | None = None) -> dict[str, Any]:
    """Check CISA Known Exploited Vulnerabilities by CVE ids or text query."""
    ids = set(_cve_ids(cve_ids or []))
    needle = (query or "").lower().strip()
    if not ids and not needle:
        return {"ok": False, "error": "need cve_ids or query"}

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"CISA KEV lookup failed: {type(exc).__name__}: {exc}"}

    matches = []
    for item in data.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").upper()
        haystack = " ".join(str(item.get(key) or "") for key in (
            "vendorProject", "product", "vulnerabilityName", "shortDescription",
        )).lower()
        if (ids and cve in ids) or (needle and needle in haystack):
            matches.append(_kev_summary(item))

    return {
        "ok": True,
        "source": "cisa-kev",
        "catalog_version": data.get("catalogVersion"),
        "date_released": data.get("dateReleased"),
        "requested": sorted(ids) if ids else query,
        "known_exploited": bool(matches),
        "results": matches[:20],
    }


def _repo_red_flags(repo: dict[str, Any]) -> list[str]:
    flags = []
    description = str(repo.get("description") or "").lower()
    name = str(repo.get("full_name") or "").lower()
    if "generator" in description or "generator" in name:
        flags.append("generic-generator")
    if "checker" in description or "scanner" in description:
        flags.append("scanner-not-poc")
    if (repo.get("stargazers_count") or 0) == 0:
        flags.append("zero-stars")
    if repo.get("archived"):
        flags.append("archived")
    return flags


def _repo_summary(repo: dict[str, Any]) -> dict[str, Any]:
    return {
        "full_name": repo.get("full_name"),
        "url": repo.get("html_url"),
        "description": repo.get("description"),
        "stars": repo.get("stargazers_count"),
        "forks": repo.get("forks_count"),
        "language": repo.get("language"),
        "pushed_at": repo.get("pushed_at"),
        "archived": repo.get("archived"),
        "red_flags": _repo_red_flags(repo),
    }


@app.tool()
async def github_poc_search(query: str, limit: int = 10) -> dict[str, Any]:
    """Search GitHub repositories for POCs and return trust-relevant metadata."""
    q = f"{query} (poc OR exploit OR vulnerability)"
    params = {
        "q": q,
        "sort": "stars",
        "order": "desc",
        "per_page": max(1, min(int(limit), 20)),
    }
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers()) as client:
            resp = await client.get("https://api.github.com/search/repositories", params=params)
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"GitHub search failed: {type(exc).__name__}: {exc}"}

    items = data.get("items") or []
    return {
        "ok": True,
        "source": "github",
        "query": q,
        "total_count": data.get("total_count"),
        "results": [_repo_summary(repo) for repo in items[: params["per_page"]]],
    }


def _parse_github_repo(value: str) -> tuple[str, str] | None:
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", value):
        owner, repo = value.split("/", 1)
        return owner, repo
    parsed = urlparse(value)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _raw_github_blob_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 5 or parts[2] != "blob":
        return None
    owner, repo, _, ref, *path_parts = parts
    path = "/".join(quote(p) for p in path_parts)
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"


_INTERESTING_ROOT_FILES = (
    "README.md",
    "README.txt",
    "readme.md",
    "exploit.py",
    "poc.py",
    "requirements.txt",
    "package.json",
    "Dockerfile",
)


async def _fetch_text(client: httpx.AsyncClient, url: str, max_chars: int) -> dict[str, Any]:
    resp = await client.get(url)
    resp.raise_for_status()
    text = resp.text
    return {
        "url": url,
        "content": text[:max_chars],
        "truncated": len(text) > max_chars,
        "size_chars": len(text),
    }


def _exploitdb_id(value: str) -> str | None:
    if re.fullmatch(r"\d{2,}", value.strip()):
        return value.strip()
    parsed = urlparse(value)
    if "exploit-db.com" not in parsed.netloc.lower():
        return None
    match = re.search(r"/(?:exploits|raw)/(\d+)", parsed.path)
    return match.group(1) if match else None


def _exploitdb_hints(content: str) -> dict[str, Any]:
    first_lines = "\n".join(content.splitlines()[:25])
    return {
        "cves": _cve_ids([content]),
        "has_usage": bool(re.search(r"(usage:|options:|python\d?\s+|perl\s+|ruby\s+)", first_lines, re.I)),
        "mentions_reverse_shell": bool(re.search(r"(reverse shell|/dev/tcp|nc\s+-|connect back)", content, re.I)),
        "mentions_auth": bool(re.search(r"(auth|login|cookie|session|csrf|token)", content, re.I)),
        "first_lines": first_lines[:2000],
    }


@app.tool()
async def exploitdb_fetch(edb_id_or_url: str, max_chars: int = MAX_FETCH_CHARS) -> dict[str, Any]:
    """Fetch raw Exploit-DB source by EDB id or exploit-db URL."""
    edb_id = _exploitdb_id(edb_id_or_url)
    if not edb_id:
        return {"ok": False, "error": "need an Exploit-DB id or exploit-db.com URL"}
    max_chars = max(1000, min(int(max_chars), 50000))
    raw_url = f"https://www.exploit-db.com/raw/{edb_id}"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers(), follow_redirects=True) as client:
            item = await _fetch_text(client, raw_url, max_chars)
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"Exploit-DB fetch failed: {type(exc).__name__}: {exc}"}
    return {
        "ok": True,
        "source": "exploit-db",
        "edb_id": edb_id,
        "url": f"https://www.exploit-db.com/exploits/{edb_id}",
        "raw_url": raw_url,
        "content": item["content"],
        "truncated": item["truncated"],
        "size_chars": item["size_chars"],
        "hints": _exploitdb_hints(str(item["content"])),
    }


@app.tool()
async def fetch_poc(url_or_repo: str, max_files: int = 6, max_chars: int = MAX_FETCH_CHARS) -> dict[str, Any]:
    """Fetch relevant POC files from a GitHub repo/blob URL or a direct text URL.

    For repo roots this fetches only high-signal root files (README, exploit.py,
    requirements, package manifest, Dockerfile) rather than the whole repo.
    """
    max_files = max(1, min(int(max_files), 10))
    max_chars = max(1000, min(int(max_chars), 50000))
    files: list[dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers=_headers(), follow_redirects=True) as client:
            raw_blob = _raw_github_blob_url(url_or_repo)
            if raw_blob:
                item = await _fetch_text(client, raw_blob, max_chars)
                item["path"] = raw_blob.rsplit("/", 1)[-1]
                files.append(item)
            elif repo := _parse_github_repo(url_or_repo):
                owner, name = repo
                api_url = f"https://api.github.com/repos/{owner}/{name}/contents"
                listing = await client.get(api_url)
                listing.raise_for_status()
                entries = listing.json()
                if not isinstance(entries, list):
                    entries = []
                by_name = {entry.get("name"): entry for entry in entries if isinstance(entry, dict)}
                selected = [
                    by_name[name]
                    for name in _INTERESTING_ROOT_FILES
                    if name in by_name and by_name[name].get("download_url")
                ][:max_files]
                for entry in selected:
                    item = await _fetch_text(client, entry["download_url"], max_chars)
                    item["path"] = entry.get("path") or entry.get("name")
                    files.append(item)
            else:
                item = await _fetch_text(client, url_or_repo, max_chars)
                item["path"] = urlparse(url_or_repo).path.rsplit("/", 1)[-1] or "download"
                files.append(item)
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"POC fetch failed: {type(exc).__name__}: {exc}"}

    return {"ok": True, "file_count": len(files), "files": files}


_RED_FLAG_PATTERNS = {
    "credential_access": re.compile(r"(password|passwd|shadow|id_rsa|token|secret)", re.I),
    "destructive": re.compile(r"(rm\s+-rf|mkfs|shutdown|reboot|del\s+/[sq])", re.I),
    "obfuscation": re.compile(r"(base64\s+-d|fromCharCode|eval\(|exec\(|pickle\.loads)", re.I),
    "external_callback": re.compile(r"(webhook|pastebin|discord(app)?\.com|telegram|ngrok)", re.I),
}

_USEFUL_PATTERNS = {
    "http_endpoint": re.compile(r"(/api/[A-Za-z0-9_./-]+|https?://[^\s'\"<>]+)", re.I),
    "reverse_shell": re.compile(r"(reverse shell|/dev/tcp|nc\s+-[^\n]*e|bash\s+-i)", re.I),
    "auth_bypass": re.compile(r"(auth bypass|authentication bypass|jwt|session|cookie)", re.I),
    "rce": re.compile(r"(remote code execution|rce|command injection|exec\()", re.I),
}


@app.tool()
async def poc_static_review(files: list[dict[str, Any]]) -> dict[str, Any]:
    """Review fetched POC file contents for useful signals and red flags."""
    red_flags: dict[str, list[str]] = {}
    useful_signals: dict[str, list[str]] = {}
    total_chars = 0
    for file in files:
        path = str(file.get("path") or file.get("url") or "file")
        content = str(file.get("content") or "")
        total_chars += len(content)
        for name, pattern in _RED_FLAG_PATTERNS.items():
            matches = sorted(set(m.group(0)[:120] for m in pattern.finditer(content)))
            if matches:
                red_flags.setdefault(name, []).extend(matches[:5])
        for name, pattern in _USEFUL_PATTERNS.items():
            matches = sorted(set(m.group(0)[:160] for m in pattern.finditer(content)))
            if matches:
                useful_signals.setdefault(name, []).extend(f"{path}: {m}" for m in matches[:5])

    verdict = "vetted"
    if red_flags:
        verdict = "needs_review"
    if {"credential_access", "destructive"} & set(red_flags):
        verdict = "red_flags"
    return {
        "ok": True,
        "verdict": verdict,
        "files_reviewed": len(files),
        "total_chars_reviewed": total_chars,
        "red_flags": red_flags,
        "useful_signals": useful_signals,
    }


def _version_parts(version: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", version)
    return tuple(int(n) for n in nums[:6])


def _compare_versions(left: str, right: str) -> int:
    a = _version_parts(left)
    b = _version_parts(right)
    size = max(len(a), len(b), 1)
    a = a + (0,) * (size - len(a))
    b = b + (0,) * (size - len(b))
    return (a > b) - (a < b)


def _range_matches(version: str, advisory_range: str) -> bool | None:
    constraints = re.findall(r"(<=|>=|<|>|=|==)\s*v?([0-9][A-Za-z0-9_.-]*)", advisory_range)
    if not constraints:
        bare = re.search(r"\bv?([0-9]+(?:\.[0-9A-Za-z_-]+)+)\b", advisory_range)
        if not bare:
            return None
        return _compare_versions(version, bare.group(1)) == 0
    for op, target in constraints:
        cmp = _compare_versions(version, target)
        if op in ("=", "==") and cmp != 0:
            return False
        if op == "<" and cmp >= 0:
            return False
        if op == "<=" and cmp > 0:
            return False
        if op == ">" and cmp <= 0:
            return False
        if op == ">=" and cmp < 0:
            return False
    return True


@app.tool()
async def affected_version_check(
    current_version: str,
    advisory_ranges: list[str],
    product: str | None = None,
) -> dict[str, Any]:
    """Check a current version against advisory range strings.

    Handles common semver-ish constraints like `< 3.0.5`, `<= 1.2.0`, and
    `>= 2.0.0 < 2.1.4`. Unknown/unparseable ranges are returned for manual
    review instead of guessed.
    """
    results = []
    affected = False
    unknown = []
    for item in advisory_ranges:
        match = _range_matches(current_version, item)
        results.append({"range": item, "matches": match})
        if match is True:
            affected = True
        elif match is None:
            unknown.append(item)
    return {
        "ok": True,
        "product": product,
        "current_version": current_version,
        "affected": affected,
        "unknown_ranges": unknown,
        "results": results,
    }


def main() -> None:
    app.run(transport="streamable-http")


if __name__ == "__main__":
    main()
