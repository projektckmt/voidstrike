"""Research MCP server - compact CVE/POC intelligence tools.

The researcher subagent should not spend expensive model turns manually
wandering NVD, GitHub, and raw POC repositories. These tools collapse the common
research loop into small structured results the model can verify and hand to
the exploit subagent.
"""

from __future__ import annotations

import asyncio
import html as html_lib
import os
import re
import time
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

import httpx
from mcp.server.fastmcp import FastMCP

app = FastMCP(
    "research",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
)

HTTP_TIMEOUT = float(os.environ.get("RESEARCH_HTTP_TIMEOUT", "20"))
MAX_FETCH_CHARS = 12000

# --- NVD throttling guard ---------------------------------------------------
# NVD's public API rate-limits hard: ~5 requests per rolling 30s window without
# an API key (50 with one), and it sheds load with 503s and slow responses. The
# researcher fires cve_lookup / vendor_advisory_search in bursts (often several
# in one model step), which instantly self-trips a 503. Two defenses:
#   (3) serialize ALL NVD traffic through one lock and space it out, so a burst
#       can't exceed the window; and
#   (2) retry transient 503/429/timeout with exponential backoff, so a throttle
#       smooths over instead of surfacing as a hard tool failure.
# The spacing adapts to whether a key is present (set NVD_API_KEY to go faster);
# both knobs are env-overridable.
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_MAX_RETRIES = int(os.environ.get("NVD_MAX_RETRIES", "3"))
_NVD_LOCK = asyncio.Lock()
_nvd_last_request = 0.0


def _nvd_min_interval() -> float:
    """Minimum seconds between NVD requests. ~6s unkeyed (NVD's own guidance),
    ~0.6s when an API key raises the window to 50/30s. Override via env."""
    default = "0.6" if os.environ.get("NVD_API_KEY") else "6.0"
    return float(os.environ.get("NVD_MIN_INTERVAL_S", default))


async def _nvd_get(client: httpx.AsyncClient, params: dict[str, Any]) -> httpx.Response:
    """GET the NVD CVE API behind a global rate-limiter with retry/backoff.

    Serializes through `_NVD_LOCK` and enforces `_nvd_min_interval()` spacing
    (so concurrent callers queue rather than burst), and retries transient
    503/429/timeout up to `NVD_MAX_RETRIES` with exponential backoff. Non-
    transient statuses (e.g. 404) raise immediately, as before, for the caller's
    existing error handling. Raises the last transient error if retries run out.
    """
    global _nvd_last_request
    interval = _nvd_min_interval()
    last_exc: Exception | None = None

    for attempt in range(NVD_MAX_RETRIES):
        resp: httpx.Response | None = None
        async with _NVD_LOCK:
            wait = interval - (time.monotonic() - _nvd_last_request)
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                resp = await client.get(NVD_URL, params=params)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_exc = exc
            finally:
                _nvd_last_request = time.monotonic()

        if resp is not None and resp.status_code not in (429, 503):
            resp.raise_for_status()  # propagate non-transient 4xx as before
            return resp

        if resp is not None:  # 429/503 throttle
            last_exc = httpx.HTTPStatusError(
                f"NVD {resp.status_code} (rate-limited)",
                request=resp.request,
                response=resp,
            )
        if attempt < NVD_MAX_RETRIES - 1:
            await asyncio.sleep(min(interval * (2 ** attempt), 30.0))

    assert last_exc is not None
    raise last_exc


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
            resp = await _nvd_get(client, params)
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
    resp = await _nvd_get(client, params)
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


# --- open-web search --------------------------------------------------------
# Curated sources (NVD / GitHub advisories / Exploit-DB) miss blog write-ups,
# gist PoCs, and brand-new CVEs. `web_search` is the open-web fallback. It uses
# Tavily or Brave when a key is present (cleaner, more reliable), else keyless
# DuckDuckGo HTML — best-effort, since DDG throttles, so a failure is returned
# softly rather than raised. Results are uniform {title, url, snippet} the
# researcher then feeds to `fetch_poc` / `browser__goto`.
_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
_DDG_RESULT_RE = re.compile(
    r'<a[^>]*class="result__a"[^>]*href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>', re.S
)
_DDG_SNIPPET_RE = re.compile(r'class="result__snippet"[^>]*>(?P<snippet>.*?)</a>', re.S)
_TAG_RE = re.compile(r"<[^>]+>")


def _strip_html(text: str) -> str:
    return html_lib.unescape(_TAG_RE.sub("", text)).strip()


def _ddg_unwrap(href: str) -> str:
    """DDG wraps results as //duckduckgo.com/l/?uddg=<url-encoded>&...; unwrap it."""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        target = parse_qs(parsed.query).get("uddg")
        if target:
            return unquote(target[0])
    return href


def _parse_ddg_html(body: str, limit: int) -> list[dict[str, Any]]:
    snippets = _DDG_SNIPPET_RE.findall(body)
    results: list[dict[str, Any]] = []
    for i, m in enumerate(_DDG_RESULT_RE.finditer(body)):
        url = _ddg_unwrap(m.group("href"))
        title = _strip_html(m.group("title"))
        if url and title:
            results.append({
                "title": title,
                "url": url,
                "snippet": _strip_html(snippets[i]) if i < len(snippets) else "",
            })
        if len(results) >= limit:
            break
    return results


async def _ddg_search(client: httpx.AsyncClient, query: str, limit: int) -> tuple[str, list[dict[str, Any]]]:
    resp = await client.get(
        "https://html.duckduckgo.com/html/",
        params={"q": query},
        headers={"User-Agent": _BROWSER_UA},
    )
    resp.raise_for_status()
    return "duckduckgo", _parse_ddg_html(resp.text, limit)


async def _tavily_search(client: httpx.AsyncClient, query: str, limit: int, key: str) -> tuple[str, list[dict[str, Any]]]:
    resp = await client.post(
        "https://api.tavily.com/search",
        json={"api_key": key, "query": query, "max_results": limit},
    )
    resp.raise_for_status()
    results = [
        {"title": r.get("title", ""), "url": r.get("url", ""), "snippet": r.get("content", "")}
        for r in (resp.json().get("results") or [])[:limit]
    ]
    return "tavily", results


async def _brave_search(client: httpx.AsyncClient, query: str, limit: int, key: str) -> tuple[str, list[dict[str, Any]]]:
    resp = await client.get(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": query, "count": limit},
        headers={"X-Subscription-Token": key, "Accept": "application/json"},
    )
    resp.raise_for_status()
    web = ((resp.json().get("web") or {}).get("results")) or []
    results = [
        {"title": r.get("title", ""), "url": r.get("url", ""), "snippet": r.get("description", "")}
        for r in web[:limit]
    ]
    return "brave", results


@app.tool()
async def web_search(query: str, limit: int = 8) -> dict[str, Any]:
    """Open-web search for exploits / PoCs / write-ups.

    Use this as a FALLBACK when the curated sources (`cve_lookup`,
    `github_poc_search`, `exploitdb_fetch`) come up empty or the exact CVE is too
    new for them. Backend auto-selects: Tavily (`TAVILY_API_KEY`) or Brave
    (`BRAVE_API_KEY`) when a key is set, otherwise keyless DuckDuckGo (best-effort,
    may throttle). Returns ranked `{title, url, snippet}` — feed promising URLs to
    `fetch_poc` or `browser__goto`, and vet anything runnable with the
    `poc-trust-evaluation` skill before recommending it.
    """
    query = (query or "").strip()
    if not query:
        return {"ok": False, "error": "need a non-empty query"}
    limit = max(1, min(int(limit), 20))
    tavily = os.environ.get("TAVILY_API_KEY")
    brave = os.environ.get("BRAVE_API_KEY")

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            if tavily:
                source, results = await _tavily_search(client, query, limit, tavily)
            elif brave:
                source, results = await _brave_search(client, query, limit, brave)
            else:
                source, results = await _ddg_search(client, query, limit)
    except (httpx.HTTPError, ValueError) as exc:
        return {"ok": False, "error": f"web search failed ({type(exc).__name__}): {exc}"}

    return {"ok": True, "source": source, "query": query, "results": results}


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
