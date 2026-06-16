"""Tests for the research MCP server helpers."""

from __future__ import annotations

import asyncio

from src.mcp_servers.research import server


def _run(coro):
    return asyncio.run(coro)


def test_summarize_nvd_item_extracts_core_fields() -> None:
    item = {
        "cve": {
            "id": "CVE-2025-12345",
            "published": "2025-01-01T00:00:00.000",
            "lastModified": "2025-01-02T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Remote code execution in Example."}],
            "metrics": {
                "cvssMetricV31": [{
                    "baseSeverity": "CRITICAL",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "vectorString": "CVSS:3.1/AV:N/AC:L",
                    },
                }]
            },
            "weaknesses": [{
                "description": [{"lang": "en", "value": "CWE-78"}],
            }],
            # NVD 2.0: references is a flat list (the old test used the retired
            # 1.0 `referenceData` shape, which is exactly the bug that crashed
            # cve_lookup with "'list' object has no attribute 'get'").
            "references": [{
                "url": "https://vendor.example/advisory",
                "source": "vendor",
                "tags": ["Vendor Advisory"],
            }],
        }
    }

    out = server._summarize_nvd_item(item)

    assert out["id"] == "CVE-2025-12345"
    assert out["cvss"]["base_score"] == 9.8
    assert out["weaknesses"] == ["CWE-78"]
    assert out["references"][0]["url"] == "https://vendor.example/advisory"


def test_summarize_nvd_item_tolerates_legacy_or_malformed_references() -> None:
    # A dict (1.0 shape) or other junk in `references` must not crash — it just
    # yields no references rather than raising.
    for refs in ({"referenceData": [{"url": "x"}]}, None, ["not-a-dict"]):
        out = server._summarize_nvd_item({"cve": {"id": "CVE-1", "references": refs}})
        assert out["references"] == []


def test_parse_github_repo_accepts_repo_or_url() -> None:
    assert server._parse_github_repo("owner/repo") == ("owner", "repo")
    assert server._parse_github_repo("https://github.com/owner/repo") == ("owner", "repo")
    assert server._parse_github_repo("https://example.com/owner/repo") is None


def test_raw_github_blob_url_converts_to_raw() -> None:
    raw = server._raw_github_blob_url("https://github.com/o/r/blob/main/exploit.py")
    assert raw == "https://raw.githubusercontent.com/o/r/main/exploit.py"


def test_cve_ids_extracts_and_deduplicates() -> None:
    assert server._cve_ids(["CVE-2025-1234 and cve-2025-1234", "CVE-2024-99999"]) == [
        "CVE-2025-1234",
        "CVE-2024-99999",
    ]


def test_exploitdb_id_accepts_ids_and_urls() -> None:
    assert server._exploitdb_id("12345") == "12345"
    assert server._exploitdb_id("https://www.exploit-db.com/exploits/12345") == "12345"
    assert server._exploitdb_id("https://www.exploit-db.com/raw/12345") == "12345"
    assert server._exploitdb_id("https://example.com/exploits/12345") is None


def test_exploitdb_hints_extract_core_signals() -> None:
    hints = server._exploitdb_hints(
        "# CVE-2025-12345\n"
        "Usage: python3 exploit.py http://target\n"
        "Reverse shell via /dev/tcp after login cookie is set\n"
    )
    assert hints["cves"] == ["CVE-2025-12345"]
    assert hints["has_usage"] is True
    assert hints["mentions_reverse_shell"] is True
    assert hints["mentions_auth"] is True


def test_kev_summary_uses_cisa_fields() -> None:
    out = server._kev_summary({
        "cveID": "CVE-2025-12345",
        "vendorProject": "Example",
        "product": "Widget",
        "vulnerabilityName": "Widget RCE",
        "dateAdded": "2025-01-01",
        "knownRansomwareCampaignUse": "Known",
    })
    assert out["cve"] == "CVE-2025-12345"
    assert out["vendor_project"] == "Example"
    assert out["known_ransomware_campaign_use"] == "Known"


def test_github_advisory_summary_extracts_affected_ranges() -> None:
    out = server._github_advisory_summary({
        "ghsa_id": "GHSA-123",
        "cve_id": "CVE-2025-12345",
        "summary": "Example advisory",
        "severity": "critical",
        "vulnerabilities": [{
            "package": {"name": "flowise", "ecosystem": "npm"},
            "vulnerable_version_range": "< 3.0.6",
            "patched_versions": "3.0.6",
        }],
    })
    assert out["cve_id"] == "CVE-2025-12345"
    assert out["affected"][0]["package"] == "flowise"
    assert out["affected"][0]["vulnerable_version_range"] == "< 3.0.6"


def test_poc_static_review_flags_and_signals() -> None:
    files = [{
        "path": "exploit.py",
        "content": (
            "print('Remote Code Execution')\n"
            "url = 'http://target/api/v1/run'\n"
            "token = open('/tmp/token').read()\n"
        ),
    }]

    out = _run(server.poc_static_review(files))

    assert out["ok"] is True
    assert out["verdict"] in {"needs_review", "red_flags"}
    assert "credential_access" in out["red_flags"]
    assert "http_endpoint" in out["useful_signals"]
    assert "rce" in out["useful_signals"]


def test_affected_version_check_handles_ranges() -> None:
    out = _run(server.affected_version_check(
        current_version="3.0.5",
        advisory_ranges=["< 3.0.6", ">= 2.0.0 < 3.0.0", "not parseable"],
        product="Flowise",
    ))

    assert out["ok"] is True
    assert out["affected"] is True
    assert out["results"][0]["matches"] is True
    assert out["results"][1]["matches"] is False
    assert out["unknown_ranges"] == ["not parseable"]
