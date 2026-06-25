"""Report builder tests."""

from __future__ import annotations

from src.agent.report import build_report


def test_report_groups_by_host() -> None:
    findings = [
        {"title": "RCE in Apache", "severity": "critical", "host": "10.0.0.1",
         "description": "Apache 2.4.49 path traversal", "cve": ["CVE-2021-41773"]},
        {"title": "Weak SSH password", "severity": "medium", "host": "10.0.0.2",
         "description": "root:admin worked"},
        {"title": "SUID nmap", "severity": "high", "host": "10.0.0.1",
         "description": "/usr/bin/nmap with SUID bit, GTFOBins escape"},
    ]
    report = build_report(
        engagement_name="test",
        mode="ctf",
        target_summary=["10.0.0.1", "10.0.0.2"],
        findings=findings,
        flags=["flag{aaa}"],
        failed_objectives=[],
    )
    assert set(report.findings_by_host.keys()) == {"10.0.0.1", "10.0.0.2"}
    assert len(report.findings_by_host["10.0.0.1"]) == 2


def test_severity_rollup() -> None:
    findings = [
        {"title": "x", "severity": "critical", "host": "h1", "description": ""},
        {"title": "y", "severity": "high", "host": "h1", "description": ""},
        {"title": "z", "severity": "high", "host": "h2", "description": ""},
    ]
    report = build_report(
        engagement_name="t", mode="lab", target_summary=[],
        findings=findings, flags=[], failed_objectives=[],
    )
    assert report.severity_rollup == {"critical": 1, "high": 2}


def test_findings_sorted_by_severity_within_host() -> None:
    findings = [
        {"title": "low one", "severity": "low", "host": "h1", "description": ""},
        {"title": "crit one", "severity": "critical", "host": "h1", "description": ""},
        {"title": "med one", "severity": "medium", "host": "h1", "description": ""},
    ]
    report = build_report(
        engagement_name="t", mode="ctf", target_summary=[],
        findings=findings, flags=[], failed_objectives=[],
    )
    titles = [r.finding["title"] for r in report.findings_by_host["h1"]]
    assert titles == ["crit one", "med one", "low one"]


def test_attack_refs_attached() -> None:
    findings = [
        {"title": "Apache CVE-2021-41773 web exploit",
         "severity": "critical", "host": "h1",
         "description": "deliver_via_web triggered RCE"},
    ]
    report = build_report(
        engagement_name="t", mode="engagement", target_summary=[],
        findings=findings, flags=[], failed_objectives=[],
    )
    refs = report.findings_by_host["h1"][0].attack_refs
    assert any(r.technique_id == "T1190" for r in refs)


def test_markdown_output_contains_sections() -> None:
    findings = [
        {"title": "Test", "severity": "high", "host": "h1", "description": "d", "cve": ["CVE-2021-1"]},
    ]
    report = build_report(
        engagement_name="my-eng", mode="ctf", target_summary=["10.0.0.1"],
        findings=findings, flags=["flag{x}"], failed_objectives=["Other host"],
        executive_summary="we rooted it",
    )
    md = report.to_markdown()
    assert "# Voidstrike report — my-eng" in md
    assert "## Executive summary" in md
    assert "## Severity rollup" in md
    assert "## Findings by host" in md
    assert "flag{x}" in md
    assert "Other host" in md


def test_report_has_no_appendix_section() -> None:
    # The verbatim command/output appendix was removed — the walkthrough is the
    # only command record now.
    report = build_report(
        engagement_name="e", mode="ctf", target_summary=["10.0.0.1"],
        findings=[], flags=[], failed_objectives=[],
    )
    assert "## Appendix" not in report.to_markdown()


def test_walkthrough_is_rendered_as_main_body() -> None:
    report = build_report(
        engagement_name="e", mode="ctf", target_summary=["10.0.0.1"],
        findings=[], flags=["user.txt: abc"], failed_objectives=[],
        walkthrough="### Recon\nnmap finds SSH and HTTP:\n```\n$ nmap 10.0.0.1\n```",
    )
    md = report.to_markdown()
    assert "## Walkthrough" in md
    assert "nmap finds SSH and HTTP" in md
    # walkthrough sits above the structured findings section
    assert md.index("## Walkthrough") < md.index("## Findings by host")
