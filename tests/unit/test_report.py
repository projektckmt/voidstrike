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


def test_no_appendix_section_without_timeline() -> None:
    report = build_report(
        engagement_name="e", mode="ctf", target_summary=["10.0.0.1"],
        findings=[], flags=[], failed_objectives=[],
    )
    assert "## Appendix" not in report.to_markdown()


def test_methodology_renders_commands_and_outputs() -> None:
    timeline = [
        {
            "agent_name": "surface", "timestamp": "2026-06-10T00:00:00+00:00",
            "action": "nmap scan", "tool_input": {"command": "nmap -sV 10.0.0.1"},
            "tool_output": "22/tcp open ssh\n80/tcp open http",
            "outcome_tag": "new_finding", "error": None,
        },
        {
            "agent_name": "exploit", "action": "deliver payload",
            "tool_input": {"url": "http://10.0.0.1/upload"},
            "tool_output": "x" * 5000,  # exercises the per-step trim
            "outcome_tag": "shell", "error": None,
        },
    ]
    report = build_report(
        engagement_name="e", mode="ctf", target_summary=["10.0.0.1"],
        findings=[], flags=[], failed_objectives=[], timeline=timeline,
    )
    md = report.to_markdown()
    assert "## Appendix — full command & output log" in md
    assert "$ nmap -sV 10.0.0.1" in md        # command rendered shell-style
    assert "22/tcp open ssh" in md            # verbatim output
    assert "http://10.0.0.1/upload" in md     # url key used as command
    assert "… (output trimmed)" in md         # long output capped
    assert "`surface`" in md and "`exploit`" in md


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


def test_appendix_dejsons_tool_output() -> None:
    timeline = [{
        "agent_name": "exploit", "action": "shell__tmux_exec",
        "tool_input": {"command": "id"},
        "tool_output": '{"ok": true, "output": "uid=0(root) gid=0(root)", "new_output": true}',
        "outcome_tag": "no_result", "error": None,
    }]
    report = build_report(
        engagement_name="e", mode="ctf", target_summary=["10.0.0.1"],
        findings=[], flags=[], failed_objectives=[], timeline=timeline,
    )
    md = report.to_markdown()
    assert "$ id" in md
    assert "uid=0(root) gid=0(root)" in md   # inner stdout surfaced
    assert '"ok": true' not in md            # JSON envelope stripped
