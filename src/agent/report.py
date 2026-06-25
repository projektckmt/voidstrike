"""Engagement-report builder.

The analyst subagent uses this to produce the report. The deterministic parts
(severity rollup, ATT&CK labelling, host grouping) live here so the report
cannot hallucinate counts or invent CVEs. The LLM contributes prose into the
descriptive fields.

ATT&CK mapping is the *only* part of the workflow that uses ATT&CK.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .attack_mapping import AttackRef, map_finding

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class ReportedFinding:
    finding: dict[str, Any]
    attack_refs: list[AttackRef] = field(default_factory=list)


@dataclass
class EngagementReport:
    engagement_name: str
    mode: str
    target_summary: list[str]
    findings_by_host: dict[str, list[ReportedFinding]] = field(default_factory=dict)
    severity_rollup: dict[str, int] = field(default_factory=dict)
    failed_objectives: list[str] = field(default_factory=list)
    flag_captures: list[str] = field(default_factory=list)
    executive_summary: str = ""
    appendix_episode_summary: str = ""
    # Analyst-authored narrative walkthrough (oxdf/HTB-writeup style): prose +
    # the actual commands run + key output, quoted from the log. The main body.
    walkthrough: str = ""

    def to_markdown(self) -> str:
        lines: list[str] = []
        lines.append(f"# Voidstrike report — {self.engagement_name}")
        lines.append("")
        lines.append(f"**Mode:** {self.mode}  ")
        lines.append(f"**Targets:** {', '.join(self.target_summary)}  ")
        lines.append("")
        lines.append("## Executive summary")
        lines.append(self.executive_summary or "_(none provided)_")
        lines.append("")
        lines.append("## Severity rollup")
        lines.append("")
        lines.append("| severity | count |")
        lines.append("|---|---|")
        for severity in SEVERITY_ORDER:
            if self.severity_rollup.get(severity):
                lines.append(f"| {severity} | {self.severity_rollup[severity]} |")
        lines.append("")
        if self.flag_captures:
            lines.append("## Flags captured")
            lines.append("")
            for flag in self.flag_captures:
                lines.append(f"- `{flag}`")
            lines.append("")
        if self.walkthrough.strip():
            lines.append("## Walkthrough")
            lines.append("")
            lines.append(self.walkthrough.strip())
            lines.append("")
        lines.append("## Findings by host")
        for host, items in self.findings_by_host.items():
            lines.append("")
            lines.append(f"### {host}")
            for item in items:
                f = item.finding
                lines.append(f"#### {f.get('title')} ({f.get('severity')})")
                if f.get("cve"):
                    lines.append(f"**CVE:** {', '.join(f['cve'])}")
                if item.attack_refs:
                    refs = ", ".join(
                        f"{r.technique_id} ({r.technique_name})"
                        for r in item.attack_refs
                    )
                    lines.append(f"**ATT&CK:** {refs}")
                if f.get("description"):
                    lines.append("")
                    lines.append(f["description"])
                if f.get("impact"):
                    lines.append("")
                    lines.append(f"**Impact:** {f['impact']}")
                if f.get("evidence"):
                    lines.append("")
                    lines.append("**Evidence:**")
                    lines.append("```")
                    lines.append(f["evidence"][:4000])
                    lines.append("```")
                if f.get("remediation"):
                    lines.append("")
                    lines.append(f"**Remediation:** {f['remediation']}")
                lines.append("")
        if self.failed_objectives:
            lines.append("## What we could not compromise")
            lines.append("")
            for fo in self.failed_objectives:
                lines.append(f"- {fo}")
            lines.append("")
        lines.append("## Episode summary")
        lines.append("")
        lines.append(self.appendix_episode_summary or "_(none)_")
        return "\n".join(lines)


def build_report(
    *,
    engagement_name: str,
    mode: str,
    target_summary: list[str],
    findings: list[dict[str, Any]],
    flags: list[str],
    failed_objectives: list[str],
    executive_summary: str = "",
    episode_summary: str = "",
    walkthrough: str = "",
) -> EngagementReport:
    """Materialize a structured `EngagementReport` from raw findings + state.

    Hosts are grouped, severities rolled up, ATT&CK labels attached. `walkthrough`
    is the analyst-authored narrative (the main body).
    """
    by_host: dict[str, list[ReportedFinding]] = defaultdict(list)
    rollup: dict[str, int] = defaultdict(int)

    for finding in findings:
        refs = map_finding(finding)
        by_host[finding.get("host", "(unknown)")].append(
            ReportedFinding(finding=finding, attack_refs=refs)
        )
        rollup[finding.get("severity", "info")] += 1

    # Sort findings inside each host by severity.
    severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for items in by_host.values():
        items.sort(key=lambda x: severity_rank.get(x.finding.get("severity", "info"), 99))

    return EngagementReport(
        engagement_name=engagement_name,
        mode=mode,
        target_summary=target_summary,
        findings_by_host=dict(by_host),
        severity_rollup=dict(rollup),
        failed_objectives=failed_objectives,
        flag_captures=flags,
        executive_summary=executive_summary,
        appendix_episode_summary=episode_summary,
        walkthrough=walkthrough,
    )
