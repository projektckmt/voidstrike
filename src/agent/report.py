"""Engagement-report builder.

The analyst subagent uses this to produce the report. The deterministic parts
(severity rollup, ATT&CK labelling, host grouping) live here so the report
cannot hallucinate counts or invent CVEs. The LLM contributes prose into the
descriptive fields.

ATT&CK mapping is the *only* part of the workflow that uses ATT&CK.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from .attack_mapping import AttackRef, map_finding

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Per-step output cap in the methodology log — enough to show what a command
# returned without pasting a 200KB nmap dump into the writeup.
_STEP_OUTPUT_CHARS = 2000
# Tool-input keys that hold the actual command/target, in priority order. The
# first present one is shown as the step's "command"; otherwise the whole
# tool_input is rendered as compact JSON.
_COMMAND_KEYS = ("command", "cmd", "url", "target", "query", "payload", "args")


def _format_command(action: str, tool_input: dict[str, Any] | None) -> str:
    """Best-effort one-line command for a step: prefer a recognisable command
    field from `tool_input`, else compact JSON, else the bare action."""
    if isinstance(tool_input, dict) and tool_input:
        for key in _COMMAND_KEYS:
            val = tool_input.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        try:
            return json.dumps(tool_input, sort_keys=True, default=str)
        except (TypeError, ValueError):
            return str(tool_input)
    return action


# Output fields, in priority order, that hold the human-readable result inside a
# tool's JSON envelope — so the appendix shows the command's actual stdout/body
# instead of a wall of `{"ok": true, "output": "..."}`.
_OUTPUT_KEYS = ("output", "stdout", "body", "initial_output", "result", "note")


def _clean_output(tool_output: Any) -> str:
    """Pull the readable result out of a tool's output, de-JSON'd when possible.

    Most tools return a JSON envelope (`{"ok": true, "output": "<stdout>"}`); show
    the inner stdout/body. Fall back to the raw string otherwise."""
    if tool_output is None:
        return ""
    text = tool_output if isinstance(tool_output, str) else str(tool_output)
    text = text.strip()
    if not text:
        return ""
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text
    if isinstance(parsed, dict):
        for key in _OUTPUT_KEYS:
            val = parsed.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        # No recognised text field — drop noisy bookkeeping keys, show the rest.
        slim = {k: v for k, v in parsed.items() if k not in ("ok", "revision")}
        return json.dumps(slim, indent=2, default=str) if slim else text
    return text


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
    # Chronological episode log (commands + outputs) — the ground-truth appendix.
    timeline: list[dict[str, Any]] = field(default_factory=list)

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
        if self.timeline:
            lines.append("")
            lines.extend(self._methodology_lines())
        return "\n".join(lines)

    def _methodology_lines(self) -> list[str]:
        """Ground-truth command-and-output log replayed from the episode log.

        This is the verbatim appendix the human-readable Walkthrough is built
        from; each step renders shell-style (`$ <command>` + its output)."""
        lines = ["## Appendix — full command & output log", ""]
        lines.append(
            "_Every target-facing tool call in order, verbatim from the episode "
            f"log. Outputs trimmed to {_STEP_OUTPUT_CHARS} chars per step._"
        )
        lines.append("")
        for i, step in enumerate(self.timeline, 1):
            agent = step.get("agent_name") or "?"
            action = str(step.get("action") or "").strip() or "(action)"
            outcome = step.get("outcome_tag") or ""
            command = _format_command(action, step.get("tool_input"))
            lines.append(f"### {i}. `{agent}` · {action}" + (f" · {outcome}" if outcome else ""))
            output = _clean_output(step.get("tool_output"))
            block = "```\n"
            if command and command != action:
                block += f"$ {command}\n"
            if output:
                trimmed = output[:_STEP_OUTPUT_CHARS]
                block += trimmed + ("\n… (output trimmed)" if len(output) > _STEP_OUTPUT_CHARS else "")
            block += "\n```"
            lines.append(block)
            if step.get("error"):
                lines.append(f"**error:** {step['error']}")
            lines.append("")
        return lines


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
    timeline: list[dict[str, Any]] | None = None,
) -> EngagementReport:
    """Materialize a structured `EngagementReport` from raw findings + state.

    Hosts are grouped, severities rolled up, ATT&CK labels attached. `walkthrough`
    is the analyst-authored narrative (the main body); `timeline` is the
    chronological episode log rendered as the ground-truth appendix.
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
        timeline=timeline or [],
    )
