"""Schema tests — make sure the shapes round-trip and validation works."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.agent.subagents.exploit import ExploitResult
from src.agent.subagents.researcher import AttackCandidate, ResearchResult
from src.schemas.engagement import EngagementMode, EngagementSpec, RulesOfEngagement
from src.schemas.episodes import Episode, OutcomeTag
from src.schemas.findings import (
    ExposedService,
    Finding,
    StuckReport,
    SurfaceFindings,
)


class TestEngagementSpec:
    def test_minimal_ctf_spec(self) -> None:
        spec = EngagementSpec(name="box", mode=EngagementMode.CTF, targets=["10.10.10.5"])
        assert spec.mode is EngagementMode.CTF
        assert spec.profile == "eco"

    def test_engagement_mode_requires_signed_roe(self) -> None:
        # The mode resolver enforces this, but the schema is structurally valid.
        spec = EngagementSpec(name="real", mode=EngagementMode.ENGAGEMENT, targets=["app.example.com"])
        assert spec.roe.signed_by is None

    def test_yaml_roundtrip(self, tmp_path) -> None:
        path = tmp_path / "spec.yaml"
        path.write_text("""
name: test-box
mode: ctf
targets: ["10.10.10.5"]
budget_usd: 5.0
profile: test
""")
        spec = EngagementSpec.from_yaml(path)
        assert spec.name == "test-box"
        assert spec.budget_usd == 5.0


class TestRulesOfEngagement:
    def test_parsed_networks(self) -> None:
        roe = RulesOfEngagement(allowed_networks=["10.0.0.0/8", "172.16.0.0/12"])
        nets = roe.parsed_networks()
        assert len(nets) == 2

    def test_bad_cidr_raises_at_use(self) -> None:
        # The validator lets it in; the parser flags it.
        roe = RulesOfEngagement(allowed_networks=["bogus"])
        with pytest.raises(ValueError):
            roe.parsed_networks()


class TestFindings:
    def test_exposed_service_minimal(self) -> None:
        svc = ExposedService(host="10.0.0.1", port=22)
        assert svc.protocol == "tcp"

    def test_surface_findings_default_empty(self) -> None:
        sf = SurfaceFindings()
        assert sf.services == [] and sf.web == []

    def test_finding_round_trip(self) -> None:
        f = Finding(
            title="Outdated Apache",
            severity="high",
            host="10.0.0.1",
            description="Apache 2.4.49 vulnerable to CVE-2021-41773.",
            cve=["CVE-2021-41773"],
        )
        as_json = f.model_dump_json()
        again = Finding.model_validate_json(as_json)
        assert again.cve == ["CVE-2021-41773"]

    def test_stuck_report_minimal(self) -> None:
        r = StuckReport(engagement_id="e1", current_objective="root box")
        assert r.operator_questions == []

    def test_exploit_result_can_report_rce_without_shell(self) -> None:
        result = ExploitResult(
            rce_confirmed=True,
            rce_evidence="GET /MARKER-root callback observed",
            shell_session_name=None,
            blocked_on="reverse shell callback never arrived",
        )
        assert result.rce_confirmed is True
        assert result.shell_attempts == []

    def test_research_confirmed_lead_requires_candidate(self) -> None:
        with pytest.raises(ValidationError):
            ResearchResult(target_service="Flowise", lead_confirmed=True)

        result = ResearchResult(
            target_service="Flowise",
            lead_confirmed=True,
            candidates=[
                AttackCandidate(
                    cve="CVE-2025-59528",
                    name="CustomMCP RCE",
                    description="Function constructor injection",
                    confidence="high",
                    poc_trust="vetted",
                )
            ],
        )
        assert result.lead_confirmed is True


class TestEpisodes:
    def test_outcome_tag_values(self) -> None:
        assert OutcomeTag.NEW_FINDING == "new_finding"
        assert OutcomeTag.BLOCKED_BY_ROE == "blocked_by_roe"

    def test_episode_validation(self) -> None:
        from datetime import UTC, datetime
        ep = Episode(
            engagement_id="e1",
            agent_name="surface",
            timestamp=datetime.now(UTC),
            action="tool:nmap_quick",
            tool_input={"target": "10.0.0.1"},
        )
        assert ep.outcome_tag == OutcomeTag.NO_RESULT
