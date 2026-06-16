"""ATT&CK mapping tests."""

from __future__ import annotations

from src.agent.attack_mapping import map_episode, map_finding


def test_nmap_recon() -> None:
    ref = map_episode("surface__nmap_quick", "")
    assert ref is not None
    assert ref.tactic_id == "TA0043"
    assert ref.technique_id == "T1595.001"


def test_web_exploit() -> None:
    ref = map_episode("exploit__deliver_via_web", "uploaded file_upload")
    assert ref is not None
    assert ref.technique_id == "T1190"


def test_kerberoast() -> None:
    ref = map_episode("ad__kerberoast", "")
    assert ref is not None
    assert ref.technique_id == "T1558.003"


def test_no_match_returns_none() -> None:
    assert map_episode("orchestrator__think", "") is None


def test_finding_multi_mapping() -> None:
    finding = {
        "title": "Web app RCE via file_upload, escalated via SUID nmap",
        "evidence": "uploaded payload, then ran nmap --interactive",
        "description": "",
    }
    refs = map_finding(finding)
    techniques = {r.technique_id for r in refs}
    # The web vector AND the SUID escalation should be picked up.
    assert "T1190" in techniques
    assert "T1548.001" in techniques
