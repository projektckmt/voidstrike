"""Signed RoE document verification tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from src.agent.roe_document import verify_roe_document
from src.schemas.engagement import RulesOfEngagement


@pytest.mark.asyncio
async def test_missing_doc_fails(tmp_path: Path) -> None:
    spec_roe = RulesOfEngagement(allowed_hosts=["app.example.com"])
    result = await verify_roe_document(tmp_path / "nope.yaml", spec_roe)
    assert result.document_exists is False
    assert result.ok is False


@pytest.mark.asyncio
async def test_matching_scope_ok(tmp_path: Path) -> None:
    doc = tmp_path / "roe.yaml"
    doc.write_text(yaml.safe_dump({
        "allowed_hosts": ["app.example.com", "api.example.com"],
        "allowed_networks": ["10.0.0.0/24"],
        "allowed_techniques": ["recon", "exploit"],
    }))
    spec_roe = RulesOfEngagement(
        allowed_hosts=["app.example.com"],
        allowed_networks=["10.0.0.0/24"],
        allowed_techniques=["recon"],
    )
    result = await verify_roe_document(doc, spec_roe)
    assert result.document_exists
    assert result.scope_violations == []
    assert result.ok


@pytest.mark.asyncio
async def test_spec_broader_than_doc_fails(tmp_path: Path) -> None:
    doc = tmp_path / "roe.yaml"
    doc.write_text(yaml.safe_dump({
        "allowed_hosts": ["app.example.com"],
    }))
    spec_roe = RulesOfEngagement(
        allowed_hosts=["app.example.com", "admin.example.com"],
    )
    result = await verify_roe_document(doc, spec_roe)
    assert result.scope_matches_spec is False
    assert any("admin.example.com" in v for v in result.scope_violations)
    assert not result.ok


@pytest.mark.asyncio
async def test_spec_extra_technique_blocks(tmp_path: Path) -> None:
    doc = tmp_path / "roe.yaml"
    doc.write_text(yaml.safe_dump({
        "allowed_hosts": ["app.example.com"],
        "allowed_techniques": ["recon"],
    }))
    spec_roe = RulesOfEngagement(
        allowed_hosts=["app.example.com"],
        allowed_techniques=["recon", "lateral_movement"],
    )
    result = await verify_roe_document(doc, spec_roe)
    assert result.scope_violations  # lateral_movement is not in signed scope


@pytest.mark.asyncio
async def test_binary_doc_returns_warnings_not_violations(tmp_path: Path) -> None:
    """PDF-like RoEs can't be cross-checked structurally; we warn and allow."""
    doc = tmp_path / "signed-roe.pdf"
    doc.write_bytes(b"%PDF-1.4 fake pdf bytes")
    spec_roe = RulesOfEngagement(allowed_hosts=["app.example.com"])
    result = await verify_roe_document(doc, spec_roe)
    assert result.document_exists
    assert result.scope_matches_spec is None  # can't tell
    assert result.scope_violations == []
