"""Signed RoE document loader + verifier.

Engagement mode (plan §1.3) requires a signed Rules-of-Engagement document.
Phase 3 makes that mean something — we:

1. Verify the document file actually exists at the path.
2. If a `.sig` GPG signature is alongside, verify it (best-effort — degraded
   to "unverified" with a warning if `gpg` isn't on PATH).
3. If the document is a YAML/JSON file with structured scope, cross-check the
   `EngagementSpec.roe` matches what the document declares — refuse to start
   if the spec is broader than the signed scope.

The signature check is **advisory** at this stage — the deterministic RoE
gate still enforces the in-spec allowlist. We're catching "operator typo
expanded the scope" mistakes, not malicious tampering.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schemas.engagement import RulesOfEngagement


@dataclass
class RoEVerification:
    document_path: Path
    document_exists: bool
    signature_path: Path | None
    signature_verified: bool | None  # None = no signature file present
    structured_scope: dict[str, Any] | None
    scope_matches_spec: bool | None
    scope_violations: list[str]
    warnings: list[str]

    @property
    def ok(self) -> bool:
        if not self.document_exists:
            return False
        if self.scope_matches_spec is False:
            return False
        return True


async def verify_roe_document(
    document_path: str | Path,
    spec_roe: RulesOfEngagement,
) -> RoEVerification:
    doc = Path(document_path)
    sig = doc.with_suffix(doc.suffix + ".sig")

    warnings: list[str] = []
    scope_violations: list[str] = []

    if not doc.exists():
        return RoEVerification(
            document_path=doc,
            document_exists=False,
            signature_path=None,
            signature_verified=None,
            structured_scope=None,
            scope_matches_spec=None,
            scope_violations=[],
            warnings=[f"document path does not exist: {doc}"],
        )

    # Try to parse structured scope from the document if it looks like YAML/JSON.
    structured_scope = _parse_structured(doc)
    if structured_scope is None and doc.suffix not in {".pdf", ".docx", ".txt"}:
        warnings.append(
            f"document at {doc} could not be parsed as structured scope; "
            "human review required."
        )

    # If we have structured scope, cross-check the spec doesn't expand it.
    if structured_scope is not None:
        scope_violations = _scope_violations(spec_roe, structured_scope)
        scope_matches_spec = not scope_violations
    else:
        scope_matches_spec = None

    # GPG verification, best-effort.
    sig_exists = sig.exists()
    sig_verified: bool | None = None
    if sig_exists:
        gpg = shutil.which("gpg")
        if not gpg:
            warnings.append(
                "gpg binary not available; signature present but unverified."
            )
            sig_verified = None
        else:
            sig_verified = await _verify_gpg(gpg, doc, sig)
            if sig_verified is False:
                warnings.append("GPG signature verification FAILED.")
    else:
        warnings.append("no .sig file alongside RoE document — unsigned.")

    return RoEVerification(
        document_path=doc,
        document_exists=True,
        signature_path=sig if sig_exists else None,
        signature_verified=sig_verified,
        structured_scope=structured_scope,
        scope_matches_spec=scope_matches_spec,
        scope_violations=scope_violations,
        warnings=warnings,
    )


def _parse_structured(doc: Path) -> dict[str, Any] | None:
    """Try YAML, then JSON. Return None if it's a binary format we can't read."""
    try:
        text = doc.read_text()
    except UnicodeDecodeError:
        return None
    if doc.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # noqa: PLC0415
            return yaml.safe_load(text)
        except Exception:  # noqa: BLE001
            return None
    if doc.suffix.lower() == ".json":
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    return None


def _scope_violations(spec: RulesOfEngagement, document: dict[str, Any]) -> list[str]:
    """Return any cases where the spec is broader than the signed document.

    The document is allowed to *include* anything; the spec is only allowed to
    use a subset of what's documented. If the spec adds a network/host not in
    the document, that's a violation.
    """
    violations: list[str] = []

    allowed_hosts = set(document.get("allowed_hosts", []))
    if allowed_hosts:
        for host in spec.allowed_hosts:
            if host not in allowed_hosts and host != "*":
                violations.append(
                    f"spec allows host {host!r} which is not in the signed scope"
                )

    allowed_networks = set(document.get("allowed_networks", []))
    if allowed_networks:
        for net in spec.allowed_networks:
            if net not in allowed_networks:
                violations.append(
                    f"spec allows network {net!r} which is not in the signed scope"
                )

    allowed_techniques = set(document.get("allowed_techniques", []))
    spec_techniques = set(spec.allowed_techniques) - {"*"}
    if allowed_techniques and spec_techniques:
        extra = spec_techniques - allowed_techniques
        if extra:
            violations.append(
                f"spec enables techniques not in the signed scope: {sorted(extra)}"
            )

    return violations


async def _verify_gpg(gpg_bin: str, doc: Path, sig: Path) -> bool:
    """Detached signature verification. Returns True only on a clean verify."""
    proc = await asyncio.create_subprocess_exec(
        gpg_bin, "--verify", str(sig), str(doc),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    return (await proc.wait()) == 0
