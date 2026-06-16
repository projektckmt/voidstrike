"""Engagement mode — authorized real testing.

Requires a signed RoE document. Slow, OPSEC-aware-ish, explicit per-objective HITL.
An engagement run that auto-roots production is a lawsuit.
"""

from __future__ import annotations

from ...schemas.engagement import EngagementSpec
from ..prompts.engagement import ENGAGEMENT_ORCHESTRATOR_PROMPT
from .ctf import _allowlist_from_targets


class MissingSignedRoE(RuntimeError):
    pass


class RoEScopeViolation(RuntimeError):
    """Spec asks for a target/technique that exceeds the signed scope."""


def engagement_mode(spec: EngagementSpec):
    """Resolve engagement-mode policy.

    Refuses to proceed if:
      - no signed_document_path / signed_by on the spec, or
      - the structured RoE doc declares a narrower scope than the spec.

    GPG signature mismatch is logged as a warning but not fatal — operators
    sometimes work without GPG infra. The deterministic in-spec allowlist is
    what enforces scope at tool-call time.
    """
    from . import ResolvedMode

    if not spec.roe.signed_document_path or not spec.roe.signed_by:
        raise MissingSignedRoE(
            "Engagement mode requires a signed RoE document. "
            "Set `roe.signed_document_path` and `roe.signed_by` in the spec."
        )

    # Verify the document exists + scope doesn't exceed signed scope.
    import asyncio

    from ..roe_document import verify_roe_document  # noqa: PLC0415
    verification = asyncio.run(
        verify_roe_document(spec.roe.signed_document_path, spec.roe)
    )
    if not verification.document_exists:
        raise MissingSignedRoE(
            f"RoE document at {spec.roe.signed_document_path} does not exist."
        )
    if verification.scope_violations:
        raise RoEScopeViolation(
            "Spec exceeds the signed RoE scope:\n  - "
            + "\n  - ".join(verification.scope_violations)
        )

    # Merge spec-supplied RoE (which may already be more restrictive) with
    # network-allowlist derived from targets.
    derived = _allowlist_from_targets(spec.targets)
    roe = spec.roe.model_copy(
        update={
            "allowed_hosts": list({*spec.roe.allowed_hosts, *derived.allowed_hosts}),
            "allowed_networks": list({*spec.roe.allowed_networks, *derived.allowed_networks}),
        }
    )

    return ResolvedMode(
        name=spec.mode,
        orchestrator_prompt=ENGAGEMENT_ORCHESTRATOR_PROMPT.format(
            target=", ".join(spec.targets),
            objective=spec.objective,
            signed_by=spec.roe.signed_by,
        ),
        allowlist=roe,
        budget_usd=spec.budget_usd,
        # Engagement mode interrupts on every destructive class.
        interrupt_policy={
            "exploit": {"allow_accept": True, "allow_edit": True, "allow_respond": True},
            "lateral_movement": {"allow_accept": True, "allow_edit": True, "allow_respond": True},
            "credential_dump": {"allow_accept": True, "allow_edit": True, "allow_respond": True},
            "data_access": {"allow_accept": True, "allow_edit": True, "allow_respond": True},
        },
        default_subagents=["surface", "researcher", "exploit", "postex", "analyst"],
        spec=spec,
    )
