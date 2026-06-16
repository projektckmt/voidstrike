"""Action-class classifier tests."""

from __future__ import annotations

from src.agent.middleware.action_class import ActionClass, classify, register


def test_known_recon_tool() -> None:
    assert classify("surface__nmap_quick") == ActionClass.RECON


def test_known_exploit_tool() -> None:
    assert classify("exploit__deliver_via_web") == ActionClass.EXPLOIT


def test_credential_dump_tool() -> None:
    assert classify("postex__loot_credentials") == ActionClass.CREDENTIAL_DUMP
    assert classify("ad__dcsync") == ActionClass.CREDENTIAL_DUMP


def test_lateral_movement_classification() -> None:
    assert classify("ad__pivot") == ActionClass.LATERAL_MOVEMENT


def test_unknown_tool_defaults_to_exploit() -> None:
    """Better safe than auto-rooted — unknown tools fall through to EXPLOIT so
    engagement-mode HITL catches them."""
    assert classify("mystery__never_seen") == ActionClass.EXPLOIT


def test_register_new_tool() -> None:
    # Mutates the module-global _TOOL_CLASS; clean up after ourselves so
    # cross-test invariants (like the drift test) don't see this entry.
    from src.agent.middleware.action_class import _TOOL_CLASS  # noqa: PLC0415
    name = "phase5__new_recon"
    assert name not in _TOOL_CLASS  # sanity
    register(name, ActionClass.RECON)
    try:
        assert classify(name) == ActionClass.RECON
    finally:
        _TOOL_CLASS.pop(name, None)


def test_browser_split() -> None:
    """Browser tools split: read-only ops are recon, interactive ones exploit."""
    assert classify("browser__read_dom") == ActionClass.RECON
    assert classify("browser__fill_form") == ActionClass.EXPLOIT
    assert classify("browser__submit") == ActionClass.EXPLOIT


def test_every_mcp_tool_classified_explicitly() -> None:
    """Every tool we ship in mcp_servers/ must have an explicit classification.

    Unknown tools default to EXPLOIT (safer than RECON) so engagement-mode
    HITL catches them, but we want to avoid that fallback for our own tools —
    silent EXPLOIT classification on an actually-recon tool would create
    unnecessary HITL pauses.
    """
    from src.agent.middleware.action_class import _TOOL_CLASS  # noqa: PLC0415
    from tests.unit._fake_tools import ALL_MCP_TOOL_NAMES

    # The in-process orchestrator/analyst tools (render_report etc.) don't
    # need to be in the action class table.
    PROCESS_TOOLS = {"render_report"}

    missing = []
    for name in ALL_MCP_TOOL_NAMES:
        if name in PROCESS_TOOLS:
            continue
        if name not in _TOOL_CLASS:
            missing.append(name)
    assert not missing, (
        f"These MCP tools have no explicit action_class entry "
        f"and will fall through to ActionClass.EXPLOIT: {missing}. "
        f"Add them to _TOOL_CLASS in src/agent/middleware/action_class.py."
    )


def test_ad_dcsync_is_credential_dump_not_default() -> None:
    """Regression: DCSync was added in phase 4. Verify it's tagged CREDENTIAL_DUMP
    so engagement-mode HITL pauses before it runs."""
    assert classify("ad__dcsync") == ActionClass.CREDENTIAL_DUMP


def test_ad_pivot_is_lateral_movement() -> None:
    # ad__pivot was the old name; ad__pivot_via_psexec is the actual server tool.
    # We register both names so the classifier stays robust to renames.
    assert classify("ad__pivot") == ActionClass.LATERAL_MOVEMENT
