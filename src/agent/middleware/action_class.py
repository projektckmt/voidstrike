"""Action-class classification.

Maps a tool name to a coarse action class. The engagement-mode interrupt policy
keys off these classes — engagement mode pauses before `exploit`,
`credential_dump`, `data_access`, and `lateral_movement`. CTF mode never pauses.

The mapping is intentionally a flat table (not regex magic). New tools need an
explicit entry — surprising defaults are how we'd end up auto-rooting
something.
"""

from __future__ import annotations

from enum import StrEnum

from ...schemas.engagement import RulesOfEngagement


class ActionClass(StrEnum):
    RECON = "recon"
    EXPLOIT = "exploit"
    POSTEX = "postex"
    LATERAL_MOVEMENT = "lateral_movement"
    CREDENTIAL_DUMP = "credential_dump"
    DATA_ACCESS = "data_access"
    PERSISTENCE = "persistence"
    DEFENSIVE_EVASION = "defensive_evasion"
    SHELL_MGMT = "shell_mgmt"
    META = "meta"  # log writes, reads, etc.


_TOOL_CLASS: dict[str, ActionClass] = {
    # Surface — recon
    "surface__nmap_quick": ActionClass.RECON,
    "surface__nmap_full": ActionClass.RECON,
    "surface__httpx_fingerprint": ActionClass.RECON,
    "surface__web_intake": ActionClass.RECON,
    "surface__service_triage": ActionClass.RECON,
    "surface__subfinder": ActionClass.RECON,
    "surface__nuclei": ActionClass.RECON,
    "surface__ffuf": ActionClass.RECON,
    "surface__vhost_enum": ActionClass.RECON,
    "surface__smb_enum": ActionClass.RECON,
    "surface__ldap_enum": ActionClass.RECON,
    "surface__add_hosts_entry": ActionClass.RECON,
    "surface__curl": ActionClass.RECON,

    # Browser — recon by default; auth-flow exploitation gets the same class
    # as exploit/web because of what it can do
    "browser__goto": ActionClass.RECON,
    "browser__read_dom": ActionClass.RECON,
    "browser__get_cookies": ActionClass.RECON,
    "browser__screenshot": ActionClass.RECON,
    "browser__eval_js": ActionClass.RECON,
    "browser__fill_form": ActionClass.EXPLOIT,
    "browser__submit": ActionClass.EXPLOIT,
    "browser__click": ActionClass.EXPLOIT,
    "browser__close_session": ActionClass.META,

    # Exploit
    "exploit__searchsploit_lookup": ActionClass.RECON,
    "exploit__poc_search": ActionClass.RECON,
    "exploit__generate_payload": ActionClass.EXPLOIT,
    "exploit__deliver_via_web": ActionClass.EXPLOIT,
    "exploit__deliver_via_ssh": ActionClass.EXPLOIT,
    "exploit__deliver_via_smb": ActionClass.EXPLOIT,
    "exploit__deliver_via_ftp": ActionClass.EXPLOIT,

    # Research — read-only intelligence gathering and static review
    "research__cve_lookup": ActionClass.RECON,
    "research__vendor_advisory_search": ActionClass.RECON,
    "research__epss_lookup": ActionClass.RECON,
    "research__cisa_kev_lookup": ActionClass.RECON,
    "research__github_poc_search": ActionClass.RECON,
    "research__web_search": ActionClass.RECON,
    "research__exploitdb_fetch": ActionClass.RECON,
    "research__fetch_poc": ActionClass.RECON,
    "research__poc_static_review": ActionClass.RECON,
    "research__affected_version_check": ActionClass.RECON,

    # PostEx
    "postex__linux_basic_enum": ActionClass.POSTEX,
    "postex__windows_basic_enum": ActionClass.POSTEX,
    "postex__linpeas": ActionClass.POSTEX,
    "postex__loot_credentials": ActionClass.CREDENTIAL_DUMP,
    "postex__suid_enum": ActionClass.POSTEX,
    "postex__kernel_suggester": ActionClass.POSTEX,

    # AD (phase 4)
    "ad__bloodhound_collect": ActionClass.RECON,
    "ad__bloodhound_query": ActionClass.RECON,
    "ad__bloodhound_ingest": ActionClass.RECON,  # legacy alias
    "ad__kerberoast": ActionClass.CREDENTIAL_DUMP,
    "ad__asreproast": ActionClass.CREDENTIAL_DUMP,
    "ad__dcsync": ActionClass.CREDENTIAL_DUMP,
    "ad__pivot": ActionClass.LATERAL_MOVEMENT,  # legacy alias
    "ad__pivot_via_psexec": ActionClass.LATERAL_MOVEMENT,

    # Shell (tmux) — session mgmt
    "shell__tmux_new_session": ActionClass.SHELL_MGMT,
    "shell__tmux_exec": ActionClass.SHELL_MGMT,
    "shell__tmux_send": ActionClass.SHELL_MGMT,
    "shell__tmux_read": ActionClass.SHELL_MGMT,
    "shell__tmux_list_sessions": ActionClass.SHELL_MGMT,
    "shell__start_listener": ActionClass.SHELL_MGMT,
    "shell__stabilize_shell": ActionClass.SHELL_MGMT,
    "shell__run_oneshot": ActionClass.SHELL_MGMT,
    "shell__start_callback_server": ActionClass.SHELL_MGMT,
    "shell__wait_callback": ActionClass.SHELL_MGMT,
    "shell__callback_events": ActionClass.SHELL_MGMT,
    "shell__http_json_request": ActionClass.EXPLOIT,

    # Episodes
    "episodes__write_episode": ActionClass.META,
    "episodes__read_episode_tail": ActionClass.META,
    "episodes__read_engagement": ActionClass.META,
    "episodes__summarize_engagement": ActionClass.META,
    "episodes__write_finding": ActionClass.META,
    "episodes__list_findings": ActionClass.META,
}


def classify(tool_name: str) -> ActionClass:
    """Return the action class for a tool. Unknown tools default to EXPLOIT
    so the engagement-mode HITL catches them. Better safe than auto-rooted."""
    return _TOOL_CLASS.get(tool_name, ActionClass.EXPLOIT)


def register(tool_name: str, action_class: ActionClass) -> None:
    """Allow phase-4 modules to register new tools without editing this file."""
    _TOOL_CLASS[tool_name] = action_class


def action_class_gate(roe: RulesOfEngagement, interrupt_classes: set[str]):
    """Returns an `AgentMiddleware` that pauses for HITL before tool calls
    whose action class is in `interrupt_classes`.

    The blocked_techniques list on the RoE additionally hard-blocks the
    matching classes outright (no approval flow — just refused).
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415
    from langgraph.types import interrupt  # noqa: PLC0415

    blocked = set(roe.blocked_techniques)

    class ActionClassGate(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            tool_name = getattr(tool, "name", "")
            tool_call = getattr(request, "tool_call", {}) or {}
            args = tool_call.get("args", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""
            cls = classify(tool_name).value

            if cls in blocked:
                return ToolMessage(
                    content=(
                        f"BLOCKED by RoE: technique class {cls!r} is "
                        f"explicitly disallowed for this engagement."
                    ),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                    status="error",
                )

            if cls in interrupt_classes:
                decision = interrupt({
                    "kind": "action_class_approval",
                    "tool": tool_name,
                    "action_class": cls,
                    "args": args,
                })
                if isinstance(decision, dict) and decision.get("decision") == "reject":
                    return ToolMessage(
                        content=(
                            f"Operator rejected this action. Guidance: "
                            f"{decision.get('guidance', '(none)')}"
                        ),
                        tool_call_id=tool_call_id,
                        name=tool_name,
                        status="error",
                    )
                # `edit` and `accept` fall through to the real handler. (Args
                # editing is honoured by future deepagents versions; for now we
                # treat edit and accept identically.)
            return await handler(request)

    return ActionClassGate()
