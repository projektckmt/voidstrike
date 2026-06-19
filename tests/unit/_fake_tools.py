"""Test helpers: minimal stand-ins for langchain BaseTool instances.

Subagent specs filter by `tool.name`. They don't call the tools themselves,
so a duck-typed namespace is enough — no langchain dep required.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FakeTool:
    name: str


# The full set of MCP-tool names the agent stack expects. Order doesn't matter.
ALL_MCP_TOOL_NAMES = [
    # surface
    "surface__nmap_quick", "surface__nmap_full", "surface__httpx_fingerprint",
    "surface__web_intake", "surface__service_triage",
    "surface__subfinder", "surface__ffuf", "surface__vhost_enum", "surface__curl",
    # exploit
    "exploit__searchsploit_lookup", "exploit__poc_search",
    "exploit__generate_payload", "exploit__deliver_via_web",
    "exploit__deliver_via_ssh", "exploit__deliver_via_smb",
    "exploit__deliver_via_ftp",
    # research
    "research__cve_lookup", "research__vendor_advisory_search",
    "research__epss_lookup", "research__cisa_kev_lookup",
    "research__github_poc_search", "research__exploitdb_fetch",
    "research__fetch_poc", "research__poc_static_review",
    "research__affected_version_check", "research__web_search",
    # shell
    "shell__tmux_new_session", "shell__tmux_send", "shell__tmux_read",
    "shell__tmux_list_sessions",
    "shell__start_listener", "shell__stabilize_shell", "shell__run_oneshot",
    "shell__start_callback_server", "shell__wait_callback",
    "shell__callback_events", "shell__http_json_request",
    # postex
    "postex__linux_basic_enum", "postex__linpeas",
    "postex__windows_basic_enum", "postex__loot_credentials",
    "postex__suid_enum", "postex__kernel_suggester",
    # browser
    "browser__goto", "browser__read_dom", "browser__fill_form",
    "browser__submit", "browser__click", "browser__screenshot",
    "browser__get_cookies", "browser__eval_js", "browser__close_session",
    # episodes
    "episodes__write_episode", "episodes__read_episode_tail",
    "episodes__read_engagement", "episodes__write_finding",
    "episodes__list_findings", "episodes__summarize_engagement",
    # AD (phase 4)
    "ad__bloodhound_collect", "ad__bloodhound_query",
    "ad__kerberoast", "ad__asreproast", "ad__dcsync",
    "ad__pivot_via_psexec",
    # In-process tools
    "render_report",
]


def all_fake_tools() -> list[FakeTool]:
    return [FakeTool(name=n) for n in ALL_MCP_TOOL_NAMES]
