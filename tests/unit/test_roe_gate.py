"""RoE gate tests. The one piece the plan refuses to compromise on.

These tests exist *because* the gate is deterministic. Adding a third-party LLM
judgment call here would be how customers end up with the wrong target hit.
"""

from __future__ import annotations

import pytest

from src.agent.middleware.roe_gate import check_roe, extract_targets
from src.schemas.engagement import RulesOfEngagement


def _roe(allowed_hosts=None, allowed_networks=None, blocked_hosts=None):
    return RulesOfEngagement(
        allowed_hosts=allowed_hosts or [],
        allowed_networks=allowed_networks or [],
        blocked_hosts=blocked_hosts or [],
    )


class TestExtractTargets:
    def test_ipv4_in_string(self) -> None:
        out = extract_targets("nmap -sV 10.10.10.5")
        assert "10.10.10.5" in out.hosts

    def test_url_decomposes_to_host(self) -> None:
        out = extract_targets({"url": "http://target.lab:8080/admin"})
        assert "target.lab" in out.hosts
        assert "http://target.lab:8080/admin" in out.urls

    def test_https_url_with_path(self) -> None:
        out = extract_targets("curl https://example.com/api/v1?x=1")
        assert "example.com" in out.hosts

    def test_nested_dict(self) -> None:
        args = {"target": "10.0.0.1", "options": {"backup_url": "http://other.host/x"}}
        out = extract_targets(args)
        assert "10.0.0.1" in out.hosts
        assert "other.host" in out.hosts

    def test_list_of_targets(self) -> None:
        out = extract_targets({"hosts": ["10.0.0.1", "10.0.0.2"]})
        assert {"10.0.0.1", "10.0.0.2"}.issubset(out.hosts)

    def test_cidr_picked_up(self) -> None:
        out = extract_targets("nmap 10.10.0.0/24")
        assert "10.10.0.0/24" in out.networks

    def test_no_target_is_no_target(self) -> None:
        out = extract_targets({"command": "whoami"})
        assert not out.all_targets

    def test_ip_with_port_extracted(self) -> None:
        out = extract_targets("curl 192.168.1.5:8080")
        assert "192.168.1.5" in out.hosts

    def test_filename_like_strings_are_not_hosts(self) -> None:
        # Filenames the agent references in prose (config.php, index.html, etc.)
        # were previously matched as hostnames and tripped the gate.
        out = extract_targets(
            "examine config.php and review index.html, app.js, settings.yml"
        )
        assert not any(name in out.hosts for name in
                       ["config.php", "index.html", "app.js", "settings.yml"])

    def test_filename_does_not_block_task_delegation(self) -> None:
        roe = _roe(allowed_networks=["10.129.0.0/16"])
        allowed, reason = check_roe(
            {"description": "Look at config.php for hardcoded credentials on 10.129.95.185"},
            roe,
        )
        assert allowed, reason

    def test_python_identifiers_do_not_block(self) -> None:
        # `pty.spawn`, `os.path`, `socket.gethostbyname` etc. trip the
        # hostname regex but are never hosts. With an IP-only scope
        # (allowed_hosts=[]), they should not block the call.
        roe = _roe(allowed_networks=["10.129.0.0/16"])
        allowed, reason = check_roe({"description": (
            "python -c 'import pty; pty.spawn(\"/bin/bash\")' then "
            "use os.path.join and socket.gethostbyname against 10.129.95.185"
        )}, roe)
        assert allowed, reason

    def test_hostname_scope_still_enforced(self) -> None:
        # When the engagement DOES declare hostname scope, bare hostnames
        # still get extracted and checked.
        roe = _roe(allowed_hosts=["target.htb"])
        allowed, _ = check_roe({"url": "http://elsewhere.example.com"}, roe)
        assert not allowed


class TestCheckRoe:
    def test_in_scope_cidr_allowed(self) -> None:
        roe = _roe(allowed_networks=["10.10.0.0/16"])
        allowed, reason = check_roe({"target": "10.10.5.5"}, roe)
        assert allowed, reason

    def test_out_of_scope_blocked(self) -> None:
        roe = _roe(allowed_networks=["10.10.0.0/16"])
        allowed, reason = check_roe({"target": "192.168.1.1"}, roe)
        assert not allowed
        assert "192.168.1.1" in (reason or "")

    def test_explicit_host_allowed(self) -> None:
        roe = _roe(allowed_hosts=["target.htb"])
        assert check_roe({"url": "http://target.htb/x"}, roe)[0]

    def test_wildcard_hostname(self) -> None:
        roe = _roe(allowed_hosts=["*.htb"])
        assert check_roe({"url": "http://www.target.htb/"}, roe)[0]

    def test_wildcard_does_not_match_sibling(self) -> None:
        roe = _roe(allowed_hosts=["*.htb"])
        ok, _ = check_roe({"url": "http://target.com/"}, roe)
        assert not ok

    def test_explicit_block_overrides(self) -> None:
        roe = _roe(
            allowed_networks=["10.10.0.0/16"],
            blocked_hosts=["10.10.5.5"],
        )
        ok, _ = check_roe({"target": "10.10.5.5"}, roe)
        assert not ok

    def test_no_target_passes(self) -> None:
        # Local-only tools (searchsploit_lookup, generate_payload) have no host.
        roe = _roe(allowed_networks=["10.10.0.0/16"])
        ok, _ = check_roe({"query": "apache 2.4"}, roe)
        assert ok

    def test_mixed_allowed_and_blocked_targets_fails_on_first_block(self) -> None:
        # Tool args reference TWO hosts, one in scope and one out — must fail.
        roe = _roe(allowed_networks=["10.10.0.0/16"])
        ok, reason = check_roe(
            {"primary": "10.10.5.5", "fallback": "8.8.8.8"},
            roe,
        )
        assert not ok
        assert "8.8.8.8" in (reason or "")

    def test_cidr_subnet_of_allowed_network(self) -> None:
        roe = _roe(allowed_networks=["10.0.0.0/8"])
        ok, _ = check_roe({"target": "10.10.0.0/16"}, roe)
        assert ok

    def test_cidr_outside_allowed_network(self) -> None:
        roe = _roe(allowed_networks=["10.10.0.0/16"])
        ok, _ = check_roe({"target": "192.168.0.0/24"}, roe)
        assert not ok

    def test_universal_wildcard_allowlist(self) -> None:
        # Used by `lab` mode with a broad scope.
        roe = _roe(allowed_hosts=["*"])
        ok, _ = check_roe({"target": "literally.anything"}, roe)
        assert ok

    @pytest.mark.parametrize("target", [
        "169.254.169.254",          # AWS metadata
        "metadata.google.internal", # GCP metadata
        "127.0.0.1",                # localhost
    ])
    def test_sensitive_hosts_blocked_by_default(self, target: str) -> None:
        roe = _roe(allowed_networks=["10.10.0.0/16"])
        ok, _ = check_roe({"target": target}, roe)
        assert not ok, f"{target} must NOT match an allowlist of 10.10.0.0/16"


class TestSelfHosts:
    """The attacker's own infra (LHOST / VPN tun / staging) is never a target."""

    def _roe(self, **kw):
        return RulesOfEngagement(
            allowed_networks=kw.get("allowed_networks", ["10.129.0.0/16"]),
            self_hosts=kw.get("self_hosts", []),
        )

    def test_self_ip_exempt_even_though_not_in_allowlist(self) -> None:
        # The reported bug: LHOST 10.10.16.91 (HTB tun0) is not in scope but is
        # the attacker's own box, so it must not block.
        roe = self._roe(self_hosts=["10.10.16.0/23"])
        ok, reason = check_roe({"target": "10.10.16.91"}, roe)
        assert ok, reason

    def test_task_description_with_target_and_lhost_passes(self) -> None:
        # The exact failure shape: a task delegation naming both the in-scope
        # target and the staging IP in prose.
        roe = self._roe(self_hosts=["10.10.16.0/23"])
        ok, reason = check_roe(
            {"description": "Privilege escalation on 10.129.8.175 via reverse shell to LHOST 10.10.16.91"},
            roe,
        )
        assert ok, reason

    def test_self_exemption_does_not_allow_other_out_of_scope_hosts(self) -> None:
        # Exempting self must not become a blanket allow — a different
        # out-of-scope IP still blocks.
        roe = self._roe(self_hosts=["10.10.16.0/23"])
        ok, reason = check_roe({"target": "192.168.1.1"}, roe)
        assert not ok
        assert "192.168.1.1" in reason

    def test_single_self_ip_without_cidr(self) -> None:
        roe = self._roe(self_hosts=["10.10.16.91"])
        assert check_roe({"target": "10.10.16.91"}, roe)[0]
        # A sibling in the same /24 is NOT exempt (we listed a single IP).
        assert not check_roe({"target": "10.10.16.92"}, roe)[0]

    def test_no_self_hosts_means_no_exemption(self) -> None:
        roe = self._roe(self_hosts=[])
        assert not check_roe({"target": "10.10.16.91"}, roe)[0]


class TestUngatedTools:
    """The `task` (subagent delegation) and `write_todos` tools run purely
    in-process — their args carry hostnames/IPs as prose (e.g. the local
    episode-log endpoint at 127.0.0.1), and gating them wrongly blocks
    delegation. The spawned subagent's own tool calls are still gated."""

    @staticmethod
    def _run(tool_name, args, roe):
        import asyncio
        from types import SimpleNamespace

        from src.agent.middleware.roe_gate import roe_gate

        gate = roe_gate(roe)
        sentinel = object()

        async def handler(_request):
            return sentinel

        request = SimpleNamespace(
            tool=SimpleNamespace(name=tool_name),
            tool_call={"name": tool_name, "args": args, "id": "tc_1"},
        )
        return asyncio.run(gate.awrap_tool_call(request, handler)), sentinel

    def test_task_delegation_not_blocked_by_loopback_in_prompt(self) -> None:
        roe = _roe(allowed_networks=["10.129.21.132/32"])
        args = {"description": "Read the episode log at http://127.0.0.1:8000 and report."}
        # Sanity: check_roe itself would block this (127.0.0.1 out of scope).
        assert not check_roe(args, roe)[0]
        result, sentinel = self._run("task", args, roe)
        assert result is sentinel  # handler ran — not blocked

    def test_offensive_tool_still_gated(self) -> None:
        roe = _roe(allowed_networks=["10.129.21.132/32"])
        result, sentinel = self._run(
            "surface__curl", {"url": "http://127.0.0.1:8000"}, roe
        )
        assert result is not sentinel  # blocked → ToolMessage, handler never ran
        assert getattr(result, "status", None) == "error"
