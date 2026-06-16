"""Mode-resolution tests — make sure ctf/lab/engagement diverge in the ways the
plan requires (engagement requires signed RoE, allowlists merge correctly).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.agent.modes import resolve_mode
from src.agent.modes.engagement import MissingSignedRoE
from src.schemas.engagement import EngagementMode, EngagementSpec, RulesOfEngagement


def test_ctf_mode_allows_anything_against_target() -> None:
    spec = EngagementSpec(name="box", mode=EngagementMode.CTF, targets=["10.10.10.5"])
    resolved = resolve_mode(spec)
    assert resolved.spec.mode is EngagementMode.CTF
    assert resolved.interrupt_policy == {}
    # Bare IPv4 addresses are stored as /32 networks (`ipaddress.ip_network`
    # accepts a host-form string). This is fine for RoE — `check_roe` walks
    # both lists.
    assert "10.10.10.5" in resolved.allowlist.allowed_networks


def test_ctf_mode_with_hostname_target() -> None:
    spec = EngagementSpec(name="box", mode=EngagementMode.CTF, targets=["target.htb"])
    resolved = resolve_mode(spec)
    assert "target.htb" in resolved.allowlist.allowed_hosts


def test_ctf_mode_seeds_htb_vpn_client_ranges_as_self_hosts() -> None:
    # The attacker's HTB tun0 IP (LHOST/staging) must not trip the RoE gate.
    from src.agent.middleware.roe_gate import check_roe

    spec = EngagementSpec(name="box", mode=EngagementMode.CTF, targets=["10.129.8.175"])
    resolved = resolve_mode(spec)
    assert "10.10.16.0/23" in resolved.allowlist.self_hosts
    # The reported case resolves to allowed end-to-end.
    ok, reason = check_roe(
        {"description": "privesc on 10.129.8.175 via LHOST 10.10.16.91"},
        resolved.allowlist,
    )
    assert ok, reason


def test_ctf_mode_merges_operator_self_hosts() -> None:
    spec = EngagementSpec(
        name="box",
        mode=EngagementMode.CTF,
        targets=["10.129.8.175"],
        roe=RulesOfEngagement(self_hosts=["192.168.49.0/24"]),
    )
    resolved = resolve_mode(spec)
    assert "192.168.49.0/24" in resolved.allowlist.self_hosts
    assert "10.10.16.0/23" in resolved.allowlist.self_hosts  # HTB default still present


def test_ctf_mode_allows_discovered_htb_vhost_of_in_scope_box() -> None:
    # The reported case: target is an IP, the box serves content under a .htb
    # vhost. The gate must accept silentium.htb (it resolves to the one in-scope
    # box) but still reject a real external host.
    from src.agent.middleware.roe_gate import check_roe

    spec = EngagementSpec(name="box", mode=EngagementMode.CTF, targets=["10.129.245.103"])
    resolved = resolve_mode(spec)

    ok, reason = check_roe(
        {"description": "Target 10.129.245.103, vhost silentium.htb on port 80"},
        resolved.allowlist,
    )
    assert ok, reason
    assert check_roe({"url": "http://silentium.htb/admin"}, resolved.allowlist)[0]
    # Real internet TLDs are still gated.
    assert not check_roe({"url": "http://evil.com/x"}, resolved.allowlist)[0]


def test_lab_mode_allows_lab_tld_vhosts() -> None:
    from src.agent.middleware.roe_gate import check_roe

    spec = EngagementSpec(name="lab", mode=EngagementMode.LAB, targets=["10.10.110.0/24"])
    resolved = resolve_mode(spec)
    # AD lab hosts under .local / .htb resolve within the lab.
    assert check_roe({"target": "dc01.corp.local"}, resolved.allowlist)[0]
    assert check_roe({"target": "web.megacorp.htb"}, resolved.allowlist)[0]
    assert not check_roe({"target": "example.com"}, resolved.allowlist)[0]


def test_lab_mode_pulls_cidrs_into_allowlist() -> None:
    spec = EngagementSpec(
        name="lab", mode=EngagementMode.LAB, targets=["10.10.0.0/16"]
    )
    resolved = resolve_mode(spec)
    assert "10.10.0.0/16" in resolved.allowlist.allowed_networks
    assert "lateral_movement" in resolved.interrupt_policy


def test_engagement_mode_refuses_without_signed_roe() -> None:
    spec = EngagementSpec(
        name="real",
        mode=EngagementMode.ENGAGEMENT,
        targets=["app.customer.com"],
    )
    with pytest.raises(MissingSignedRoE):
        resolve_mode(spec)


def test_engagement_mode_with_signed_roe(tmp_path) -> None:
    import yaml
    doc = tmp_path / "signed-roe.yaml"
    doc.write_text(yaml.safe_dump({
        "allowed_hosts": ["app.customer.com"],
        "allowed_techniques": ["recon", "exploit", "postex", "credential_dump"],
    }))
    spec = EngagementSpec(
        name="real",
        mode=EngagementMode.ENGAGEMENT,
        targets=["app.customer.com"],
        roe=RulesOfEngagement(
            allowed_hosts=["app.customer.com"],
            allowed_techniques=["recon", "exploit"],
            signed_document_path=str(doc),
            signed_by="Jane Defender",
            signed_at=datetime.now(UTC),
        ),
    )
    resolved = resolve_mode(spec)
    assert "exploit" in resolved.interrupt_policy
    assert "credential_dump" in resolved.interrupt_policy


def test_engagement_mode_refuses_when_spec_exceeds_signed_scope(tmp_path) -> None:
    """Spec asks for `lateral_movement` but the signed doc doesn't allow it."""
    import yaml

    from src.agent.modes.engagement import RoEScopeViolation
    doc = tmp_path / "narrow-roe.yaml"
    doc.write_text(yaml.safe_dump({
        "allowed_hosts": ["app.customer.com"],
        "allowed_techniques": ["recon"],
    }))
    spec = EngagementSpec(
        name="real",
        mode=EngagementMode.ENGAGEMENT,
        targets=["app.customer.com"],
        roe=RulesOfEngagement(
            allowed_hosts=["app.customer.com"],
            allowed_techniques=["recon", "lateral_movement"],
            signed_document_path=str(doc),
            signed_by="Jane Defender",
            signed_at=datetime.now(UTC),
        ),
    )
    with pytest.raises(RoEScopeViolation):
        resolve_mode(spec)
