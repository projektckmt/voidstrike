"""Consistency tests between Python source and docker-compose files.

These guard against the most common silent breakage: someone renames a
service or a port in one place but not the other, the gateway can't reach
the MCP servers, and the symptom (subagent "no execution backend available")
looks like an agent problem.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parents[2]
BASE_COMPOSE = REPO / "infra" / "docker-compose.yml"
VPN_OVERLAY = REPO / "infra" / "docker-compose.vpn.yml"
OPS_OVERLAY = REPO / "infra" / "docker-compose.ops.yml"


def _load(path: pathlib.Path) -> dict:
    with open(path) as fh:
        # PyYAML's safe_load chokes on docker-compose extension tags like
        # `!reset`. Strip them before parsing.
        text = fh.read().replace("!reset null", "null")
    return yaml.safe_load(text)


# ---------------------------------------------------------------------------
# Syntactic validity
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", [BASE_COMPOSE, VPN_OVERLAY, OPS_OVERLAY])
def test_compose_file_is_valid_yaml(path: pathlib.Path) -> None:
    assert path.exists(), f"{path} missing"
    data = _load(path)
    assert "services" in data, f"{path} has no `services` section"
    assert isinstance(data["services"], dict)


# ---------------------------------------------------------------------------
# Gateway URL <-> compose service alignment
# ---------------------------------------------------------------------------

REQUIRED_MCP_SERVICES = {
    "surface-mcp",
    "exploit-mcp",
    "postex-mcp",
    "browser-mcp",
    "shell-mcp",
    "episodes-mcp",
    "research-mcp",
}


def test_all_required_mcp_services_are_defined() -> None:
    base = _load(BASE_COMPOSE)
    services = set(base["services"].keys())
    missing = REQUIRED_MCP_SERVICES - services
    assert not missing, f"missing MCP services in base compose: {missing}"


def test_gateway_mcp_urls_reference_defined_services() -> None:
    """Every MCP_*_URL the gateway uses must point at a service we actually
    define. Catches stale env vars after service renames."""
    base = _load(BASE_COMPOSE)
    services = set(base["services"].keys())
    gateway_env = base["services"]["gateway"]["environment"]
    # gateway env is a dict in our compose.
    for key, url in gateway_env.items():
        if not key.startswith("MCP_") or not key.endswith("_URL"):
            continue
        if not url or url.startswith("$"):  # ${MCP_AD_URL:-} resolves later
            continue
        # url looks like `http://<service>:<port>/mcp`
        host = url.removeprefix("http://").split(":")[0]
        assert host in services or host == "vpn", (
            f"{key}={url} points at {host!r} which is not a defined service. "
            f"Known services: {sorted(services)}"
        )


def test_vpn_overlay_redirects_mcp_urls_to_vpn_service() -> None:
    """In the VPN overlay, the gateway's MCP_*_URL for the four
    network-sensitive MCP servers must point at the `vpn` host (since they
    join its network namespace via network_mode: service:vpn)."""
    overlay = _load(VPN_OVERLAY)
    gw_env = overlay["services"]["gateway"]["environment"]
    for key in ("MCP_SURFACE_URL", "MCP_EXPLOIT_URL", "MCP_SHELL_URL", "MCP_BROWSER_URL"):
        url = gw_env.get(key, "")
        assert url.startswith("http://vpn:"), (
            f"VPN overlay: {key}={url!r} should route through the vpn sidecar. "
            "Otherwise the gateway can't reach MCP servers that joined service:vpn."
        )


def test_vpn_overlay_assigns_unique_ports_per_mcp() -> None:
    """Inside the shared vpn namespace, multiple MCP servers can't bind the
    same port. This test guards against port collisions when adding new
    services to the overlay."""
    overlay = _load(VPN_OVERLAY)
    ports = {}
    for svc_name in ("surface-mcp", "exploit-mcp", "shell-mcp", "browser-mcp"):
        svc = overlay["services"][svc_name]
        env = svc.get("environment", {})
        port = env.get("PORT")
        assert port, f"{svc_name} has no PORT in the vpn overlay"
        assert port not in ports, (
            f"port collision in vpn namespace: {svc_name} and "
            f"{ports[port]} both want port {port}"
        )
        ports[port] = svc_name


def test_vpn_overlay_services_depend_on_vpn_health() -> None:
    """If MCP servers start before the VPN tunnel is up, their network
    namespace exists but has no routes — every tool call times out. This is
    the silent failure mode that broke us. Every offensive MCP must
    `depends_on: { vpn: { condition: service_healthy } }`."""
    overlay = _load(VPN_OVERLAY)
    for svc_name in ("surface-mcp", "exploit-mcp", "shell-mcp", "browser-mcp"):
        svc = overlay["services"][svc_name]
        dep = svc.get("depends_on")
        assert dep is not None, f"{svc_name} missing depends_on vpn"
        # depends_on can be a list (no condition) or a dict (with condition)
        if isinstance(dep, list):
            pytest.fail(
                f"{svc_name}.depends_on is a list; must be a dict with "
                "{{ vpn: { condition: service_healthy } }} so MCPs wait for "
                "the tunnel."
            )
        assert "vpn" in dep, f"{svc_name}.depends_on missing vpn entry"
        cond = dep["vpn"].get("condition") if isinstance(dep["vpn"], dict) else None
        assert cond == "service_healthy", (
            f"{svc_name}.depends_on.vpn.condition is {cond!r}; must be "
            "'service_healthy' so MCP doesn't start before the tunnel."
        )


def test_vpn_service_has_a_healthcheck() -> None:
    """The healthcheck is what `service_healthy` reads. If we drop it,
    everything starts immediately and silently breaks."""
    overlay = _load(VPN_OVERLAY)
    vpn = overlay["services"]["vpn"]
    assert "healthcheck" in vpn, "vpn service must have a healthcheck"


def test_vpn_service_holds_net_admin_and_tun_device() -> None:
    """OpenVPN refuses to start without NET_ADMIN + /dev/net/tun."""
    overlay = _load(VPN_OVERLAY)
    vpn = overlay["services"]["vpn"]
    cap = vpn.get("cap_add") or []
    assert "NET_ADMIN" in cap, "vpn must have cap_add: [NET_ADMIN]"
    devs = [str(d) for d in (vpn.get("devices") or [])]
    assert any("/dev/net/tun" in d for d in devs), \
        "vpn must mount /dev/net/tun device"


@pytest.mark.parametrize("svc_name", ["surface-mcp", "exploit-mcp", "shell-mcp", "browser-mcp"])
def test_offensive_mcp_containers_have_net_admin_in_vpn_overlay(svc_name: str) -> None:
    """The Kali `nmap` binary has file capabilities `cap_net_admin,cap_net_raw=eip`.
    The kernel refuses to exec a file-capability-bearing binary unless those
    caps are in the process's bounding set — failing with "Operation not
    permitted" at exec time, which looks like the agent saying
    "target unreachable" because the tool returned an unparseable error.

    Capabilities are PER-PROCESS, not inherited from the network-namespace
    donor (vpn). Every offensive MCP container that joins service:vpn must
    add NET_ADMIN + NET_RAW explicitly.
    """
    overlay = _load(VPN_OVERLAY)
    svc = overlay["services"][svc_name]
    cap_add = svc.get("cap_add") or []
    for required in ("NET_ADMIN", "NET_RAW"):
        assert required in cap_add, (
            f"{svc_name} missing cap_add: {required!r}. "
            "Without it, nmap (and other file-capability binaries) fail at "
            "exec time with 'Operation not permitted'. "
            "Caps are per-process — they aren't inherited from the vpn "
            "namespace donor."
        )


# ---------------------------------------------------------------------------
# Engagements directory is bind-mounted, not a named volume
# ---------------------------------------------------------------------------


def _engagements_volume_strings(svc: dict) -> list[str]:
    """Pull every volume mapping (short-form `host:container`) targeting
    /engagement or /app/engagements out of a compose service dict."""
    out: list[str] = []
    for v in svc.get("volumes") or []:
        if isinstance(v, str) and ("/engagement" in v or "/app/engagements" in v):
            out.append(v)
        elif isinstance(v, dict):
            # Long-form mount
            target = v.get("target", "")
            if "/engagement" in target or "/app/engagements" in target:
                source = v.get("source", "")
                out.append(f"{source}:{target}")
    return out


def test_gateway_engagements_is_bind_mount_to_project_root() -> None:
    """A previous version mounted the engagements dir as a Docker NAMED
    VOLUME (`engagements:/app/engagements`). That made files invisible to
    the host's filesystem tools and confused operators ("where are my
    reports?"). It must be a bind-mount against the project's
    `engagements/` dir — so reports / flags / lab_state are grep-able
    directly on the host."""
    base = _load(BASE_COMPOSE)
    for svc_name in ("gateway", "shell-mcp"):
        svc = base["services"][svc_name]
        mappings = _engagements_volume_strings(svc)
        assert mappings, f"{svc_name} has no engagements mount"
        for m in mappings:
            source = m.split(":", 1)[0]
            # Named-volume source has no slash; bind-mount source is a path.
            assert "/" in source, (
                f"{svc_name}: {m!r} looks like a named volume. "
                "Bind-mount the project's engagements dir instead "
                "(`../engagements:<container path>`) so files are visible "
                "on the host."
            )
            assert "engagements" in source, (
                f"{svc_name}: {m!r} doesn't point at an engagements dir on "
                "the host."
            )


def test_web_has_both_browser_and_internal_gateway_urls() -> None:
    """The Next.js dashboard runs server components inside Docker AND client
    components in the browser. They need different URLs:

      - `NEXT_PUBLIC_GATEWAY_URL=http://localhost:8000` → browser path
        (reaches the gateway through the host's port forward).
      - `GATEWAY_INTERNAL_URL=http://gateway:8000` → server-side path
        (Docker DNS reaches the sibling container).

    Missing the internal URL is what caused "everything is empty in the web
    UI" — every server-rendered page silently fell back to its empty state
    because `fetch('http://localhost:8000')` inside the container is
    connection-refused.
    """
    base = _load(BASE_COMPOSE)
    web = base["services"].get("web")
    assert web is not None, "web service missing from base compose"
    env = web.get("environment") or {}
    assert env.get("NEXT_PUBLIC_GATEWAY_URL", "").startswith("http://localhost:"), (
        "NEXT_PUBLIC_GATEWAY_URL must point at localhost — the browser sees "
        "the gateway via the host port forward, not the Docker DNS name."
    )
    internal = env.get("GATEWAY_INTERNAL_URL", "")
    assert internal.startswith("http://gateway:") or internal.startswith("http://gateway/"), (
        f"GATEWAY_INTERNAL_URL must use the Docker service name (`gateway`), "
        f"not localhost. Got {internal!r}. Server components inside the web "
        "container fetch through this URL."
    )


def test_no_named_engagements_volume_declared() -> None:
    """The top-level `volumes:` block must NOT declare an `engagements`
    named volume — switching to a bind-mount means the named volume is
    dead weight and would silently absorb the mapping on some compose
    versions."""
    base = _load(BASE_COMPOSE)
    declared = (base.get("volumes") or {})
    assert "engagements" not in declared, (
        "Remove `engagements:` from the top-level `volumes:` block in "
        "docker-compose.yml — the project now bind-mounts ../engagements "
        "directly on each service that needs it."
    )

    ops = _load(OPS_OVERLAY)
    declared = (ops.get("volumes") or {})
    assert "engagements" not in declared, (
        "Same in docker-compose.ops.yml."
    )


# ---------------------------------------------------------------------------
# Gateway and base-compose alignment with the Python `_mcp_url()` defaults
# ---------------------------------------------------------------------------

def test_mcp_url_default_format_matches_compose_service_names() -> None:
    """`_mcp_url('surface')` builds `http://surface-mcp:8080/mcp`. The base
    compose must define `surface-mcp` on port 8080 (or the gateway must
    explicitly override the env var). This test confirms the implicit-
    convention path matches reality."""
    from src.agent.main import _mcp_url  # noqa: PLC0415
    base = _load(BASE_COMPOSE)
    services = base["services"]
    for short_name in ("surface", "exploit", "postex", "browser", "shell", "episodes", "research"):
        svc_name = f"{short_name}-mcp"
        assert svc_name in services, f"{svc_name} missing from compose"
        # Default URL the Python build_agent path uses.
        default_url = _mcp_url(short_name)
        # Should reference the service name.
        assert svc_name in default_url, (
            f"_mcp_url({short_name!r})={default_url!r} doesn't reference "
            f"compose service {svc_name!r}"
        )
