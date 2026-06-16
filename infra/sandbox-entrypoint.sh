#!/usr/bin/env bash
# Sandbox container entrypoint.
#
# 1. If a VPN config is mounted, bring up the tunnel before anything else runs.
#    the orchestrator gates the engagement on tunnel-up; if the
#    tunnel drops mid-engagement, the agent pauses and escalates via StuckReport.
# 2. Exec the actual container command (the MCP server, or `sleep infinity`
#    for the kali-sandbox).

set -euo pipefail

VPN_CONFIG="${VPN_CONFIG_PATH:-/etc/openvpn/client.ovpn}"
VPN_LOG="/var/log/openvpn-client.log"

if [[ -f "$VPN_CONFIG" ]]; then
    echo "[entrypoint] starting OpenVPN with $VPN_CONFIG" >&2
    mkdir -p /dev/net
    if [[ ! -c /dev/net/tun ]]; then
        mknod /dev/net/tun c 10 200 || true
        chmod 600 /dev/net/tun || true
    fi
    openvpn --config "$VPN_CONFIG" \
        --daemon \
        --log-append "$VPN_LOG" \
        --auth-nocache \
        --script-security 2 \
        --up /etc/openvpn/up.sh 2>/dev/null || \
    openvpn --config "$VPN_CONFIG" --daemon --log-append "$VPN_LOG"

    # Wait up to 30s for the tunnel interface to appear.
    for _ in {1..60}; do
        if ip a show tun0 >/dev/null 2>&1 || ip a show tap0 >/dev/null 2>&1; then
            echo "[entrypoint] VPN tunnel up" >&2
            break
        fi
        sleep 0.5
    done

    if ! (ip a show tun0 >/dev/null 2>&1 || ip a show tap0 >/dev/null 2>&1); then
        echo "[entrypoint] WARNING: VPN tunnel never came up. Tail of log:" >&2
        tail -n 50 "$VPN_LOG" >&2 || true
    fi
fi

exec "$@"
