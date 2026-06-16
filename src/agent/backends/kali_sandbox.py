"""Kali sandbox backend.

A thin wrapper that the deep-agents virtual-filesystem and skills loader will
mount onto. The sandbox container is brought up out-of-band by the gateway
when an engagement starts (VPN tunnel up, ops-net joined), and the backend
holds a handle to it.

Phase 1 keeps this minimal — the agent talks to the sandbox only via MCP
servers; the backend is mostly for the virtual filesystem and the engagement
working directory.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class KaliSandboxBackend:
    image: str = "voidstrike/kali:pinned"
    network: str = "voidstrike_ops"
    container_id: str | None = None
    working_dir: Path = field(default_factory=lambda: Path("/engagement"))
    vpn_config: str | None = None
    extra_env: dict[str, str] = field(default_factory=dict)

    async def start(self) -> str:
        """Bring up the sandbox container with the VPN tunnel.

        Returns the container ID. Idempotent — repeat calls are a no-op.
        """
        if self.container_id:
            return self.container_id
        cmd = [
            "docker", "run", "-d",
            "--rm",
            "--cap-add=NET_ADMIN",
            "--device=/dev/net/tun",
            "--network", self.network,
            "-v", f"{self.working_dir}:/engagement",
        ]
        if self.vpn_config:
            cmd.extend(["-v", f"{self.vpn_config}:/etc/openvpn/client.ovpn:ro"])
        for k, v in self.extra_env.items():
            cmd.extend(["-e", f"{k}={v}"])
        cmd.append(self.image)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"docker run failed: {stderr.decode()}")
        self.container_id = stdout.decode().strip()
        return self.container_id

    async def verify_vpn(self, gateway_ip: str, timeout_s: int = 30) -> bool:
        """Verify the sandbox can reach the VPN gateway."""
        if not self.container_id:
            return False
        cmd = ["docker", "exec", self.container_id, "ping", "-c", "1", "-W", str(timeout_s), gateway_ip]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return (await proc.wait()) == 0

    async def stop(self) -> None:
        if not self.container_id:
            return
        proc = await asyncio.create_subprocess_exec(
            "docker", "stop", self.container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        self.container_id = None

    def to_state(self) -> dict[str, Any]:
        return {
            "image": self.image,
            "network": self.network,
            "container_id": self.container_id,
            "working_dir": str(self.working_dir),
        }
