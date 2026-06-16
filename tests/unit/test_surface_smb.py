"""surface__smb_enum — anonymous SMB recon for Windows/AD targets.

Lists shares, tests anonymous READ per share, lists readable-share contents,
and enumerates users over a null session. The recon path for boxes like HTB
Querier (anon-readable share → loot file with creds).
"""

from __future__ import annotations

import pytest


def _fake_exec_factory():
    """Return an _exec stand-in that answers each smbclient/rpcclient call."""
    async def _exec(cmd, timeout_s=0):
        joined = " ".join(cmd)
        if "-L" in cmd:  # share listing (grepable)
            return {"ok": True, "rc": 0,
                    "stdout": "Disk|Reports|\nDisk|ADMIN$|Remote Admin\nIPC|IPC$|Remote IPC\n",
                    "stderr": ""}
        if "//10.129.10.14/Reports" in joined:  # readable share
            return {"ok": True, "rc": 0,
                    "stdout": "  .\n  ..\n  Currency Volume Report.xlsm   A   12345\n",
                    "stderr": ""}
        if "enumdomusers" in joined:
            return {"ok": True, "rc": 0,
                    "stdout": "user:[Administrator] rid:[0x1f4]\nuser:[mssql-svc] rid:[0x450]\n",
                    "stderr": ""}
        return {"ok": False, "rc": 1, "stdout": "", "stderr": "NT_STATUS_ACCESS_DENIED"}
    return _exec


@pytest.mark.asyncio
async def test_smb_enum_lists_shares_contents_and_users(monkeypatch):
    from src.mcp_servers.surface import server
    monkeypatch.setattr(server, "_exec", _fake_exec_factory())

    res = await server.smb_enum(target="10.129.10.14")
    assert res["ok"] is True
    names = {s["name"] for s in res["shares"]}
    assert {"Reports", "ADMIN$", "IPC$"} <= names
    # Admin / IPC shares are skipped, not probed.
    by_name = {s["name"]: s for s in res["shares"]}
    assert by_name["ADMIN$"]["access"] == "skipped"
    assert by_name["IPC$"]["access"] == "skipped"
    # The Disk share is probed and readable, with its loot file surfaced.
    assert by_name["Reports"]["access"] == "read"
    assert res["anonymous_readable_shares"] == ["Reports"]
    assert any(".xlsm" in f for f in res["readable_share_contents"]["Reports"])
    # Null-session users enumerated.
    assert "Administrator" in res["null_session_users"]
    assert "mssql-svc" in res["null_session_users"]


@pytest.mark.asyncio
async def test_smb_enum_lists_over_445_not_139(monkeypatch):
    # Regression: `smbclient -L` by IP must use 445; 139 fails with
    # NT_STATUS_RESOURCE_NAME_NOT_FOUND.
    from src.mcp_servers.surface import server
    calls = []

    async def _exec(cmd, timeout_s=0):
        calls.append(cmd)
        if "-L" in cmd:
            return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}
        return {"ok": False, "rc": 1, "stdout": "", "stderr": ""}

    monkeypatch.setattr(server, "_exec", _exec)
    await server.smb_enum(target="10.129.10.14", port=139)
    list_cmd = next(c for c in calls if "-L" in c)
    assert list_cmd[list_cmd.index("-p") + 1] == "445"


@pytest.mark.asyncio
async def test_smb_enum_handles_refused_listing(monkeypatch):
    from src.mcp_servers.surface import server

    async def _exec(cmd, timeout_s=0):
        return {"ok": False, "rc": 1, "stdout": "", "stderr": "NT_STATUS_ACCESS_DENIED"}

    monkeypatch.setattr(server, "_exec", _exec)
    res = await server.smb_enum(target="10.129.10.14")
    assert res["ok"] is False
    assert "hint" in res
