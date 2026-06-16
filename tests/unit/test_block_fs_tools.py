"""Tests for the subagent vfs-tool governor.

The vfs is NOT the Kali/target filesystem, but it has two real trees the agent
legitimately uses: `/skills/...` (skill bodies) and `/large_tool_results/...`
(offloaded oversized tool results). So `read_file`/`ls`/`glob`/`grep` are
allowed against those paths and redirected to the shell tools otherwise;
`write_file`/`edit_file` are always blocked.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from src.agent.middleware.block_fs_tools import VFS_TOOL_NAMES, block_fs_tools


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name: str, args: dict | None = None, call_id: str = "c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": args or {}, "id": call_id},
    )


def _handler():
    calls: list[str] = []

    async def handler(request):
        calls.append(request.tool.name)
        return SimpleNamespace(content="real-result", name=request.tool.name, status="success")

    return handler, calls


def test_writes_always_blocked():
    guard = block_fs_tools()
    handler, calls = _handler()
    for name in ("write_file", "edit_file"):
        res = _run(guard.awrap_tool_call(_request(name, {"path": "/large_tool_results/x"}), handler))
        assert res.status == "error"
        assert "TOOL_UNAVAILABLE" in res.content
    assert calls == []  # never executed, even under an allowed root


def test_read_search_blocked_off_the_vfs_trees():
    guard = block_fs_tools()
    handler, calls = _handler()
    for name in ("ls", "glob", "grep", "read_file"):
        res = _run(guard.awrap_tool_call(_request(name, {"path": "/usr/bin"}), handler))
        assert res.status == "error", name
    assert calls == []


def test_passes_through_real_tools():
    guard = block_fs_tools()
    handler, calls = _handler()

    for name in ("shell__tmux_send", "shell__tmux_read", "postex__windows_basic_enum",
                 "episodes__write_finding", "shell__tmux_new_session"):
        res = _run(guard.awrap_tool_call(_request(name), handler))
        assert getattr(res, "status", None) != "error"
        assert res.content == "real-result"
    assert calls == [
        "shell__tmux_send", "shell__tmux_read", "postex__windows_basic_enum",
        "episodes__write_finding", "shell__tmux_new_session",
    ]


def test_read_file_allowed_for_skill_and_offloaded_paths():
    guard = block_fs_tools()
    handler, calls = _handler()

    for path in (
        "/skills/postex/windows-privesc/SKILL.md",
        "skills/exploit/file-staging/SKILL.md",
        "/large_tool_results/toolu_01E3V3SCAVrSD7zkhuAhdfFw",
    ):
        res = _run(guard.awrap_tool_call(_request("read_file", {"file_path": path}), handler))
        assert getattr(res, "status", None) != "error", path
        assert res.content == "real-result"
    assert calls == ["read_file"] * 3


def test_grep_and_ls_allowed_within_large_tool_results():
    # The reported regression: deepagents tells the model to grep/ls offloaded
    # results, but they were hard-blocked. The bare dir must work too.
    guard = block_fs_tools()
    handler, calls = _handler()

    r1 = _run(guard.awrap_tool_call(_request("grep", {"pattern": "CVE-2025-58434", "path": "/large_tool_results"}), handler))
    r2 = _run(guard.awrap_tool_call(_request("read_file", {"file_path": "/large_tool_results"}), handler))
    r3 = _run(guard.awrap_tool_call(_request("ls", {"path": "/large_tool_results/"}), handler))
    for r in (r1, r2, r3):
        assert getattr(r, "status", None) != "error"
        assert r.content == "real-result"
    assert calls == ["grep", "read_file", "ls"]


def test_read_file_on_box_path_redirects_to_shell():
    guard = block_fs_tools()
    handler, calls = _handler()

    res = _run(guard.awrap_tool_call(_request("read_file", {"file_path": "/tmp/hfs/http.log"}), handler))
    assert res.status == "error"
    assert "READ_FILE_OUT_OF_SCOPE" in res.content
    assert "shell__tmux_send" in res.content
    assert "/tmp/hfs/http.log" in res.content  # echoed into the cat hint
    assert calls == []


def test_grep_off_vfs_points_to_shell():
    guard = block_fs_tools()
    handler, _ = _handler()
    res = _run(guard.awrap_tool_call(_request("grep", {"pattern": "x", "path": "/etc"}), handler))
    assert res.status == "error"
    assert "shell__tmux_send" in res.content


def test_preserves_tool_call_id():
    guard = block_fs_tools()
    handler, _ = _handler()
    res = _run(guard.awrap_tool_call(_request("glob", {"pattern": "**/*", "path": "/x"}, call_id="abc123"), handler))
    assert res.tool_call_id == "abc123"


def test_vfs_tool_names_is_the_full_six():
    assert VFS_TOOL_NAMES == {"ls", "read_file", "write_file", "edit_file", "glob", "grep"}
