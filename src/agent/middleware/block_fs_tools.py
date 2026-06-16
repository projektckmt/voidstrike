"""Govern the deepagents virtual-filesystem tools inside a subagent loop.

deepagents binds the six builtin filesystem tools (`ls`, `read_file`,
`write_file`, `edit_file`, `glob`, `grep`) to every agent **and** every subagent
via `FilesystemMiddleware`. Our harness profile (see `profile.py`) marks them
`excluded_tools`, but deepagents implements that with `_ToolExclusionMiddleware`,
which only filters `request.tools` — it hides the schema from the model, it does
**not** unbind the tools from the ToolNode. Anthropic models, heavily trained on
these exact tool names from Claude Code, emit `tool_use` blocks for them anyway,
and the ToolNode runs them against the in-memory vfs. The orchestrator strips
the names from its compiled ToolNode (`_strip_orchestrator_fs_tools` in
`main.py`); subagents are separate subgraphs that strip never reaches, so we
govern them at the tool-call boundary here.

Key nuance: the vfs is NOT the Kali/target filesystem, but it is NOT empty
either — it has two real, populated trees:
  * `/skills/...`            — skill bodies, loaded on demand via `read_file`
                               (progressive disclosure).
  * `/large_tool_results/...`— oversized tool results FilesystemMiddleware
                               offloaded; deepagents tells the model to
                               `read_file` / `grep` / `ls` them back.

So the rule is path-based, not name-based:
  * `read_file`/`ls`/`glob`/`grep` are ALLOWED when their path targets one of
    those trees (real vfs content), and REDIRECTED to the shell tools otherwise
    (the model trying to read/search a file that lives on the box).
  * `write_file`/`edit_file` are always blocked — the agent has no business
    writing the vfs; real artifacts go to the target or the episode log.
"""

from __future__ import annotations

# All six deepagents vfs tools (kept as the canonical set for callers/tests).
VFS_TOOL_NAMES: frozenset[str] = frozenset({
    "ls", "read_file", "write_file", "edit_file", "glob", "grep",
})

# Never useful here — writing the vfs accomplishes nothing for an engagement.
_ALWAYS_BLOCKED: frozenset[str] = frozenset({"write_file", "edit_file"})

# Read/search tools: allowed only against the real vfs trees below.
_PATH_SCOPED: frozenset[str] = frozenset({"ls", "read_file", "glob", "grep"})

# The populated vfs trees the agent may legitimately read/search.
_ALLOWED_VFS_ROOTS: frozenset[str] = frozenset({"skills", "large_tool_results"})


def _vfs_path_allowed(path: str) -> bool:
    """True if `path`'s first segment is a real vfs tree (skills / offloaded results).

    Handles the bare dir (`/large_tool_results`) and nested paths
    (`/large_tool_results/toolu_x`, `skills/postex/.../SKILL.md`) alike.
    """
    first = (path or "").strip().lstrip("/").split("/", 1)[0]
    return first in _ALLOWED_VFS_ROOTS


def block_fs_tools():
    """Return middleware that path-scopes the vfs read/search tools to the real
    vfs trees and hard-blocks vfs writes. Attach one instance per subagent loop.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    def _err(tool_call_id: str, name: str, content: str) -> ToolMessage:
        return ToolMessage(content=content, tool_call_id=tool_call_id, name=name, status="error")

    class BlockFsTools(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            tool_name = getattr(tool, "name", "") or ""
            tool_call = getattr(request, "tool_call", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""

            if tool_name in _ALWAYS_BLOCKED:
                return _err(
                    tool_call_id, tool_name,
                    f"TOOL_UNAVAILABLE: `{tool_name}` writes the agent's virtual filesystem, "
                    "which is not the target or Kali host and accomplishes nothing here. "
                    "Write real artifacts on the box via `shell__tmux_send`, or record "
                    "findings with `episodes__write_episode`. Do not retry this tool.",
                )

            if tool_name in _PATH_SCOPED:
                args = tool_call.get("args", {}) or {}
                path = str(args.get("file_path") or args.get("path") or "")
                if _vfs_path_allowed(path):
                    # Real vfs content (a skill body, or an offloaded tool result).
                    return await handler(request)
                if tool_name == "read_file":
                    return _err(
                        tool_call_id, tool_name,
                        f"READ_FILE_OUT_OF_SCOPE: `read_file` reads the agent's virtual "
                        f"filesystem — only `/skills/...` and `/large_tool_results/...` live "
                        f"there, NOT the Kali sandbox or the target, so {path!r} is not "
                        "visible and this will always fail. To read a real file on the box, "
                        "use your shell: `shell__tmux_send(session_name, 'cat "
                        f"{path or '<path>'}')` (or `type` on Windows), then "
                        "`shell__tmux_read(session_name)`.",
                    )
                return _err(
                    tool_call_id, tool_name,
                    f"TOOL_UNAVAILABLE: `{tool_name}` only works on the agent's virtual "
                    f"filesystem (`/skills/...`, `/large_tool_results/...`); {path or 'that path'} "
                    "is not there. The vfs is NOT the target or Kali host filesystem. To "
                    "list/search/glob files on the box, run the real command via "
                    "`shell__tmux_send`: `ls`/`dir`, `grep -r`/`findstr`, `find`. For "
                    "Kali-local work, open a `shell__tmux_new_session`.",
                )

            return await handler(request)

    return BlockFsTools()
