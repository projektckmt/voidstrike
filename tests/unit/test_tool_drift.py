"""Cross-source drift detector.

Each subagent declares an explicit allowlist of MCP tools by name. Those
names must match what the relevant MCP server module actually exposes
(`@app.tool()` decorated functions). Otherwise the spec's filter quietly
drops the tool, and the subagent reports "no execution backend" because
its tool list is empty.

We scan each MCP server module via AST (no imports needed) to find
`@app.tool()`-decorated function names, then verify every name listed in
any subagent's allowlist exists somewhere.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
MCP_DIRS = {
    "surface": REPO / "src" / "mcp_servers" / "surface" / "server.py",
    "exploit": REPO / "src" / "mcp_servers" / "exploit" / "server.py",
    "postex":  REPO / "src" / "mcp_servers" / "postex"  / "server.py",
    "browser": REPO / "src" / "mcp_servers" / "browser" / "server.py",
    "shell":   REPO / "src" / "mcp_servers" / "shell"   / "server.py",
    "episodes":REPO / "src" / "mcp_servers" / "episodes"/ "server.py",
    "research":REPO / "src" / "mcp_servers" / "research"/ "server.py",
    "ad":      REPO / "src" / "mcp_servers" / "ad"      / "server.py",
}

SUBAGENT_FILES = [
    REPO / "src" / "agent" / "subagents" / "surface.py",
    REPO / "src" / "agent" / "subagents" / "exploit.py",
    REPO / "src" / "agent" / "subagents" / "postex.py",
    REPO / "src" / "agent" / "subagents" / "analyst.py",
    REPO / "src" / "agent" / "subagents" / "researcher.py",
    REPO / "src" / "agent" / "subagents" / "ad.py",
]


def _tool_functions_in(server_path: pathlib.Path) -> set[str]:
    """Return the set of function names that are `@app.tool()`-decorated in
    the module at `server_path`."""
    tree = ast.parse(server_path.read_text(), filename=str(server_path))
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            # @app.tool(...)
            if (isinstance(dec, ast.Call)
                    and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr == "tool"
                    and isinstance(dec.func.value, ast.Name)
                    and dec.func.value.id == "app"):
                out.add(node.name)
                break
    return out


def _allowlisted_tool_names_in(subagent_path: pathlib.Path) -> set[str]:
    """Extract the set of string literals appearing inside `t.name in {...}`
    filters in the subagent module. These are the names the subagent
    expects."""
    tree = ast.parse(subagent_path.read_text(), filename=str(subagent_path))
    out: set[str] = set()
    for node in ast.walk(tree):
        # We're after `t.name in {...}` — a Compare node with an In op
        # against a Set literal of Constants.
        if not isinstance(node, ast.Compare):
            continue
        if not (len(node.ops) == 1 and isinstance(node.ops[0], ast.In)):
            continue
        if not isinstance(node.comparators[0], ast.Set):
            continue
        for elt in node.comparators[0].elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                if "__" in elt.value:  # MCP tools use double-underscore prefix
                    out.add(elt.value)
    return out


def test_every_subagent_allowlisted_tool_exists_in_some_mcp_server() -> None:
    """The drift catcher — a typo'd allowlist entry was previously silent."""
    catalogue: set[str] = set()
    for prefix, path in MCP_DIRS.items():
        for fn_name in _tool_functions_in(path):
            catalogue.add(f"{prefix}__{fn_name}")

    missing: list[tuple[str, str]] = []
    for sub_path in SUBAGENT_FILES:
        for name in _allowlisted_tool_names_in(sub_path):
            if name not in catalogue:
                missing.append((sub_path.name, name))

    if missing:
        lines = [f"  {sub} -> allowlists {name!r} but no MCP server exposes it"
                 for sub, name in missing]
        pytest.fail(
            "Subagent allowlists reference tools the MCP servers don't export.\n"
            "This means the subagent's `tools=[...]` filter silently drops them, "
            "and the subagent runs with a smaller toolset than its prompt expects:\n"
            + "\n".join(lines)
        )


def test_every_mcp_server_has_at_least_one_tool() -> None:
    """Catches an empty-server regression: if someone removes every
    @app.tool decorator while refactoring, the MCP server becomes useless
    silently."""
    for prefix, path in MCP_DIRS.items():
        tools = _tool_functions_in(path)
        assert tools, f"{prefix} MCP server defines zero @app.tool() functions"


def test_tools_referenced_in_action_class_table_exist_in_an_mcp_server() -> None:
    """The action_class table classifies tools by name. If it references a
    tool that no MCP server exports, the classifier's entry is dead code
    (won't fire) — but a fresh tool added to an MCP server won't be in the
    table either, falling through to ActionClass.EXPLOIT. The first failure
    is silent and harmless; the second causes spurious HITL pauses. This
    test catches both ways."""
    from src.agent.middleware.action_class import _TOOL_CLASS  # noqa: PLC0415

    catalogue: set[str] = set()
    for prefix, path in MCP_DIRS.items():
        for fn_name in _tool_functions_in(path):
            catalogue.add(f"{prefix}__{fn_name}")

    # Ignore in-process tools (no MCP prefix).
    classified_mcp_tools = {n for n in _TOOL_CLASS if "__" in n}

    # Allow a handful of legacy aliases (defended in action_class.py).
    legacy_aliases = {"ad__pivot", "ad__bloodhound_ingest"}

    stale = classified_mcp_tools - catalogue - legacy_aliases
    missing_from_table = catalogue - classified_mcp_tools

    # Stale entries: classifier knows tools the servers don't expose — usually
    # harmless but worth flagging during cleanup.
    if stale:
        pytest.fail(
            f"action_class table references tools no MCP server exports: "
            f"{sorted(stale)}. Either remove from _TOOL_CLASS or add to a server."
        )

    # Missing entries: real bug — the tool will be tagged EXPLOIT by default
    # and trigger HITL in engagement mode.
    if missing_from_table:
        pytest.fail(
            f"MCP servers expose tools that aren't classified: "
            f"{sorted(missing_from_table)}. Add explicit entries in "
            "src/agent/middleware/action_class.py — leaving them out means "
            "engagement-mode HITL fires on benign operations."
        )
