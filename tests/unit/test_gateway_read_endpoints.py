"""Source-level guard against the broken 'POST to /mcp/tools/<name>' pattern.

For weeks the dashboard's /findings and /episodes endpoints silently 404'd
because they tried to call MCP tools by POSTing to a REST URL that doesn't
exist (the MCP HTTP transport is streamable-http on `/mcp`, not a tree of
REST resources). The fix:

  - Use Postgres directly for episode / finding reads (the data is there).
  - Use a proper MCP client (`mcp.client.streamable_http`) for genuinely-MCP
    state like shell sessions.

These tests scan gateway/main.py at the AST level so the bad pattern can't
sneak back in. They also pin the per-endpoint shape we expose to the web UI.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

GATEWAY = pathlib.Path(__file__).resolve().parents[2] / "src" / "gateway" / "main.py"


def test_no_endpoint_posts_to_mcp_tools_rest_path() -> None:
    """Any `client.post(...)` whose URL ends in `/tools/<name>` is the
    broken pattern — the MCP server doesn't have a REST tree there.
    Allowed: f-strings with `/mcp` alone, or `streamablehttp_client(url)`."""
    src = GATEWAY.read_text()
    tree = ast.parse(src, filename=str(GATEWAY))
    offending: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Look for `.post(` calls where the URL arg contains `/tools/`.
        if isinstance(node.func, ast.Attribute) and node.func.attr == "post":
            if not node.args:
                continue
            url_arg = node.args[0]
            url_text = _stringify(url_arg)
            if url_text and "/tools/" in url_text:
                offending.append(
                    f"line {node.lineno}: post({url_text!r}) — this is the "
                    "broken /mcp/tools/<name> REST path. Use _call_mcp_tool() "
                    "for live MCP calls, or query Postgres directly."
                )
    assert not offending, "\n".join(offending)


def _stringify(node: ast.AST) -> str:
    """Best-effort: render an AST node as a string for grepping. Handles
    constants, f-strings, simple concatenations."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                parts.append("<expr>")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _stringify(node.left) + _stringify(node.right)
    return ""


def test_gateway_has_call_mcp_tool_helper() -> None:
    """The proper way to call an MCP tool from the gateway is the
    `_call_mcp_tool` helper that uses `mcp.client.streamable_http`. If
    someone removes it, every shell-related endpoint will silently break."""
    src = GATEWAY.read_text()
    assert "_call_mcp_tool" in src, (
        "The `_call_mcp_tool` helper is gone. Without it the shell read/list "
        "endpoints can't reach the shell-mcp server. Use the streamable_http "
        "client pattern."
    )
    assert "streamablehttp_client" in src, (
        "The MCP streamable-http client import is missing. The shell "
        "endpoints rely on it."
    )


def test_findings_endpoint_uses_postgres_not_mcp_post() -> None:
    """The /findings endpoint must read directly from Postgres. The MCP
    round-trip via REST never worked and shouldn't come back."""
    src = GATEWAY.read_text()
    # The new endpoint should reference the findings table SELECT.
    assert "FROM findings" in src, (
        "/findings should SELECT FROM findings — direct Postgres read."
    )


def test_episodes_endpoint_uses_postgres_not_mcp_post() -> None:
    src = GATEWAY.read_text()
    assert "FROM episodes" in src
    assert "ORDER BY ts" in src


def test_shells_endpoint_returns_empty_when_mcp_unreachable() -> None:
    """Past engagements have no live shell-mcp sessions — the endpoint must
    return empty cleanly, not 500 or raise. We verify this by ensuring the
    endpoint goes through `_call_mcp_tool` (which returns None on failure)
    and translates None to an empty `sessions` list."""
    src = GATEWAY.read_text()
    # Find the list_shells function.
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "list_shells":
            body_src = ast.unparse(node)
            assert "_call_mcp_tool" in body_src, (
                "list_shells should use _call_mcp_tool — which gracefully "
                "returns None for unreachable servers."
            )
            # And the None-handling: the body should reference `or []` or
            # similar fallback so an unreachable MCP doesn't 500.
            assert "or {}" in body_src or "or []" in body_src or "is None" in body_src
            return
    pytest.fail("list_shells endpoint not found in gateway/main.py")
