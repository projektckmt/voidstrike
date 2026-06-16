"""Test for `_load_prefixed_mcp_tools` — the MCP tool name-prefixer.

The `langchain-mcp-adapters` version installed returns tools with bare
function names. All our allowlists / action_class / required_tools assume
the `<server>__<tool>` convention. This helper bridges that gap.

If any future version of the adapter starts prefixing on its own, OR drops
the `get_tools(server_name=...)` API, this test will catch the change and
let us update accordingly.
"""

from __future__ import annotations

import pytest

from tests.unit._fake_tools import FakeTool


class _FakeMCP:
    """Stand-in for MultiServerMCPClient — just enough surface for the
    prefixer to walk."""

    def __init__(self, by_server: dict[str, list[str]],
                 *, support_per_server_api: bool = True,
                 fail_server: str | None = None):
        self._by_server = by_server
        self._support = support_per_server_api
        self._fail_server = fail_server
        self._flat_called = False

    async def get_tools(self, *, server_name: str | None = None):
        if server_name is None:
            self._flat_called = True
            flat = []
            for tools in self._by_server.values():
                flat.extend(FakeTool(name=n) for n in tools)
            return flat
        if not self._support:
            raise TypeError(
                "get_tools() got unexpected keyword argument 'server_name'"
            )
        if server_name == self._fail_server:
            raise RuntimeError("simulated server failure")
        return [FakeTool(name=n) for n in self._by_server.get(server_name, [])]


@pytest.mark.asyncio
async def test_prefixes_each_tool_with_its_server_name() -> None:
    from src.agent.main import _load_prefixed_mcp_tools
    mcp = _FakeMCP({
        "surface": ["nmap_quick", "ffuf"],
        "exploit": ["generate_payload"],
    })
    tools = await _load_prefixed_mcp_tools(mcp, {"surface": {}, "exploit": {}})
    names = sorted(t.name for t in tools)
    assert names == [
        "exploit__generate_payload",
        "surface__ffuf",
        "surface__nmap_quick",
    ]


@pytest.mark.asyncio
async def test_falls_back_to_flat_when_per_server_api_unsupported() -> None:
    from src.agent.main import _load_prefixed_mcp_tools
    mcp = _FakeMCP(
        {"surface": ["nmap_quick"]},
        support_per_server_api=False,
    )
    tools = await _load_prefixed_mcp_tools(mcp, {"surface": {}})
    # Falls back to bare get_tools() — tools come back unprefixed.
    assert mcp._flat_called
    assert [t.name for t in tools] == ["nmap_quick"]


@pytest.mark.asyncio
async def test_skips_failing_server_but_returns_others() -> None:
    """A single MCP server's get_tools() failing must not nuke the rest."""
    from src.agent.main import _load_prefixed_mcp_tools
    mcp = _FakeMCP(
        {
            "surface": ["nmap_quick"],
            "exploit": ["generate_payload"],
            "broken": ["something"],
        },
        fail_server="broken",
    )
    tools = await _load_prefixed_mcp_tools(
        mcp, {"surface": {}, "exploit": {}, "broken": {}}
    )
    names = sorted(t.name for t in tools)
    assert names == ["exploit__generate_payload", "surface__nmap_quick"]


@pytest.mark.asyncio
async def test_no_collision_between_servers_with_same_function_name() -> None:
    """Two servers can expose tools with identical bare names — without the
    prefix they'd collide. After prefixing, both are reachable."""
    from src.agent.main import _load_prefixed_mcp_tools
    mcp = _FakeMCP({
        "episodes": ["read_engagement"],
        "shell": ["read_engagement"],   # contrived collision
    })
    tools = await _load_prefixed_mcp_tools(
        mcp, {"episodes": {}, "shell": {}}
    )
    names = sorted(t.name for t in tools)
    assert names == ["episodes__read_engagement", "shell__read_engagement"]


@pytest.mark.asyncio
async def test_empty_config_produces_no_tools() -> None:
    from src.agent.main import _load_prefixed_mcp_tools
    mcp = _FakeMCP({})
    tools = await _load_prefixed_mcp_tools(mcp, {})
    assert tools == []
