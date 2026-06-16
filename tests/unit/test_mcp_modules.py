"""Smoke tests for the MCP server modules.

Each MCP server module must:
  - Define a module-level `app` FastMCP instance
  - Define a `main()` function callable from `python -m`
  - Bind port + host via env vars (not hardcoded run() kwargs — that was a
    real bug we hit; FastMCP.run() doesn't accept host/port in this SDK)

These tests don't actually start the servers. They import the modules and
inspect attributes. This catches:
  - Renamed/missing entry points
  - Bare `FastMCP("name")` constructors with no host/port (regression target)
  - main() that calls run(transport=..., host=..., port=...) (other regression)
"""

from __future__ import annotations

import ast
import importlib
import pathlib
import sys
import types

import pytest

MCP_MODULES = [
    "src.mcp_servers.episodes.server",
    "src.mcp_servers.surface.server",
    "src.mcp_servers.exploit.server",
    "src.mcp_servers.postex.server",
    "src.mcp_servers.shell.server",
    "src.mcp_servers.browser.server",
    "src.mcp_servers.research.server",
    "src.mcp_servers.ad.server",
]


@pytest.fixture(autouse=True)
def stub_mcp_fastmcp(monkeypatch):
    """The real `mcp.server.fastmcp.FastMCP` isn't installed in the unit-test
    venv. Stub it so each module imports cleanly. We capture constructor args
    so the per-test assertions can check them."""

    captured: dict[str, dict] = {}

    class FakeFastMCP:
        def __init__(self, name: str, **kwargs):
            self.name = name
            self.kwargs = kwargs
            captured[name] = kwargs
            self.tools: list = []

        def tool(self, *a, **kw):
            def decorator(fn):
                self.tools.append(fn)
                return fn
            return decorator

        def custom_route(self, *a, **kw):
            """Mirror FastMCP's custom_route — non-MCP HTTP routes registered
            by shell server (`/admin/reset`). Tests don't exercise them, just
            need the decorator to be a no-op pass-through."""
            def decorator(fn):
                return fn
            return decorator

        def run(self, transport: str = "stdio", **kwargs):
            # Real FastMCP.run() accepts only `transport=` plus a small set
            # of kwargs. If our main() ever passes host/port here we'd want
            # to fail loudly — but at import time we just record the call.
            raise RuntimeError("FastMCP.run called during import")

    fake_mcp = types.ModuleType("mcp")
    fake_server = types.ModuleType("mcp.server")
    fake_fastmcp_mod = types.ModuleType("mcp.server.fastmcp")
    fake_fastmcp_mod.FastMCP = FakeFastMCP
    fake_server.fastmcp = fake_fastmcp_mod
    fake_mcp.server = fake_server
    # The postex server drives the shell server with an MCP *client*
    # (`from mcp import ClientSession`,
    # `from mcp.client.streamable_http import streamablehttp_client`). Stub
    # those so it imports cleanly without the real package.
    fake_mcp.ClientSession = type("ClientSession", (), {})
    fake_client = types.ModuleType("mcp.client")
    fake_streamable = types.ModuleType("mcp.client.streamable_http")
    fake_streamable.streamablehttp_client = lambda *a, **kw: None
    fake_client.streamable_http = fake_streamable
    fake_mcp.client = fake_client
    monkeypatch.setitem(sys.modules, "mcp", fake_mcp)
    monkeypatch.setitem(sys.modules, "mcp.server", fake_server)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fake_fastmcp_mod)
    monkeypatch.setitem(sys.modules, "mcp.client", fake_client)
    monkeypatch.setitem(sys.modules, "mcp.client.streamable_http", fake_streamable)

    # psycopg + psycopg_pool aren't installed; episodes server imports them
    # at module top. Stub minimally.
    psycopg = types.ModuleType("psycopg")
    psycopg.rows = types.ModuleType("psycopg.rows")
    psycopg.rows.dict_row = lambda *a, **kw: None
    monkeypatch.setitem(sys.modules, "psycopg", psycopg)
    monkeypatch.setitem(sys.modules, "psycopg.rows", psycopg.rows)
    psycopg_pool = types.ModuleType("psycopg_pool")
    psycopg_pool.AsyncConnectionPool = lambda *a, **kw: None
    monkeypatch.setitem(sys.modules, "psycopg_pool", psycopg_pool)

    # Other transitively-imported libs likely absent in CI test venv.
    for stub_name in ("httpx",):
        if stub_name not in sys.modules:
            stub = types.ModuleType(stub_name)
            # httpx needs AsyncClient as a context-manager class.
            class _Stub:
                def __init__(self, *a, **kw): pass
                async def __aenter__(self): return self
                async def __aexit__(self, *a): return False
                async def post(self, *a, **kw): return None
                async def get(self, *a, **kw): return None
            stub.AsyncClient = _Stub
            monkeypatch.setitem(sys.modules, stub_name, stub)

    return captured


@pytest.mark.parametrize("module_path", MCP_MODULES)
def test_module_imports(module_path, stub_mcp_fastmcp) -> None:
    """Each MCP server module imports cleanly with the stubs in place."""
    # Clear any cached version so the fresh stubs apply.
    sys.modules.pop(module_path, None)
    mod = importlib.import_module(module_path)
    assert hasattr(mod, "app"), f"{module_path} must expose `app`"
    assert hasattr(mod, "main"), f"{module_path} must expose `main()`"
    assert callable(mod.main)


@pytest.mark.parametrize("module_path", MCP_MODULES)
def test_fastmcp_constructed_with_host_and_port(module_path, stub_mcp_fastmcp) -> None:
    """Regression: every MCP server must build FastMCP with host+port kwargs.

    The early code path called `app.run(transport=..., host=..., port=...)`
    which the current FastMCP SDK rejects. Putting host/port on the
    constructor (as `Settings`) is the right place.
    """
    sys.modules.pop(module_path, None)
    importlib.import_module(module_path)
    # Each server constructs exactly one FastMCP at import time.
    assert stub_mcp_fastmcp, "no FastMCP() constructions captured"
    # Find this module's construction.
    name_to_kwargs = stub_mcp_fastmcp
    # Any server module's FastMCP must have host + port wired through.
    for name, kwargs in name_to_kwargs.items():
        assert "host" in kwargs, (
            f"FastMCP({name!r}) missing host=. The fix from the field is "
            "host=os.environ.get('HOST', '0.0.0.0') on the constructor."
        )
        assert "port" in kwargs, (
            f"FastMCP({name!r}) missing port=. Use port=int(os.environ.get('PORT', '8080'))."
        )


@pytest.mark.parametrize("module_path", MCP_MODULES)
def test_main_does_not_pass_host_port_to_run(module_path) -> None:
    """Catch the original regression at the source level — re-introducing
    host/port kwargs in `app.run(...)` would break every MCP container.

    We do this by AST-inspecting the module file (no import dance needed)."""
    rel_path = module_path.replace(".", "/") + ".py"
    src = pathlib.Path(rel_path).read_text()
    tree = ast.parse(src, filename=rel_path)
    offending = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Look for `app.run(...)`
        if (isinstance(func, ast.Attribute) and func.attr == "run"
                and isinstance(func.value, ast.Name) and func.value.id == "app"):
            kw_names = {kw.arg for kw in node.keywords}
            for bad in ("host", "port"):
                if bad in kw_names:
                    offending.append(f"{rel_path}: app.run(...) passes {bad}=")
    assert not offending, "\n".join(offending)


def test_surface_uses_httpx_toolkit_not_bare_httpx() -> None:
    """Regression: the surface MCP must call `httpx-toolkit`, not `httpx`.

    Kali ships ProjectDiscovery's tool as `httpx-toolkit` to avoid a name
    collision with the Python `httpx` library — which we install as a project
    dep (see pyproject.toml). The Python httpx CLI lands in
    `/opt/voidstrike-venv/bin/httpx` and shadows the Go binary on PATH, so a
    bare `httpx` invocation parses `-silent` as a short option and fails with
    "No such option '-s'". Pin the binary name at the source level.
    """
    src = pathlib.Path("src/mcp_servers/surface/server.py").read_text()
    tree = ast.parse(src)
    offending = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.List):
            continue
        # First element of the cmd list is the executable name.
        if not node.elts:
            continue
        first = node.elts[0]
        if isinstance(first, ast.Constant) and first.value == "httpx":
            offending.append(
                f"src/mcp_servers/surface/server.py:{first.lineno}: "
                "cmd starts with 'httpx' — use 'httpx-toolkit' instead "
                "(see CLAUDE.md 'Important gotchas' once this is added)."
            )
    assert not offending, "\n".join(offending)
