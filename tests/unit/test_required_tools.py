"""`_assert_required_tools` tests.

The runtime symptom "subagent has no execution backend available" was caused
by an MCP server being unreachable at startup, getting filtered out by the
probe, and the subagent ending up with an empty tools list. This helper
turns that silent failure into a loud startup error.
"""

from __future__ import annotations

import pytest

from tests.unit._fake_tools import FakeTool


def _spec(name: str, tool_names: list[str], required: set[str] | None = None) -> dict:
    return {
        "name": name,
        "tools": [FakeTool(name=n) for n in tool_names],
        "required_tools": required or set(),
    }


def test_passes_when_required_tools_are_bound() -> None:
    from src.agent.main import _assert_required_tools
    sub = _spec("surface",
                tool_names=["surface__nmap_quick", "episodes__write_episode"],
                required={"surface__nmap_quick"})
    _assert_required_tools([sub])  # no raise


def test_passes_when_subagent_has_no_required_tools() -> None:
    from src.agent.main import _assert_required_tools
    sub = _spec("foo", tool_names=[], required=None)
    _assert_required_tools([sub])


def test_raises_when_required_tool_missing() -> None:
    from src.agent.main import _assert_required_tools
    sub = _spec("surface",
                tool_names=["episodes__write_episode"],   # nmap_quick missing
                required={"surface__nmap_quick"})
    with pytest.raises(RuntimeError) as exc:
        _assert_required_tools([sub])
    msg = str(exc.value)
    assert "surface__nmap_quick" in msg
    # The error must enumerate the possible causes so operators can target
    # the right layer.
    assert "MCP server" in msg
    assert "names" in msg  # name-mismatch hypothesis
    assert "HTTP handshake" in msg  # handshake-failure hypothesis


def test_raises_aggregates_all_failing_subagents() -> None:
    from src.agent.main import _assert_required_tools
    subs = [
        _spec("surface",
              tool_names=[], required={"surface__nmap_quick"}),
        _spec("exploit",
              tool_names=["exploit__searchsploit_lookup"],
              required={"exploit__generate_payload", "shell__start_listener"}),
    ]
    with pytest.raises(RuntimeError) as exc:
        _assert_required_tools(subs)
    msg = str(exc.value)
    # Both subagents named.
    assert "surface" in msg and "exploit" in msg
    # And each missing tool surfaces.
    assert "surface__nmap_quick" in msg
    assert "exploit__generate_payload" in msg
    assert "shell__start_listener" in msg


def test_lists_what_was_actually_bound_for_diagnosis() -> None:
    """When a required tool is missing, the error must show what IS bound so
    the operator can quickly tell whether the right MCP server was reached
    at all (zero tools bound = server unreachable; partial set = subagent
    allowlist drift)."""
    from src.agent.main import _assert_required_tools
    sub = _spec("surface",
                tool_names=["episodes__write_episode"],   # only episodes
                required={"surface__nmap_quick"})
    with pytest.raises(RuntimeError) as exc:
        _assert_required_tools([sub])
    msg = str(exc.value)
    assert "episodes__write_episode" in msg  # what WAS bound
    # The "subagent bound list" section should show the real tool — the
    # word 'NONE' may appear elsewhere (e.g. the catalogue blurb), so we
    # check that the relevant 'Bound tools were:' line is non-empty.
    bound_line = next(
        line for line in msg.splitlines() if "Bound tools were:" in line
    )
    assert "[NONE]" not in bound_line


def test_zero_bound_tools_says_NONE_explicitly() -> None:
    """The 'subagent has no execution backend' symptom maps directly to
    zero tools bound. Make that visible in the error."""
    from src.agent.main import _assert_required_tools
    sub = _spec("surface", tool_names=[], required={"surface__nmap_quick"})
    with pytest.raises(RuntimeError) as exc:
        _assert_required_tools([sub])
    msg = str(exc.value)
    bound_line = next(
        line for line in msg.splitlines() if "Bound tools were:" in line
    )
    assert "[NONE]" in bound_line


def test_catalogue_dumped_in_error() -> None:
    """When the global MCP catalogue is non-empty but the subagent's filter
    didn't match anything, the error must show the actual catalogue so the
    operator can spot a name-mismatch (e.g. `surface_nmap_quick` vs
    `surface__nmap_quick`)."""
    from src.agent.main import _assert_required_tools
    sub = _spec("surface",
                tool_names=[],
                required={"surface__nmap_quick"})
    fake_catalogue = [
        FakeTool(name="surface_nmap_quick"),     # NB: single underscore
        FakeTool(name="surface_httpx_fingerprint"),
    ]
    with pytest.raises(RuntimeError) as exc:
        _assert_required_tools([sub], catalogue=fake_catalogue)
    msg = str(exc.value)
    # The catalog blurb must surface the real tool names so a mismatch is
    # visible.
    assert "surface_nmap_quick" in msg
    assert "Full MCP catalogue" in msg


def test_catalogue_empty_when_no_servers_loaded() -> None:
    """If get_tools() returned nothing, the catalogue blurb should say so
    explicitly — that's the 'all MCP servers failed' case."""
    from src.agent.main import _assert_required_tools
    sub = _spec("surface", tool_names=[], required={"surface__nmap_quick"})
    with pytest.raises(RuntimeError) as exc:
        _assert_required_tools([sub], catalogue=[])
    msg = str(exc.value)
    assert "all MCP servers failed get_tools()" in msg
