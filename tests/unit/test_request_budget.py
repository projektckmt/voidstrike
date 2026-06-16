"""Tests for the per-tool request budget (browse_budget / curl_budget).

Caps how many times a subagent calls a grinding tool per invocation so it can't
spiral (the researcher's 92-page browse, the surface agent's 90-curl grind).
Count is read statelessly from `request.state.messages`, so a second `task()`
delegation starts fresh.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from langchain_core.messages import AIMessage, ToolMessage

from src.agent.middleware.request_budget import (
    browse_budget,
    curl_budget,
    request_budget,
    research_budget,
)


def _run(coro):
    return asyncio.run(coro)


def _request(tool_name, state_messages, call_id="c1"):
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": {}, "id": call_id},
        state={"messages": state_messages},
    )


def _results(tool_name, n):
    """History with `n` completed results for `tool_name`."""
    msgs = []
    for i in range(n):
        msgs.append(AIMessage(content="", tool_calls=[{"name": tool_name, "args": {}, "id": f"t{i}"}]))
        msgs.append(ToolMessage(content="{}", tool_call_id=f"t{i}", name=tool_name))
    return msgs


async def _ok(request):
    return SimpleNamespace(content="ran", name=request.tool.name, status="success")


# --- generic request_budget ------------------------------------------------

def test_allows_under_budget():
    g = request_budget("surface__curl", 40, marker="X", directive="stop")
    res = _run(g.awrap_tool_call(_request("surface__curl", _results("surface__curl", 10)), _ok))
    assert res.content == "ran"


def test_blocks_at_budget():
    g = request_budget("surface__curl", 40, marker="CURL_BUDGET_EXHAUSTED", directive="hand off")
    res = _run(g.awrap_tool_call(_request("surface__curl", _results("surface__curl", 40)), _ok))
    assert res.status == "error"
    assert "CURL_BUDGET_EXHAUSTED" in res.content
    assert "hand off" in res.content
    assert "40" in res.content


def test_other_tools_unaffected():
    g = request_budget("surface__curl", 2, marker="X", directive="stop")
    res = _run(g.awrap_tool_call(_request("surface__httpx_fingerprint", _results("surface__curl", 99)), _ok))
    assert res.content == "ran"


def test_stateless_per_invocation():
    # Fresh invocation (empty history) is never blocked regardless of prior runs.
    g = request_budget("surface__curl", 2, marker="X", directive="stop")
    res = _run(g.awrap_tool_call(_request("surface__curl", []), _ok))
    assert res.content == "ran"


def test_preserves_call_id():
    g = request_budget("surface__curl", 1, marker="X", directive="stop")
    res = _run(g.awrap_tool_call(_request("surface__curl", _results("surface__curl", 3), call_id="zz"), _ok))
    assert res.tool_call_id == "zz"


# --- specializations -------------------------------------------------------

def test_browse_budget_caps_goto_and_spares_read_dom():
    g = browse_budget(max_browses=25)
    blocked = _run(g.awrap_tool_call(_request("browser__goto", _results("browser__goto", 25)), _ok))
    assert blocked.status == "error"
    assert "BROWSE_BUDGET_EXHAUSTED" in blocked.content
    # read_dom of already-loaded pages is never capped.
    ok = _run(g.awrap_tool_call(_request("browser__read_dom", _results("browser__goto", 40)), _ok))
    assert ok.content == "ran"


def test_curl_budget_blocks_and_points_to_exploit_handoff():
    g = curl_budget(max_calls=40)
    res = _run(g.awrap_tool_call(_request("surface__curl", _results("surface__curl", 40)), _ok))
    assert res.status == "error"
    assert "CURL_BUDGET_EXHAUSTED" in res.content
    assert "SurfaceFindings" in res.content
    assert "exploit subagent" in res.content


def test_research_budget_counts_across_tools():
    # The whack-a-mole fix: the cap is the SUM across goto/grep/read_file/etc, so
    # a spiral that switches tools is still bounded.
    g = research_budget(max_calls=50)
    # 20 goto + 20 grep + 10 read_file = 50 completed research calls.
    history = (
        _results("browser__goto", 20)
        + _results("grep", 20)
        + _results("read_file", 10)
    )
    # The next research call (any of them) is blocked.
    res = _run(g.awrap_tool_call(_request("grep", history), _ok))
    assert res.status == "error"
    assert "RESEARCH_BUDGET_EXHAUSTED" in res.content


def test_research_budget_counts_structured_research_tools():
    g = research_budget(max_calls=2)
    history = (
        _results("research__cve_lookup", 1)
        + _results("research__github_poc_search", 1)
    )
    res = _run(g.awrap_tool_call(_request("research__fetch_poc", history), _ok))
    assert res.status == "error"
    assert "RESEARCH_BUDGET_EXHAUSTED" in res.content


def test_research_budget_counts_priority_and_exploitdb_tools():
    g = research_budget(max_calls=3)
    history = (
        _results("research__epss_lookup", 1)
        + _results("research__cisa_kev_lookup", 1)
        + _results("research__vendor_advisory_search", 1)
    )
    res = _run(g.awrap_tool_call(_request("research__exploitdb_fetch", history), _ok))
    assert res.status == "error"
    assert "RESEARCH_BUDGET_EXHAUSTED" in res.content


def test_budgets_have_distinct_names():
    # langchain rejects two middleware with the same .name on one agent, and the
    # researcher carries both browse_budget and research_budget. Each budget must
    # therefore have a unique name.
    names = {browse_budget().name, curl_budget().name, research_budget().name}
    assert len(names) == 3
    # Two instances of the same budget still share a name (correctly a dup).
    assert browse_budget().name == browse_budget().name


def test_research_budget_allows_episode_writes_and_returns():
    # Episode writes / the response tool aren't research tools — never blocked,
    # so the subagent can always record + return even past the cap.
    g = research_budget(max_calls=5)
    history = _results("grep", 50)
    for name in ("episodes__write_episode", "ResearchResult"):
        res = _run(g.awrap_tool_call(_request(name, history), _ok))
        assert res.content == "ran"
