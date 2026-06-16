"""Cap how many times a subagent may call one grinding tool before it must move on.

Two observed spirals share a shape — a subagent hammers a single tool without
converging and never returns its result:
  * the researcher loaded 92 `browser__goto` pages and never emitted a result;
  * the surface agent fired 90 `surface__curl` requests (50 at one Flowise
    auth-bypass endpoint) and never returned `SurfaceFindings`.

`stuck_detector` is orchestrator-only, `repeat_guard` only catches byte-identical
failing calls (these vary the URL / payload format), and the tmux guards don't
apply. So this caps page/request *breadth* per invocation: it counts completed
results for `tool_name` in the current subagent invocation (read statelessly
from `request.state`, so a second `task()` delegation starts fresh — no
cross-invocation leak) and, once the cap is hit, blocks further calls with a
`directive` telling the subagent to stop and return.

`browse_budget` and `curl_budget` are thin specializations.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def _messages_from_state(state: Any) -> list[Any]:
    if isinstance(state, dict):
        return state.get("messages") or []
    return getattr(state, "messages", None) or []


def request_budget(tools: str | Iterable[str], max_calls: int, *, marker: str, directive: str):
    """Return middleware that caps total calls across `tools` per invocation.

    `tools` is one tool name or a set of them — the budget counts completed
    results for *any* of them (so a multi-tool research grind is bounded even as
    the model switches tools). On the call that would exceed `max_calls`, returns
    a `status="error"` ToolMessage `"{marker}: ...{directive}"` instead of
    executing. Count is read statelessly from `request.state`, so a second
    `task()` delegation starts fresh.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    names = frozenset({tools} if isinstance(tools, str) else tools)

    class RequestBudget(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            name = getattr(tool, "name", "") or ""
            if name not in names:
                return await handler(request)

            messages = _messages_from_state(getattr(request, "state", None))
            done = sum(
                1
                for m in messages
                if isinstance(m, ToolMessage) and getattr(m, "name", "") in names
            )
            if done >= max_calls:
                tool_call = getattr(request, "tool_call", {}) or {}
                return ToolMessage(
                    content=f"{marker}: you've made {done} of these calls this task — "
                    f"that is enough. {directive}",
                    tool_call_id=tool_call.get("id", "") or "",
                    name=name,
                    status="error",
                )
            return await handler(request)

    # langchain rejects two middleware with the same `.name` (which defaults to
    # the class name) on one agent. A subagent can carry more than one budget
    # (e.g. the researcher gets both browse_budget and research_budget), so give
    # each instance a distinct class name derived from its unique marker.
    RequestBudget.__name__ = f"RequestBudget_{marker}"
    RequestBudget.__qualname__ = RequestBudget.__name__
    return RequestBudget()


def browse_budget(max_browses: int = 25):
    """Cap `browser__goto` navigations — push a browser-driven subagent (the
    researcher) to synthesize and return instead of spiraling through pages."""
    return request_budget(
        "browser__goto",
        max_browses,
        marker="BROWSE_BUDGET_EXHAUSTED",
        directive=(
            "Stop navigating and RETURN now: synthesize the exploit chain (CVE id, "
            "the exact request/primitive, prerequisites) from what you've already "
            "read and call your structured response tool. Partial or negative "
            "findings are fine — record key facts with `episodes__write_episode`, "
            "then return. You may still `browser__read_dom` pages already loaded, "
            "but do not navigate to new ones."
        ),
    )


def curl_budget(max_calls: int = 40):
    """Cap `surface__curl` requests — surface is recon: characterize the surface
    and hand off, don't grind an exploit (e.g. an auth-bypass) over many requests."""
    return request_budget(
        "surface__curl",
        max_calls,
        marker="CURL_BUDGET_EXHAUSTED",
        directive=(
            "You are RECON, not exploitation. Stop probing and return "
            "`SurfaceFindings` now with what you've characterized (service/version, "
            "live endpoints, and any CVE/auth-bypass hypothesis). Hand the actual "
            "exploitation — forgot-password/auth-bypass, credential dumping, LFI — "
            "to the exploit subagent; do not grind it here."
        ),
    )


# The read/search tools a research-style subagent grinds. Counted together so
# the cap holds no matter which one it spirals on (per-tool caps just relocate
# the spiral: goto -> grep -> read_file ...). Episode writes and the structured
# response tool are deliberately excluded — those are progress / the return.
_RESEARCH_TOOLS = frozenset({
    "browser__goto", "browser__read_dom", "grep", "read_file",
    "exploit__poc_search", "exploit__searchsploit_lookup",
    "research__cve_lookup", "research__vendor_advisory_search",
    "research__epss_lookup", "research__cisa_kev_lookup",
    "research__github_poc_search", "research__exploitdb_fetch",
    "research__fetch_poc", "research__poc_static_review",
    "research__affected_version_check",
})


def research_budget(max_calls: int = 50):
    """Cap total read/search calls a research subagent makes per invocation, so
    it converges to a `ResearchResult` instead of spiraling across tools."""
    return request_budget(
        _RESEARCH_TOOLS,
        max_calls,
        marker="RESEARCH_BUDGET_EXHAUSTED",
        directive=(
            "Stop gathering and RETURN now — you've read/searched plenty. Synthesize "
            "what you have into your structured response (CVE id, the concrete "
            "exploitation primitive, prerequisites) and call it. Partial or "
            "low-confidence is fine — record key facts with `episodes__write_episode`, "
            "then return. A focused lead the exploit agent can act on beats more "
            "reading that never ships."
        ),
    )
