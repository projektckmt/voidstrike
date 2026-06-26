"""Guard against unproductive vhost-enumeration loops.

`surface__vhost_enum` brute-forces the `Host:` header against a DNS wordlist and
keeps only responses that differ from the wildcard baseline. When the target
serves a *uniform* response for every unknown `Host` (a wildcard responder —
common on CTF boxes fronting the real app on a named vhost), every wordlist run
comes back empty with a hint that says exactly that. The failure mode this
catches (observed on a real run): the agent reads "no vhost differed from the
wildcard" as "use a bigger wordlist" and re-runs `vhost_enum` 5× with
ever-larger SecLists files — which cannot work, because no DNS wordlist beats a
wildcard responder. The productive move is to derive candidate vhost names from
*context* (the box/domain name, the page title, the discovered product) and
probe them directly with a `Host:`-header `surface__curl`.

Deterministic, like `fuzz_guard`: the prompt can ask the model to pivot, but
this stops the loop regardless after `max_unproductive` empty/wildcard results
against the same host. Attach to the surface subagent loop (orchestrator-level
middleware doesn't intercept tool calls inside a subagent runtime).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ._util import parse_tool_content as _parse_tool_content


def _host_of(base_url: str) -> str:
    """Group attempts by the host being fuzzed (`http://wingdata.htb/` -> host)."""
    netloc = urlsplit(base_url).netloc
    return netloc or base_url


def _is_unproductive(result: Any) -> bool:
    """A vhost_enum result that found no real vhost: empty matches, or the tool's
    own 'nothing differed from the wildcard' signal."""
    parsed = _parse_tool_content(result)
    if not isinstance(parsed, dict):
        return False
    if parsed.get("ok") is True and parsed.get("results") == []:
        return True
    return "wildcard" in str(parsed.get("hint", "")).lower()


def vhost_guard(max_unproductive: int = 2):
    """Stop re-running `surface__vhost_enum` once it has come back empty /
    wildcard-only `max_unproductive` times for the same host."""
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    unproductive: dict[str, int] = {}

    class VhostGuard(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool_name = getattr(getattr(request, "tool", None), "name", "") or ""
            if tool_name != "surface__vhost_enum":
                return await handler(request)

            tool_call = getattr(request, "tool_call", {}) or {}
            args = tool_call.get("args", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""
            host = _host_of(str(args.get("base_url", "")))

            if unproductive.get(host, 0) >= max_unproductive:
                return ToolMessage(
                    content=(
                        "VHOST_ENUM_UNPRODUCTIVE: stop wordlist-grinding the `Host:` header "
                        f"for {host!r} — it came back empty/wildcard-only {unproductive[host]} "
                        "times, which means this box serves a uniform response for every unknown "
                        "Host (a wildcard responder). A bigger DNS wordlist cannot beat that. "
                        "Instead, derive candidate vhost names from CONTEXT — the box/domain name, "
                        "the page title, the product you fingerprinted — and probe them directly "
                        "with a Host-header curl, e.g. "
                        "`surface__curl(url=\"http://<ip>/\", headers={\"Host\": \"ftp." + host + "\"})` "
                        "(try `ftp.`, `admin.`, `portal.`, `dev.`, the product name). "
                        "If those also return the wildcard page, report that vhost enumeration is "
                        "wildcard-blocked and hand back."
                    ),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                    status="error",
                )

            result = await handler(request)
            if _is_unproductive(result):
                unproductive[host] = unproductive.get(host, 0) + 1
            return result

    return VhostGuard()
