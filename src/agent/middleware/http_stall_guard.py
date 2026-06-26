"""Break repeated HTTP-result stalls inside exploit-style subagents.

`shell__http_json_request` returns `ok: true` when the transport succeeded,
even if the application replied 500/401 with the same blocker over and over.
That means `repeat_guard` sees success and a model can burn many expensive
turns retrying a stuck auth/RCE path. This guard fingerprints the semantic HTTP
outcome and forces a structured hand-back after a small number of repeats.
"""

from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlsplit

from ._util import parse_tool_content as _parse_tool_content


def _normalized_path(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    return parts.path or "/"


def _body_fingerprint(body: str, max_chars: int = 400) -> str:
    normalized = " ".join(body[:max_chars].split())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _http_outcome_signature(args: dict[str, Any], payload: dict[str, Any]) -> str | None:
    if payload.get("ok") is False:
        error = str(payload.get("error", ""))
        return f"transport-error::{_body_fingerprint(error)}"

    status = payload.get("status_code")
    if status is None:
        return None
    try:
        code = int(status)
    except (TypeError, ValueError):
        return None

    # Successful/redirect responses are real signal. Only cap repeated client
    # and server errors that are very likely to be a stuck prerequisite.
    if code < 400:
        return None

    method = str(args.get("method") or "POST").upper()
    path = _normalized_path(str(args.get("url") or ""))
    body = str(payload.get("body") or "")
    return f"{method} {path}::{code}::{_body_fingerprint(body)}"


def http_stall_guard(max_repeats: int = 5):
    """Cap repeated identical HTTP blockers from `shell__http_json_request`.

    After `max_repeats` semantically identical 4xx/5xx outcomes on the same
    method/path, the over-budget tool result is replaced with a hard
    instruction to return a partial structured result with the
    evidence and blocker instead of paying for another retry loop.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    repeats: dict[str, int] = {}

    class HttpStallGuard(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            tool_name = getattr(tool, "name", "") or ""
            if tool_name != "shell__http_json_request":
                return await handler(request)

            tool_call = getattr(request, "tool_call", {}) or {}
            args = tool_call.get("args", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""

            result = await handler(request)
            payload = _parse_tool_content(result)
            if not isinstance(payload, dict):
                return result

            sig = _http_outcome_signature(args, payload)
            if sig is None:
                repeats.clear()
                return result

            count = repeats.get(sig, 0) + 1
            repeats[sig] = count
            if count <= max_repeats:
                return result

            return ToolMessage(
                content=(
                    f"HTTP_STALL_BLOCKED: `shell__http_json_request` has seen the "
                    f"same blocking HTTP outcome {count} times ({sig}). Stop "
                    "retrying this endpoint. Return your structured result now "
                    "with `blocked_on` explaining the repeated status/body, any "
                    "partial success already proven, and the next recommended "
                    "manual or alternate action."
                ),
                tool_call_id=tool_call_id,
                name=tool_name,
                status="error",
            )

    return HttpStallGuard()
