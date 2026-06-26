"""Guard against unproductive ffuf loops."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from ._util import parse_tool_content as _parse_tool_content


@dataclass
class _FuzzState:
    attempts: int = 0
    empty_results: int = 0
    missing_wordlists: int = 0

    def should_block(self, *, max_attempts: int, max_empty: int, max_missing: int) -> bool:
        return (
            self.attempts >= max_attempts
            or self.empty_results >= max_empty
            or self.missing_wordlists >= max_missing
        )

    def record(self, result: Any) -> None:
        self.attempts += 1
        parsed = _parse_tool_content(result)
        if not isinstance(parsed, dict):
            return
        if parsed.get("ok") is False and "wordlist not found" in str(parsed.get("error", "")):
            self.missing_wordlists += 1
            return
        if parsed.get("ok") is True and parsed.get("results") == []:
            self.empty_results += 1


def _ffuf_scope(url: str) -> str:
    """Group related FUZZ and FUZZ.php attempts by origin + directory."""
    parsed = urlsplit(url)
    if not parsed.scheme or not parsed.netloc:
        return url.split("FUZZ", 1)[0]
    before_fuzz = parsed.path.split("FUZZ", 1)[0]
    directory = before_fuzz.rsplit("/", 1)[0] if before_fuzz else ""
    return f"{parsed.scheme}://{parsed.netloc}{directory}/"


def fuzz_guard(max_attempts: int = 4, max_empty: int = 3, max_missing_wordlists: int = 1):
    """Limit repetitive ffuf attempts against the same web root.

    This is intentionally deterministic. The prompt can ask the model to pivot,
    but the guard prevents a bad loop from burning minutes on every SecLists
    variant after repeated empty results.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    states: dict[str, _FuzzState] = {}

    class FuzzGuard(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            tool_name = getattr(tool, "name", "")
            if tool_name != "surface__ffuf":
                return await handler(request)

            tool_call = getattr(request, "tool_call", {}) or {}
            args = tool_call.get("args", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""
            scope = _ffuf_scope(str(args.get("url", "")))
            state = states.setdefault(scope, _FuzzState())
            if state.should_block(
                max_attempts=max_attempts,
                max_empty=max_empty,
                max_missing=max_missing_wordlists,
            ):
                return ToolMessage(
                    content=(
                        "FFUF_BUDGET_EXHAUSTED: stop directory fuzzing this web root. "
                        f"Scope={scope!r}; attempts={state.attempts}; "
                        f"empty_results={state.empty_results}; "
                        f"missing_wordlists={state.missing_wordlists}. "
                        "Pivot to httpx/browser fingerprinting, source/HTML review, service-specific "
                        "enumeration, credentials/default routes, or report that path fuzzing produced no signal."
                    ),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                    status="error",
                )

            result = await handler(request)
            state.record(result)
            return result

    return FuzzGuard()
