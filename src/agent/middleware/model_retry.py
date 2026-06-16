"""Retry transient model-provider errors instead of crashing the engagement.

A model call can hit a transient provider error — Anthropic **529 Overloaded**,
429 rate-limit, 5xx, connection timeouts. langgraph's model node has no retry,
so the exception propagates through `_panic_or_proceed` and **kills the whole
engagement** (observed: a single 529 mid-run ended a long engagement). The
provider SDK's own retries (a couple, short backoff) get exhausted during a
sustained overload.

We can't just set `max_retries` on the model object: the agents are created from
`provider:model` *strings* so deepagents applies its HarnessProfile (CLAUDE.md
gotcha #2), not pre-built instances we could configure. So we retry at the
middleware layer — `awrap_model_call` re-invokes the model call with exponential
backoff + jitter, re-raising only after the budget is exhausted or for
non-transient / control-flow exceptions.
"""

from __future__ import annotations

import asyncio
import logging
import random

log = logging.getLogger("voidstrike.agent")

# HTTP statuses worth retrying (overload / rate-limit / transient server errors).
_RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}

# SDK exception class names that mean "transient, try again" across providers.
_RETRY_EXC_NAMES = {
    "OverloadedError", "RateLimitError", "APITimeoutError", "APIConnectionError",
    "InternalServerError", "ServiceUnavailableError", "APIResponseValidationError",
}

_RETRY_PHRASES = ("overloaded", "rate limit", "rate_limit", "service unavailable",
                  "temporarily unavailable", "timeout", "connection reset",
                  "connection error")


def _status_code(exc: object) -> int | None:
    code = getattr(exc, "status_code", None)
    if code is None:
        resp = getattr(exc, "response", None)
        code = getattr(resp, "status_code", None)
    return code if isinstance(code, int) else None


def _is_transient(exc: BaseException) -> bool:
    if _status_code(exc) in _RETRY_STATUS:
        return True
    if type(exc).__name__ in _RETRY_EXC_NAMES:
        return True
    msg = str(exc).lower()
    return any(p in msg for p in _RETRY_PHRASES)


def model_retry(max_retries: int = 8, base_delay: float = 1.0, max_delay: float = 60.0):
    """Return middleware that retries transient model-call failures with backoff.

    Attach to every agent loop (orchestrator + subagents) — any model call can
    hit a provider overload, and one uncaught 529 ends the engagement.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langgraph.errors import GraphBubbleUp, GraphRecursionError  # noqa: PLC0415

    class ModelRetry(AgentMiddleware):
        async def awrap_model_call(self, request, handler):  # noqa: ANN001
            attempt = 0
            while True:
                try:
                    return await handler(request)
                except (GraphBubbleUp, GraphRecursionError):
                    raise  # control flow (HITL interrupt, recursion halt) — never retry
                except Exception as exc:  # noqa: BLE001
                    if attempt >= max_retries or not _is_transient(exc):
                        raise
                    attempt += 1
                    delay = min(base_delay * 2 ** (attempt - 1), max_delay)
                    delay *= 0.5 + random.random()  # jitter, 0.5x–1.5x
                    log.warning(
                        "transient model error (%s: %s) — retry %d/%d in %.1fs",
                        type(exc).__name__, str(exc)[:120], attempt, max_retries, delay,
                    )
                    await asyncio.sleep(delay)

    return ModelRetry()
