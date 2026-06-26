"""Budget guard middleware.

Tracks cumulative cost from the episode log and aborts the engagement when the
configured cap is reached (with a soft-warning at 80% and a hard-stop at 95%).
Guards against the "cost runaway" failure mode.

## Pricing

We compute per-step cost using realistic Anthropic / OpenAI list prices,
broken out by token kind:

  - input (uncached)
  - input read from cache (≈10% of full price)
  - input written to cache (≈125% of full price for ephemeral 5-min cache)
  - output

The numbers are list prices as of late 2025 — if Anthropic rolls a new
generation, update `_PRICING_USD_PER_M`. They're not load-bearing for
correctness; the goal is "operator sees a number that's within ~20% of the
real bill" so they can size their `budget_usd` realistically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Prices in USD per 1 million tokens. Keys are the model identifier as
# reported in `usage_metadata` / `response_metadata.model_name`.
# Falls back to `_FALLBACK_PRICING` for unknown models so we still produce a
# rough number instead of $0.
_PRICING_USD_PER_M: dict[str, dict[str, float]] = {
    # Anthropic
    "claude-opus-4-8":   {"in": 15.0, "out": 75.0, "cache_read": 1.50, "cache_write": 18.75},
    "claude-opus-4-7":   {"in": 15.0, "out": 75.0, "cache_read": 1.50, "cache_write": 18.75},
    "claude-opus-4-6":   {"in": 15.0, "out": 75.0, "cache_read": 1.50, "cache_write": 18.75},
    "claude-sonnet-4-6": {"in":  3.0, "out": 15.0, "cache_read": 0.30, "cache_write":  3.75},
    "claude-sonnet-4-5": {"in":  3.0, "out": 15.0, "cache_read": 0.30, "cache_write":  3.75},
    "claude-haiku-4-5":  {"in":  0.80, "out": 4.00, "cache_read": 0.08, "cache_write":  1.00},
    # OpenAI (rough — list prices for gpt-5-class as of writing; gpt-5.5 reuses
    # gpt-5 figures and 5.4-mini/nano reuse the 5-mini/nano figures pending
    # confirmed pricing)
    "gpt-5.5":           {"in": 10.0, "out": 30.0, "cache_read": 1.00, "cache_write": 10.0},
    "gpt-5.4-mini":      {"in":  0.30, "out": 2.40, "cache_read": 0.075, "cache_write": 0.30},
    "gpt-5.4-nano":      {"in":  0.10, "out": 0.80, "cache_read": 0.025, "cache_write": 0.10},
}

# Used when we get usage data but can't identify the model — better to log
# *some* number than $0.00.
_FALLBACK_PRICING = {"in": 3.0, "out": 15.0, "cache_read": 0.30, "cache_write": 3.75}


def _price_step(model_name: str, usage: dict[str, Any]) -> float:
    """Convert a `usage_metadata` dict into a USD cost for one model step.

    `usage` follows langchain-core's standard shape:
        {
          "input_tokens": int,
          "output_tokens": int,
          "input_token_details": {"cache_read": int, "cache_creation": int},
          "total_tokens": int,
        }
    Some providers populate `input_token_details`, others don't — fall back
    to treating all input as uncached when details are missing.
    """
    pricing = _resolve_pricing(model_name)
    input_total = int(usage.get("input_tokens") or 0)
    output_total = int(usage.get("output_tokens") or 0)
    details = usage.get("input_token_details") or {}
    cached_read = int(details.get("cache_read") or details.get("cached") or 0)
    cached_write = int(details.get("cache_creation") or details.get("cache_write") or 0)
    uncached = max(0, input_total - cached_read - cached_write)
    return (
        uncached * pricing["in"]
        + cached_read * pricing["cache_read"]
        + cached_write * pricing["cache_write"]
        + output_total * pricing["out"]
    ) / 1_000_000


def _resolve_pricing(model_name: str) -> dict[str, float]:
    """Look up the per-1M-token prices for `model_name`. The name comes from
    `response_metadata.model_name`; we strip the `anthropic/` or
    `provider:` prefix some integrations add."""
    if not model_name:
        return _FALLBACK_PRICING
    candidates = [
        model_name,
        model_name.split("/", 1)[-1],
        model_name.split(":", 1)[-1],
    ]
    for c in candidates:
        if c in _PRICING_USD_PER_M:
            return _PRICING_USD_PER_M[c]
    return _FALLBACK_PRICING


@dataclass
class _BudgetState:
    cap_usd: float
    spent_usd: float = 0.0
    warned: bool = False
    halted: bool = False
    # Useful for the dashboard/CLI to display a breakdown later.
    spent_by_model: dict[str, float] = field(default_factory=dict)

    @property
    def remaining(self) -> float:
        return max(0.0, self.cap_usd - self.spent_usd)

    @property
    def fraction(self) -> float:
        if self.cap_usd <= 0:
            return 0.0
        return self.spent_usd / self.cap_usd


def budget_guard(cap_usd: float):
    """Returns an `AgentMiddleware` that tracks spend per engagement and
    short-circuits the model loop with a warning at 80% / a halt at 95%.

    Spend per step is taken from `usage_metadata` on the last AIMessage (the
    standard langchain-core metric across providers). The middleware adds a
    visible budget message into the state so the orchestrator sees it.
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import AIMessage  # noqa: PLC0415

    states: dict[str, _BudgetState] = {}

    def _get(thread_id: str) -> _BudgetState:
        if thread_id not in states:
            states[thread_id] = _BudgetState(cap_usd=cap_usd)
        return states[thread_id]

    class BudgetGuard(AgentMiddleware):
        async def aafter_model(self, state):  # noqa: ANN001
            thread_id = state.get("thread_id") or state.get("configurable", {}).get("thread_id") or "default"
            s = _get(thread_id)

            # Pull token usage from the last message if available.
            messages = state.get("messages") or []
            if messages:
                last = messages[-1]
                usage = getattr(last, "usage_metadata", None) or {}
                model_name = (
                    (getattr(last, "response_metadata", None) or {}).get("model_name")
                    or (getattr(last, "response_metadata", None) or {}).get("model")
                    or ""
                )
                step_cost = _price_step(model_name, usage)
                if step_cost > 0:
                    s.spent_usd += step_cost
                    key = model_name or "(unknown)"
                    s.spent_by_model[key] = s.spent_by_model.get(key, 0.0) + step_cost

            if s.fraction >= 0.95 and not s.halted:
                s.halted = True
                return {
                    "messages": [
                        AIMessage(
                            content=(
                                f"BUDGET HALT: ${s.spent_usd:.2f} of "
                                f"${s.cap_usd:.2f} spent (>=95%). "
                                "Aborting engagement."
                            )
                        )
                    ],
                    "halt": True,
                }
            if s.fraction >= 0.80 and not s.warned:
                s.warned = True
                return {
                    "messages": [
                        AIMessage(
                            content=(
                                f"BUDGET WARNING: ${s.spent_usd:.2f} of "
                                f"${s.cap_usd:.2f} spent (>=80%). "
                                "Tighten remaining work and prioritise objective-met paths."
                            )
                        )
                    ]
                }
            return None

    return BudgetGuard()
