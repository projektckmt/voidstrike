"""Budget guard state + pricing tests."""

from __future__ import annotations

from src.agent.middleware.budget_guard import _BudgetState, _price_step, _resolve_pricing

# ---------------------------------------------------------------------------
# State accounting
# ---------------------------------------------------------------------------


def test_warning_threshold() -> None:
    s = _BudgetState(cap_usd=10.0)
    s.spent_usd = 8.0
    assert s.fraction == 0.8
    assert not s.warned
    assert not s.halted


def test_halt_threshold() -> None:
    s = _BudgetState(cap_usd=10.0)
    s.spent_usd = 9.6
    assert s.fraction >= 0.95


def test_remaining() -> None:
    s = _BudgetState(cap_usd=10.0)
    s.spent_usd = 3.5
    assert s.remaining == 6.5


def test_zero_cap_is_safe() -> None:
    s = _BudgetState(cap_usd=0.0)
    assert s.fraction == 0.0
    assert s.remaining == 0.0


# ---------------------------------------------------------------------------
# Pricing — these are the cost-runaway bugs we actually got bitten by.
# ---------------------------------------------------------------------------


def test_resolve_pricing_known_anthropic_models() -> None:
    # Bare name
    assert _resolve_pricing("claude-opus-4-8")["in"] == 15.0
    # With `anthropic/` prefix
    assert _resolve_pricing("anthropic/claude-opus-4-8")["in"] == 15.0
    # With `anthropic:` prefix
    assert _resolve_pricing("anthropic:claude-opus-4-8")["in"] == 15.0


def test_resolve_pricing_unknown_model_falls_back() -> None:
    """Unknown models should NOT cost $0 — fall back to a sane default so
    the budget guard still produces a meaningful number."""
    pricing = _resolve_pricing("some-future-model")
    assert pricing["in"] > 0
    assert pricing["out"] > 0


def test_price_step_input_only() -> None:
    """100k input tokens on Opus = 100k * $15 / 1M = $1.50"""
    cost = _price_step("claude-opus-4-8", {
        "input_tokens": 100_000,
        "output_tokens": 0,
    })
    assert abs(cost - 1.50) < 0.001


def test_price_step_output_only() -> None:
    """10k output tokens on Opus = 10k * $75 / 1M = $0.75"""
    cost = _price_step("claude-opus-4-8", {
        "input_tokens": 0,
        "output_tokens": 10_000,
    })
    assert abs(cost - 0.75) < 0.001


def test_price_step_with_cache_read_is_cheaper() -> None:
    """A cached read is ~10x cheaper than fresh input. This is the lever
    we get back by keeping prompt caching enabled."""
    fresh = _price_step("claude-opus-4-8", {
        "input_tokens": 100_000,
        "output_tokens": 0,
    })
    cached = _price_step("claude-opus-4-8", {
        "input_tokens": 100_000,
        "output_tokens": 0,
        "input_token_details": {"cache_read": 100_000},
    })
    # Cached read is significantly cheaper; ratio should be ~10x or better.
    assert cached < fresh
    assert cached < fresh / 5, (
        f"expected cached read to be << fresh, got cached=${cached:.4f} "
        f"vs fresh=${fresh:.4f}"
    )


def test_price_step_cache_write_costs_more_than_fresh() -> None:
    """First-time cache writes pay a small premium (~25%)."""
    fresh = _price_step("claude-opus-4-8", {
        "input_tokens": 100_000,
        "output_tokens": 0,
    })
    writing = _price_step("claude-opus-4-8", {
        "input_tokens": 100_000,
        "output_tokens": 0,
        "input_token_details": {"cache_creation": 100_000},
    })
    assert writing > fresh


def test_price_step_handles_haiku_not_opus_priced() -> None:
    """Haiku (the `test` profile's tier) must be priced as Haiku, not Opus —
    so budget accounting stays accurate across tiers."""
    opus_cost = _price_step("claude-opus-4-8", {
        "input_tokens": 100_000, "output_tokens": 0,
    })
    haiku_cost = _price_step("claude-haiku-4-5", {
        "input_tokens": 100_000, "output_tokens": 0,
    })
    assert haiku_cost < opus_cost / 10, (
        f"haiku should be ~20x cheaper than opus on input; "
        f"got haiku=${haiku_cost:.4f}, opus=${opus_cost:.4f}"
    )


def test_price_step_zero_usage_is_zero_cost() -> None:
    assert _price_step("claude-opus-4-8", {}) == 0
    assert _price_step("claude-opus-4-8",
                       {"input_tokens": 0, "output_tokens": 0}) == 0


def test_price_step_real_typical_step() -> None:
    """A typical opus step: ~5k input, ~500 output, no cache.
    Expected ~ 5000 * 15/1M + 500 * 75/1M = $0.075 + $0.0375 = ~$0.11"""
    cost = _price_step("claude-opus-4-8", {
        "input_tokens": 5_000, "output_tokens": 500,
    })
    assert 0.10 < cost < 0.13
