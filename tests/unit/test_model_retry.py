"""Tests for the transient-model-error retry middleware.

A provider 529/429/5xx on a model call used to propagate through langgraph's
model node and crash the whole engagement. This retries transient errors with
backoff and re-raises only non-transient / control-flow exceptions.
"""

from __future__ import annotations

import asyncio

import pytest
from langgraph.errors import GraphInterrupt

from src.agent.middleware.model_retry import _is_transient, model_retry


def _run(coro):
    return asyncio.run(coro)


class _OverloadedError(Exception):
    status_code = 529


class _RateLimitedError(Exception):
    status_code = 429


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    async def _instant(_):
        return None
    monkeypatch.setattr(asyncio, "sleep", _instant)


# --- _is_transient -----------------------------------------------------------

def test_is_transient_by_status_code():
    assert _is_transient(_OverloadedError("Overloaded"))
    assert _is_transient(_RateLimitedError("rate limited"))


def test_is_transient_by_type_name():
    class OverloadedError(Exception): ...
    assert _is_transient(OverloadedError("x"))


def test_is_transient_by_phrase():
    assert _is_transient(Exception("the service is temporarily unavailable"))


def test_not_transient_for_value_error():
    assert not _is_transient(ValueError("bad input"))


# --- middleware --------------------------------------------------------------

def test_retries_then_succeeds():
    guard = model_retry(max_retries=5)
    calls = {"n": 0}

    async def handler(request):
        calls["n"] += 1
        if calls["n"] < 3:
            raise _OverloadedError("Overloaded")
        return "ok"

    assert _run(guard.awrap_model_call("req", handler)) == "ok"
    assert calls["n"] == 3  # failed twice, succeeded on the third


def test_gives_up_after_budget_and_reraises():
    guard = model_retry(max_retries=2)
    calls = {"n": 0}

    async def handler(request):
        calls["n"] += 1
        raise _OverloadedError("Overloaded")

    with pytest.raises(_OverloadedError):
        _run(guard.awrap_model_call("req", handler))
    assert calls["n"] == 3  # initial + 2 retries


def test_non_transient_reraises_immediately():
    guard = model_retry(max_retries=5)
    calls = {"n": 0}

    async def handler(request):
        calls["n"] += 1
        raise ValueError("schema error")

    with pytest.raises(ValueError):
        _run(guard.awrap_model_call("req", handler))
    assert calls["n"] == 1  # no retries for a non-transient error


def test_graph_interrupt_not_retried():
    # HITL interrupts must propagate immediately, never be retried.
    guard = model_retry(max_retries=5)
    calls = {"n": 0}

    async def handler(request):
        calls["n"] += 1
        raise GraphInterrupt(())

    with pytest.raises(GraphInterrupt):
        _run(guard.awrap_model_call("req", handler))
    assert calls["n"] == 1
