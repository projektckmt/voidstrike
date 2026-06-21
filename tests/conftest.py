"""Shared pytest fixtures.

`src/__init__.py` already skips loading `.env` under pytest, but a developer's
*shell* may still export model-routing vars (OPENROUTER_API_KEY etc.). Those
change how `src.agent.models` resolves a model (native string vs. an OpenRouter
key-fallback / proxy instance), which would make the model/subagent-spec tests
pass or fail depending on the local environment. Clear them for every test so
resolution is deterministic; a test that needs one set still does so via its own
`monkeypatch` (which runs after this autouse fixture and wins).
"""

from __future__ import annotations

import pytest

_ROUTING_ENV = (
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "LITELLM_MASTER_KEY",
    "VOIDSTRIKE_THINKING_EFFORT",
)


@pytest.fixture(autouse=True)
def _clean_model_routing_env(monkeypatch):
    for var in _ROUTING_ENV:
        monkeypatch.delenv(var, raising=False)
    # The LiteLLM proxy is ON by default (unset = enabled), so explicitly disable
    # it for tests — they assert on the direct-path `provider:model` strings and
    # have no proxy to reach. A test that wants proxy behaviour sets it itself.
    monkeypatch.setenv("VOIDSTRIKE_USE_LITELLM", "false")
