"""Harness profile registration tests.

The profile excludes the heavy fs tools and the Anthropic prompt-caching
middleware. Both were broken at various points in the saga and the
regressions were hard to notice. These tests pin:

  - `register()` is idempotent (multi-call safe)
  - When deepagents is missing, `register()` doesn't blow up the whole agent
  - When AnthropicPromptCachingMiddleware isn't where we expect, we register
    anyway (just without the middleware exclusion) instead of failing
"""

from __future__ import annotations

import sys
import types

import pytest


@pytest.fixture(autouse=True)
def reset_registered_flag(monkeypatch):
    """Each test runs against a fresh register() state."""
    from src.agent import profile as profile_mod
    monkeypatch.setattr(profile_mod, "_REGISTERED", False)


def _install_fake_deepagents(monkeypatch, capture: list) -> None:
    """Stub out the deepagents.{HarnessProfile, register_harness_profile} pair
    so the test doesn't require the real package."""

    class FakeHarnessProfile:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    def fake_register(key, profile):
        capture.append((key, profile))

    mod = types.ModuleType("deepagents")
    mod.HarnessProfile = FakeHarnessProfile
    mod.register_harness_profile = fake_register
    monkeypatch.setitem(sys.modules, "deepagents", mod)


def test_register_calls_register_harness_profile_under_expected_keys(monkeypatch):
    capture: list = []
    _install_fake_deepagents(monkeypatch, capture)

    from src.agent.profile import register
    register()

    keys = [k for k, _ in capture]
    assert "anthropic" in keys
    assert "anthropic:claude-opus-4-8" in keys
    assert "anthropic:claude-sonnet-4-6" in keys
    assert "anthropic:claude-haiku-4-5" in keys


def test_register_excludes_heavy_fs_tools(monkeypatch):
    capture: list = []
    _install_fake_deepagents(monkeypatch, capture)

    from src.agent.profile import register
    register()

    _, profile = capture[0]
    excluded = profile.kwargs["excluded_tools"]
    # These are the schema-bulk fs tools we hide from the model surface.
    for tool in {"ls", "write_file", "edit_file", "glob", "grep"}:
        assert tool in excluded
    # read_file is deliberately KEPT — deepagents' skills load their SKILL.md
    # bodies on demand via read_file (progressive disclosure). Excluding it
    # would let the agent see the skill list but never read any instructions.
    assert "read_file" not in excluded


def test_register_keeps_prompt_caching_middleware_enabled(monkeypatch):
    """We do NOT exclude AnthropicPromptCachingMiddleware. An earlier round
    of code excluded it on a wrong theory; the actual fix for "compiled
    grammar too large" was tool-name prefixing in `_load_prefixed_mcp_tools`.
    Keeping the middleware enabled saves ~90% on cached input cost — material
    on Opus runs.

    If you're re-introducing the exclusion, document the new reason and
    update this test deliberately."""
    capture: list = []
    _install_fake_deepagents(monkeypatch, capture)

    from src.agent.profile import register
    register()

    _, profile = capture[0]
    excluded_middleware = profile.kwargs.get("excluded_middleware") or frozenset()
    assert not excluded_middleware, (
        "AnthropicPromptCachingMiddleware must stay enabled for cost savings. "
        "Found exclusions: " + repr(set(excluded_middleware))
    )


def test_register_idempotent(monkeypatch):
    capture: list = []
    _install_fake_deepagents(monkeypatch, capture)

    from src.agent.profile import register
    register()
    first_call_count = len(capture)
    register()
    register()
    assert len(capture) == first_call_count, \
        "register() must be idempotent — calling it again duplicates registrations"


def test_register_tolerates_missing_deepagents(monkeypatch):
    """If deepagents isn't installed (e.g. wrong venv), register() should
    log + no-op instead of crashing — so the rest of the agent code can
    still import."""
    # Force the import to fail.
    monkeypatch.setitem(sys.modules, "deepagents", None)

    from src.agent.profile import register
    # Should not raise.
    register()
