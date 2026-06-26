"""Tests for the models module's small helpers — `tool_response_format` and
`model_for`. These are pure-Python utility functions.
"""

from __future__ import annotations

import pytest


def test_model_for_returns_dict_with_model_and_fallbacks() -> None:
    from src.agent.models import model_for
    choice = model_for("eco", "orchestrator")
    assert "model" in choice and isinstance(choice["model"], str)
    assert "fallbacks" in choice and isinstance(choice["fallbacks"], list)


def test_model_for_uses_provider_colon_model_format() -> None:
    from src.agent.models import model_for
    for profile in ("eco", "max", "test"):
        for role in ("orchestrator", "surface", "exploit", "postex", "analyst", "researcher"):
            ident = model_for(profile, role)["model"]  # type: ignore[arg-type]
            assert ":" in ident, f"{profile}/{role}: {ident!r} should be provider:model"


def test_eco_exploit_never_demoted() -> None:
    """Demoting Exploit in eco is what causes silent failure on
    hard boxes. Make sure we don't accidentally drop it."""
    from src.agent.models import HIGH, model_for
    assert model_for("eco", "exploit")["model"] == HIGH[0]


def test_test_profile_uses_cheapest_tier() -> None:
    from src.agent.models import LOW, model_for
    for role in ("orchestrator", "surface", "exploit", "postex", "analyst", "researcher"):
        assert model_for("test", role)["model"] == LOW[0]


def test_eco_never_uses_low_tier() -> None:
    """eco's floor is MID — LOW (Haiku) is too weak for real engagement work
    (it botched PostEx privesc triage). LOW belongs to the `test` profile only."""
    from src.agent.models import LOW, model_for
    for role in ("orchestrator", "surface", "exploit", "postex", "analyst", "researcher"):
        assert model_for("eco", role)["model"] not in LOW, (
            f"eco/{role} must not use a LOW-tier model"
        )


def test_eco_runs_noncritical_roles_on_mid() -> None:
    """eco runs the non-hot-loop roles on MID (Sonnet): surface, postex (was
    LOW), and analyst (a one-shot report). The hot-loop reasoning roles
    (orchestrator/exploit) stay HIGH."""
    from src.agent.models import HIGH, MID, model_for
    for role in ("surface", "postex", "analyst", "researcher"):
        assert model_for("eco", role)["model"] == MID[0], f"eco/{role} should be MID"
    for role in ("orchestrator", "exploit"):
        assert model_for("eco", role)["model"] == HIGH[0], f"eco/{role} should be HIGH"


def _stub_init_chat_model(monkeypatch):
    """Replace `langchain.chat_models.init_chat_model` with a recorder so the
    thinking-instance branch can be tested without the real dep or a network
    client. Returns a dict that captures the call's model_id + kwargs."""
    import sys
    import types

    calls: dict = {}
    fake = types.ModuleType("langchain.chat_models")

    def init_chat_model(model_id, **kwargs):  # noqa: ANN001, ANN202
        calls["model_id"] = model_id
        calls["kwargs"] = kwargs
        return object()  # a non-str sentinel standing in for a BaseChatModel

    fake.init_chat_model = init_chat_model
    monkeypatch.setitem(sys.modules, "langchain.chat_models", fake)
    if "langchain" not in sys.modules:
        monkeypatch.setitem(sys.modules, "langchain", types.ModuleType("langchain"))
    return calls


def test_model_arg_for_default_off_returns_string(monkeypatch) -> None:
    """Unset env → byte-identical to today: the plain provider:model string."""
    monkeypatch.delenv("VOIDSTRIKE_THINKING_EFFORT", raising=False)
    from src.agent.models import model_arg_for, model_for
    for role in ("exploit", "postex"):
        out = model_arg_for("eco", role)
        assert out == model_for("eco", role)["model"]
        assert isinstance(out, str)


@pytest.mark.parametrize("val", ["", "off", "0", "ultra", "2048", "  "])
def test_model_arg_for_invalid_effort_returns_string(monkeypatch, val) -> None:
    """Empty / off / non-effort values all disable thinking (fail safe)."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", val)
    from src.agent.models import model_arg_for
    assert isinstance(model_arg_for("eco", "exploit"), str)


def test_model_arg_for_non_thinking_roles_always_string(monkeypatch) -> None:
    """Only exploit/postex opt into thinking; other roles stay strings even
    with effort set (the orchestrator MUST stay a string — gotcha #2)."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "high")
    from src.agent.models import model_arg_for
    for role in ("orchestrator", "surface", "analyst", "researcher"):
        assert isinstance(model_arg_for("eco", role), str)


def test_model_arg_for_enabled_builds_adaptive_instance(monkeypatch) -> None:
    """Valid effort + thinking role → an instance built with the Opus 4.8
    adaptive-thinking surface (no budget_tokens, no temperature)."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "xhigh")
    calls = _stub_init_chat_model(monkeypatch)
    from src.agent.models import model_arg_for
    out = model_arg_for("eco", "exploit")  # eco/exploit → Opus
    assert not isinstance(out, str)
    assert calls["model_id"].startswith("anthropic:")
    kw = calls["kwargs"]
    assert kw["thinking"] == {"type": "adaptive", "display": "summarized"}
    assert kw["output_config"] == {"effort": "xhigh"}  # Opus keeps xhigh
    assert "budget_tokens" not in kw.get("thinking", {})  # removed on 4.8
    assert "temperature" not in kw                        # removed on 4.8


def test_model_arg_for_sonnet_tier_returns_string(monkeypatch) -> None:
    """Sonnet 4.6 (eco/postex) can't think under the agent's forced tool_choice
    (Anthropic 400s on thinking+forced-tools — adaptive and classic). So the
    direct path must NOT build a thinking instance — leave a plain string."""
    monkeypatch.delenv("VOIDSTRIKE_USE_LITELLM", raising=False)
    monkeypatch.setenv("VOIDSTRIKE_USE_LITELLM", "false")
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "max")
    calls = _stub_init_chat_model(monkeypatch)
    from src.agent.models import model_arg_for, model_for
    assert "sonnet" in model_for("eco", "postex")["model"]  # guards the premise
    out = model_arg_for("eco", "postex")
    assert isinstance(out, str)
    assert calls == {}  # init_chat_model never called


def test_model_arg_for_haiku_tier_returns_string(monkeypatch) -> None:
    """The `test` profile runs exploit on Haiku, which has no adaptive-thinking
    support — fall back to the plain string, never build an instance."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "high")
    calls = _stub_init_chat_model(monkeypatch)
    from src.agent.models import model_arg_for
    out = model_arg_for("test", "exploit")  # test/exploit → Haiku
    assert isinstance(out, str)
    assert calls == {}


def test_model_arg_for_non_anthropic_tier_returns_string(monkeypatch) -> None:
    """A non-anthropic tier falls back to the plain string (the thinking wiring
    is Anthropic-specific) and never builds an instance."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "high")
    # No OpenRouter key → the key-fallback can't fire, so a missing OpenAI key
    # still yields the plain string (this test is about the thinking path).
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    import src.agent.models as models
    monkeypatch.setattr(
        models, "model_for", lambda _p, _r: {"model": "openai:gpt-5.5", "fallbacks": []}
    )
    calls = _stub_init_chat_model(monkeypatch)
    out = models.model_arg_for("eco", "exploit")
    assert out == "openai:gpt-5.5"
    assert calls == {}  # init_chat_model was never called


def _stub_chat_openai(monkeypatch):
    """Replace `langchain_openai.ChatOpenAI` with a recorder so the LiteLLM-proxy
    branch can be exercised without the real dep or a live proxy. Returns a dict
    capturing the constructor kwargs."""
    import sys
    import types

    calls: dict = {}
    fake = types.ModuleType("langchain_openai")

    class ChatOpenAI:  # noqa: N801
        def __init__(self, **kwargs):  # noqa: ANN003
            calls.update(kwargs)

    fake.ChatOpenAI = ChatOpenAI
    monkeypatch.setitem(sys.modules, "langchain_openai", fake)
    return calls


def test_gpt_profile_uses_native_openai_id() -> None:
    """The `gpt` profile uses the native `openai:gpt-5.5` id — routing to
    OpenRouter (when only that key is set) is left to the fallback, not hardcoded."""
    from src.agent.models import model_for
    for role in ("orchestrator", "surface", "exploit", "postex", "analyst", "researcher"):
        assert model_for("gpt", role)["model"] == "openai:gpt-5.5"


@pytest.mark.parametrize(
    ("effort", "expected"),
    [("low", "low"), ("medium", "medium"), ("high", "high"), ("xhigh", "high"), ("max", "high")],
)
def test_proxy_reasoning_openai_uses_reasoning_effort(monkeypatch, effort, expected) -> None:
    """OpenAI gpt models get the unified `reasoning_effort`, clamped to high."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", effort)
    from src.agent.models import _proxy_reasoning_kwargs
    assert _proxy_reasoning_kwargs("openai:gpt-5.5", "exploit") == {"reasoning_effort": expected}


def test_proxy_reasoning_opus_uses_adaptive_keeps_effort(monkeypatch) -> None:
    """Opus gets the adaptive thinking form via extra_body; Opus keeps xhigh/max."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "max")
    from src.agent.models import _proxy_reasoning_kwargs
    kw = _proxy_reasoning_kwargs("anthropic:claude-opus-4-8", "exploit")
    assert kw["max_tokens"] == 8192
    assert kw["extra_body"]["thinking"] == {"type": "adaptive", "display": "summarized"}
    assert kw["extra_body"]["output_config"] == {"effort": "max"}
    assert "reasoning_effort" not in kw  # not the OpenAI knob


def test_proxy_reasoning_sonnet_excluded(monkeypatch) -> None:
    """Sonnet 4.6 gets NO reasoning — thinking 400s under our forced tool_choice,
    so only Opus adaptive qualifies among Anthropic models."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "max")
    from src.agent.models import _proxy_reasoning_kwargs
    assert _proxy_reasoning_kwargs("anthropic:claude-sonnet-4-6", "postex") == {}


def test_proxy_reasoning_only_thinking_roles(monkeypatch) -> None:
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "high")
    from src.agent.models import _proxy_reasoning_kwargs
    for role in ("orchestrator", "surface", "analyst", "researcher"):
        assert _proxy_reasoning_kwargs("openai:gpt-5.5", role) == {}
    for role in ("exploit", "postex"):
        assert _proxy_reasoning_kwargs("openai:gpt-5.5", role) != {}


def test_proxy_reasoning_excludes_qwen_ollama_nonopus_anthropic(monkeypatch) -> None:
    """Qwen breaks forced tool_choice; ollama doesn't reason; non-Opus Anthropic
    (Sonnet/Haiku) 400s on thinking+forced-tools → no kwargs for any of them."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "high")
    from src.agent.models import _proxy_reasoning_kwargs
    assert _proxy_reasoning_kwargs("openrouter:qwen/qwen3.7-max", "exploit") == {}
    assert _proxy_reasoning_kwargs("ollama:qwen3:32b", "exploit") == {}
    assert _proxy_reasoning_kwargs("anthropic:claude-haiku-4-5", "exploit") == {}
    assert _proxy_reasoning_kwargs("anthropic:claude-sonnet-4-6", "exploit") == {}


def test_proxy_reasoning_off_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("VOIDSTRIKE_THINKING_EFFORT", raising=False)
    from src.agent.models import _proxy_reasoning_kwargs
    assert _proxy_reasoning_kwargs("openai:gpt-5.5", "exploit") == {}


def test_model_arg_for_gpt_thinking_role_attaches_reasoning(monkeypatch) -> None:
    """Proxy on + gpt profile + thinking role + effort set → a ChatOpenAI pointed
    at the proxy's gpt id, carrying the unified reasoning_effort param."""
    monkeypatch.setenv("VOIDSTRIKE_USE_LITELLM", "true")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sk-test")
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "max")
    calls = _stub_chat_openai(monkeypatch)
    from src.agent.models import model_arg_for
    out = model_arg_for("gpt", "exploit")
    assert not isinstance(out, str)
    assert calls["model"] == "openai/gpt-5.5"
    assert calls["reasoning_effort"] == "high"  # max clamps to high


def test_model_arg_for_eco_thinking_role_uses_adaptive(monkeypatch) -> None:
    """Reasoning is not gpt-only: eco/exploit (Opus) through the proxy gets the
    adaptive thinking form, not reasoning_effort."""
    monkeypatch.setenv("VOIDSTRIKE_USE_LITELLM", "true")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sk-test")
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "high")
    calls = _stub_chat_openai(monkeypatch)
    from src.agent.models import model_arg_for
    out = model_arg_for("eco", "exploit")
    assert not isinstance(out, str)
    assert calls["model"] == "anthropic/claude-opus-4-8"
    assert calls["extra_body"]["thinking"]["type"] == "adaptive"
    assert calls["extra_body"]["output_config"] == {"effort": "high"}
    assert "reasoning_effort" not in calls


def test_model_arg_for_gpt_non_thinking_role_no_reasoning(monkeypatch) -> None:
    """Non-thinking roles route through the proxy without any reasoning param."""
    monkeypatch.setenv("VOIDSTRIKE_USE_LITELLM", "true")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sk-test")
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "max")
    calls = _stub_chat_openai(monkeypatch)
    from src.agent.models import model_arg_for
    out = model_arg_for("gpt", "surface")
    assert not isinstance(out, str)
    assert calls["model"] == "openai/gpt-5.5"
    assert "reasoning_effort" not in calls
    assert "extra_body" not in calls


def test_model_arg_for_qwen_thinking_role_no_reasoning(monkeypatch) -> None:
    """qwen profile exploit/postex must NOT get reasoning (breaks forced tool_choice)."""
    monkeypatch.setenv("VOIDSTRIKE_USE_LITELLM", "true")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sk-test")
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "max")
    calls = _stub_chat_openai(monkeypatch)
    from src.agent.models import model_arg_for
    out = model_arg_for("qwen", "exploit")
    assert not isinstance(out, str)
    assert calls["model"] == "openrouter/qwen/qwen3.7-max"
    assert "reasoning_effort" not in calls
    assert "extra_body" not in calls


def test_tool_response_format_raises_when_langchain_missing(monkeypatch) -> None:
    """If langchain isn't importable, `tool_response_format` should surface a
    clear ImportError instead of failing later inside deepagents with a
    cryptic AttributeError."""
    import sys
    # Force langchain.agents.structured_output to be unimportable.
    monkeypatch.setitem(sys.modules, "langchain.agents.structured_output", None)
    from src.agent.models import tool_response_format
    with pytest.raises((ImportError, TypeError)):
        tool_response_format(object)


def test_tool_response_format_wraps_via_toolstrategy(monkeypatch) -> None:
    """Confirm `tool_response_format(X)` returns a ToolStrategy-wrapped form
    when the import succeeds. We stub the module to avoid the real dep."""
    import sys
    import types

    fake = types.ModuleType("langchain.agents.structured_output")

    class FakeToolStrategy:
        def __init__(self, schema):
            self.schema = schema

    fake.ToolStrategy = FakeToolStrategy
    monkeypatch.setitem(sys.modules, "langchain.agents.structured_output", fake)

    # Also stub parents so the dotted import resolves.
    parents = ["langchain", "langchain.agents"]
    for name in parents:
        if name not in sys.modules:
            monkeypatch.setitem(sys.modules, name, types.ModuleType(name))

    from src.agent.models import tool_response_format

    class Schema: ...

    out = tool_response_format(Schema)
    assert isinstance(out, FakeToolStrategy)
    assert out.schema is Schema
