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


def test_model_arg_for_clamps_effort_for_sonnet_tier(monkeypatch) -> None:
    """Sonnet 4.6 (eco/postex) doesn't support xhigh/max — clamp to high."""
    monkeypatch.setenv("VOIDSTRIKE_THINKING_EFFORT", "max")
    calls = _stub_init_chat_model(monkeypatch)
    from src.agent.models import model_arg_for, model_for
    assert "sonnet" in model_for("eco", "postex")["model"]  # guards the premise
    out = model_arg_for("eco", "postex")
    assert not isinstance(out, str)
    assert calls["kwargs"]["output_config"] == {"effort": "high"}


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
    import src.agent.models as models
    monkeypatch.setattr(
        models, "model_for", lambda _p, _r: {"model": "openai:gpt-5", "fallbacks": []}
    )
    calls = _stub_init_chat_model(monkeypatch)
    out = models.model_arg_for("eco", "exploit")
    assert out == "openai:gpt-5"
    assert calls == {}  # init_chat_model was never called


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
