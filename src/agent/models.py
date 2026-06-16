"""Profile → per-role model mapping.

Exploit stays HIGH in `eco` because demotion there is what causes
silent failure on hard boxes. `eco`'s floor is MID (Sonnet) — LOW (Haiku) is
reserved for the `test` profile only; it's too weak for real engagement work.

## We hand deepagents `provider:model` *strings*, not instances

`model_for(...)["model"]` is a `provider:model` string; the subagent specs and
the orchestrator pass that string straight to `create_deep_agent`. deepagents'
`resolve_model` then builds the model AND looks up the registered
`HarnessProfile` by the string (fs-tool exclusion on the orchestrator surface;
see CLAUDE.md gotcha #2). The Anthropic strict-grammar "too large" error is NOT
fixed here — it's the tool-name prefixing shim in `main.py` (see `profile.py`).

The one exception is `model_arg_for(...)`, which may return a thinking-enabled
`BaseChatModel` *instance* for a reasoning-heavy subagent (exploit/postex) when
`VOIDSTRIKE_THINKING_EFFORT` is set. That's safe for *subagents* specifically:
deepagents appends `AnthropicPromptCachingMiddleware` to every subagent
unconditionally (caching is preserved), and subagent fs-tool exclusion comes
from the `block_fs_tools` middleware in `main.py`, not the harness profile — so
an instance loses nothing material there. It is NOT safe for the orchestrator,
whose fs-tool exclusion *is* the harness profile (gotcha #2).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Literal, TypedDict

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

Profile = Literal["eco", "max", "test"]
Role = Literal["orchestrator", "surface", "exploit", "postex", "analyst", "researcher"]

HIGH = ["anthropic:claude-opus-4-8", "openai:gpt-5", "google_genai:gemini-3-pro"]
MID = ["anthropic:claude-sonnet-4-6", "openai:gpt-5-mini", "google_genai:gemini-flash"]
LOW = ["anthropic:claude-haiku-4-5", "openai:gpt-5-nano", "ollama:qwen3:32b"]


class ModelChoice(TypedDict):
    """Tier configuration. `model` is the first-choice provider:model string;
    `fallbacks` are tried in order if the first fails (currently informational —
    actual fallback routing happens at the LiteLLM-proxy layer if configured)."""

    model: str
    fallbacks: list[str]


def _chain(tier: list[str]) -> ModelChoice:
    return {"model": tier[0], "fallbacks": tier[1:]}


MODEL_FOR_PROFILE: dict[Profile, dict[Role, ModelChoice]] = {
    # eco never uses LOW (Haiku): it's too weak for the reasoning these roles do
    # (postex privesc triage especially). eco saves vs `max` by running the
    # non-critical roles on MID (Sonnet), not by dropping to LOW. The floor is
    # MID; the critical roles (orchestrator/exploit) stay HIGH (Opus).
    "eco": {
        "orchestrator": _chain(HIGH),
        "surface": _chain(MID),
        "exploit": _chain(HIGH),  # never demote — silent failure on hard boxes
        "postex": _chain(MID),    # was LOW; Haiku botched privesc triage
        "analyst": _chain(MID),   # one-shot report, not in the hot loop — Sonnet is fine
        "researcher": _chain(MID), # deep reads are expensive; escalate via profile=max when needed
    },
    "max": {
        "orchestrator": _chain(HIGH),
        "surface": _chain(HIGH),
        "exploit": _chain(HIGH),
        "postex": _chain(HIGH),
        "analyst": _chain(HIGH),
        "researcher": _chain(HIGH),
    },
    "test": {
        "orchestrator": _chain(LOW),
        "surface": _chain(LOW),
        "exploit": _chain(LOW),
        "postex": _chain(LOW),
        "analyst": _chain(LOW),
        "researcher": _chain(LOW),
    },
}


def model_for(profile: Profile, role: Role) -> ModelChoice:
    """Return the ModelChoice (identifier + fallback list) for a (profile, role)
    pair. Subagent specs pass `model_arg_for(...)` to deepagents.

    Raises a clear ValueError on an unknown profile — otherwise a typo
    (`fabel`) surfaces as a cryptic KeyError deep inside a subagent spec."""
    if profile not in MODEL_FOR_PROFILE:
        valid = ", ".join(MODEL_FOR_PROFILE)
        raise ValueError(f"unknown profile {profile!r} (valid profiles: {valid})")
    return MODEL_FOR_PROFILE[profile][role]


# Roles that get extended thinking when VOIDSTRIKE_THINKING_EFFORT is set.
# These are the reasoning-heavy hot-loop subagents whose reflexive
# act-act-act loops cause the expensive retry detours (a debug.jsonl run
# showed 0 thinking tokens and prose on only 6/183 turns — the model was
# pattern-matching the next command instead of diagnosing the last result).
# Extended thinking forces deliberation between actions. Default off, so an
# unset env reproduces today's behavior exactly — set the env to A/B.
_THINKING_ROLES: frozenset[Role] = frozenset({"exploit", "postex"})

# Adaptive-thinking effort levels (Opus 4.7/4.8 surface). Opus accepts all of
# these; Sonnet 4.6 only the first three (xhigh/max are Opus-tier). Haiku has no
# effort/adaptive support, so we leave it as a plain string. `budget_tokens` and
# the `{type:"enabled"}` thinking form are *removed* on Opus 4.8 (they 400), as
# are `temperature`/`top_p`/`top_k` — see the claude-api skill.
_OPUS_EFFORTS = ("low", "medium", "high", "xhigh", "max")
_SONNET_EFFORTS = ("low", "medium", "high")


def _thinking_effort() -> str:
    """Requested adaptive-thinking effort from env; '' when unset/off/invalid
    (thinking disabled)."""
    val = os.environ.get("VOIDSTRIKE_THINKING_EFFORT", "").strip().lower()
    return val if val in _OPUS_EFFORTS else ""


def model_arg_for(profile: Profile, role: Role) -> str | BaseChatModel:
    """Model value to hand a subagent spec's `model` field.

    Default: the `provider:model` string (deepagents resolves it and applies
    the harness profile + prompt caching). When `VOIDSTRIKE_THINKING_EFFORT` is
    a valid effort level and `role` is reasoning-heavy (`_THINKING_ROLES`),
    return an adaptive-thinking Anthropic *instance* instead. See the module
    docstring for why an instance is safe for a subagent but not the
    orchestrator.

    Adaptive thinking (`thinking={"type":"adaptive"}` + `output_config.effort`)
    is the Opus 4.7/4.8 surface — the older `budget_tokens` form 400s there.
    Effort is clamped to what the model tier supports; non-Anthropic / Haiku
    tiers fall back to the plain string.
    """
    model_id = model_for(profile, role)["model"]
    effort = _thinking_effort()
    if not effort or role not in _THINKING_ROLES:
        return model_id
    if "opus-4" in model_id:
        allowed = _OPUS_EFFORTS
    elif "sonnet-4-6" in model_id:
        allowed = _SONNET_EFFORTS
    else:
        # Haiku / non-Anthropic tier — no adaptive-thinking support; leave as a
        # plain string so deepagents resolves it normally.
        return model_id
    eff = effort if effort in allowed else "high"
    from langchain.chat_models import init_chat_model
    return init_chat_model(
        model_id,
        # `display: "summarized"` populates the thinking-block text (omitted by
        # default on Opus 4.7/4.8) so the CLI can render the model's reasoning.
        thinking={"type": "adaptive", "display": "summarized"},
        output_config={"effort": eff},
        # Adaptive thinking tokens count toward the output cap; the ChatAnthropic
        # default (1024) is too low once the model also emits tool-call args.
        # Stay under the SDK's ~16k non-streaming guard.
        max_tokens=8192,
    )


def tool_response_format(schema):
    """Wrap a Pydantic schema in `ToolStrategy(...)` so the subagent must
    *call* the structured-response tool at the end of its loop.

    Without this, a bare schema like `response_format=SurfaceFindings`
    defaults to `ProviderStrategy` for Anthropic/OpenAI (native structured
    output), which lets the model satisfy the schema on its very first turn
    *before* running any real tools — subagents end up returning empty
    placeholders like `{"services": [], "web": [], "summary": "Starting recon..."}`
    without ever calling nmap.

    Lazy import keeps the rest of the codebase testable without langchain.
    """
    from langchain.agents.structured_output import ToolStrategy  # noqa: PLC0415
    return ToolStrategy(schema)
