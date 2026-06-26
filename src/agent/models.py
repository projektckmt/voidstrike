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

The exceptions all flow through `spec_model(...)` / `model_arg_for(...)`, which
may return a `BaseChatModel` *instance* instead of a string:

1. Adaptive thinking — a thinking-enabled instance for a reasoning-heavy subagent
   (exploit/postex) when `VOIDSTRIKE_THINKING_EFFORT` is set. Safe for subagents:
   deepagents appends `AnthropicPromptCachingMiddleware` to every subagent
   unconditionally (caching preserved), and subagent fs-tool exclusion comes from
   the `block_fs_tools` middleware in `main.py`, not the harness profile.
2. OpenRouter (direct) — a `ChatOpenAI` instance pointed at OpenRouter (see
   `_resolve_openrouter`), for the `qwen` profile when the proxy is disabled.
3. LiteLLM proxy — **on by default** (unset = enabled; `VOIDSTRIKE_USE_LITELLM=
   false` opts out). A `ChatOpenAI` instance pointed at the proxy (see
   `_resolve_litellm`) for provider fallback / caching / budget. This takes
   precedence over (1) and (2): *all* models route through the proxy,
   openrouter/qwen included (the proxy config disables Qwen thinking). Reasoning
   still works over the proxy: `model_arg_for` attaches reasoning per provider
   for the thinking roles (exploit/postex) — OpenAI a `reasoning_effort`,
   Anthropic the adaptive `thinking` form (see `_proxy_reasoning_kwargs`) — Qwen
   excepted. Anthropic reasoning needs ANTHROPIC_API_KEY set so the proxy routes
   Claude native (OpenRouter doesn't forward the adaptive form).
   Applies to the orchestrator too: it forfeits the harness profile's
   *schema* trimming and Anthropic prompt caching, but fs tools are still removed
   from the ToolNode in `main.py` and the grammar crash is handled by tool-name
   prefixing — so it's a cost trade-off, not a correctness one.
4. OpenRouter key-fallback — when a model's *native* provider key is missing but
   `OPENROUTER_API_KEY` is set, that model is served via OpenRouter (see
   `_openrouter_fallback`), so an OpenRouter-only setup can still run the
   Anthropic/OpenAI/Google profiles. Self-gating on the absent native key; the
   proxy path (3) takes precedence when enabled.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any, Literal, TypedDict

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

log = logging.getLogger("voidstrike.models")

Profile = Literal["eco", "max", "test", "qwen", "gpt"]
Role = Literal["orchestrator", "surface", "exploit", "postex", "analyst", "researcher"]

HIGH = ["anthropic:claude-opus-4-8", "openai:gpt-5.5", "google_genai:gemini-3-pro"]
MID = ["anthropic:claude-sonnet-4-6", "openai:gpt-5.4-mini", "google_genai:gemini-flash"]
LOW = ["anthropic:claude-haiku-4-5", "openai:gpt-5.4-nano", "ollama:qwen3:32b"]

# OpenRouter tier. The `openrouter:` prefix is OUR internal identifier — we do
# NOT let deepagents/init_chat_model resolve it (see `_resolve_openrouter` for
# why the langchain-openrouter SDK path can't disable Qwen's thinking mode, which
# breaks forced-tool-choice structured output). `spec_model`/`model_arg_for`
# convert these strings into a configured `ChatOpenAI` instance before they reach
# deepagents. No HarnessProfile is registered for openrouter (see profile.py), so
# the orchestrator's fs tools aren't hidden from its surface here — same as the
# existing non-Anthropic `test` tier. Treat qwen as a cheap/experimental lane.
QWEN = ["openrouter:qwen/qwen3.7-max"]

# Single-model GPT tier — every role on gpt-5.5. Resolves like any other
# `openai:` model: through the LiteLLM proxy when enabled, else the native OpenAI
# SDK, else the OpenRouter key-fallback if OPENAI_API_KEY is absent. The thinking
# roles (exploit/postex) get reasoning regardless of which of those routes serves
# the model — see `model_arg_for` / `_proxy_reasoning_effort`.
GPT = ["openai:gpt-5.5"]

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Provider prefix → the env var holding that provider's *native* API key. Used by
# the OpenRouter key-fallback (see `_openrouter_fallback`). Providers absent here
# (ollama=local, openrouter=itself) never fall back.
_NATIVE_KEY_ENV = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "google_genai": "GOOGLE_API_KEY",
}

# Our internal `provider:model` id → the equivalent OpenRouter model slug, for
# the key-fallback path. OpenRouter slugs are NOT a mechanical transform of our
# ids (`-8`→`.8`, provider renames, and Google has no exact `gemini-3-pro`), so
# they're explicit. Verified against the OpenRouter catalogue 2026-06; update if
# slugs drift (a stale slug just disables fallback for that one model with a log
# warning — it won't break native-key routing).
_OPENROUTER_EQUIVALENT = {
    "anthropic:claude-opus-4-8": "anthropic/claude-opus-4.8",
    "anthropic:claude-sonnet-4-6": "anthropic/claude-sonnet-4.6",
    "anthropic:claude-haiku-4-5": "anthropic/claude-haiku-4.5",
    "openai:gpt-5.5": "openai/gpt-5.5",
    "openai:gpt-5.4-mini": "openai/gpt-5.4-mini",
    "openai:gpt-5.4-nano": "openai/gpt-5.4-nano",
    # Google has no plain text `gemini-3-pro` on OpenRouter — closest is the 3.1
    # pro preview; flash maps to the current stable flash.
    "google_genai:gemini-3-pro": "google/gemini-3.1-pro-preview",
    "google_genai:gemini-flash": "google/gemini-2.5-flash",
}

# Default address of the in-cluster LiteLLM proxy (matches docker-compose). The
# runtime only routes through it when VOIDSTRIKE_USE_LITELLM is truthy.
DEFAULT_LITELLM_PROXY_URL = "http://litellm:4000"

# Our internal `provider:model` identifier → the LiteLLM proxy's `model_name`
# (the keys in infra/litellm-config.yaml). Most just swap the first `:` for `/`;
# these three don't (provider rename / tag punctuation), so they're explicit.
_LITELLM_NAME_OVERRIDES = {
    "google_genai:gemini-3-pro": "google/gemini-3-pro",
    "google_genai:gemini-flash": "google/gemini-flash",
    "ollama:qwen3:32b": "ollama/qwen3-32b",
}


class ModelChoice(TypedDict):
    """Tier configuration. `model` is the first-choice provider:model string;
    `fallbacks` are tried in order if the first fails. The `fallbacks` list here
    is informational (documents intent); the *active* fallback routing happens at
    the LiteLLM-proxy layer (infra/litellm-config.yaml `router_settings`) when
    VOIDSTRIKE_USE_LITELLM is enabled — see `_resolve_litellm`."""

    model: str
    fallbacks: list[str]


def _has_key(var: str) -> bool:
    """True if env var `var` holds a real-looking API key — set, non-empty, and
    not a `.env.example` placeholder. The example convention is a trailing `...`
    (`sk-ant-...`, `sk-...`, `...`), so we treat those as absent. This is what
    makes "leave the placeholders, set only OPENROUTER_API_KEY" engage the
    OpenRouter fallback instead of 401-ing on a fake native key."""
    val = os.environ.get(var, "").strip()
    return bool(val) and not val.endswith("...")


def _chain(tier: list[str]) -> ModelChoice:
    return {"model": tier[0], "fallbacks": tier[1:]}


def _resolve_openrouter(model_id: str) -> BaseChatModel | None:
    """Build a chat model for an `openrouter:<model>` id, or None if `model_id`
    isn't an OpenRouter model.

    We deliberately bypass deepagents' `init_chat_model("openrouter:...")` path
    (the `langchain-openrouter` / `openrouter` SDK). That SDK's reasoning config
    models only `effort`/`summary` and silently drops `enabled`, so there is no
    way to turn thinking mode *off* through it. Qwen3.x runs in thinking mode by
    default, and Alibaba's upstream rejects a forced `tool_choice`
    (`required`/named) while thinking — which is exactly what our structured-
    output ToolStrategy (`tool_response_format`) sends. Result: a hard 400
    ("tool_choice ... does not support being set to required or object in
    thinking mode") on every subagent that returns a structured response.

    OpenRouter is OpenAI-compatible, so we reach it via `ChatOpenAI` against
    OpenRouter's base URL. The openai client forwards `extra_body` verbatim, so
    `{"reasoning": {"enabled": False}}` actually arrives and disables thinking —
    making forced tool_choice (and thus structured output) work.
    """
    if not model_id.startswith("openrouter:"):
        return None
    name = model_id.split(":", 1)[1]
    if not _has_key("OPENROUTER_API_KEY"):
        raise RuntimeError(
            f"OPENROUTER_API_KEY is not set (or still the .env.example placeholder) "
            f"— required for openrouter models like {model_id!r} (see .env.example)."
        )
    api_key = os.environ["OPENROUTER_API_KEY"]
    from langchain_openai import ChatOpenAI  # noqa: PLC0415
    return ChatOpenAI(
        model=name,
        base_url=OPENROUTER_BASE_URL,
        api_key=api_key,
        # Disable Qwen's default thinking mode — incompatible with the forced
        # tool_choice our structured output relies on. See above.
        extra_body={"reasoning": {"enabled": False}},
    )


def _openrouter_fallback(model_id: str) -> BaseChatModel | None:
    """Serve an Anthropic/OpenAI/Google model via OpenRouter when its *native*
    provider key is missing but `OPENROUTER_API_KEY` is set; else None.

    OpenRouter's unified API hosts all three providers, so a user who only has an
    OpenRouter key can still run the `eco`/`max`/`test` profiles — the model
    transparently routes through OpenRouter instead of failing on a missing
    native key. Self-gating: only fires when the native key is absent, so adding
    a native key later silently reverts to the direct SDK (which keeps Anthropic
    prompt caching etc.). Unlike Qwen, these models don't need thinking disabled
    (verified: forced tool_choice works), so no `extra_body`.
    """
    provider = model_id.split(":", 1)[0]
    key_env = _NATIVE_KEY_ENV.get(provider)
    if key_env is None:
        return None  # ollama (local) / openrouter (handled elsewhere) — no fallback
    if _has_key(key_env):
        return None  # native key present — use the direct provider SDK
    if not _has_key("OPENROUTER_API_KEY"):
        return None  # nothing to fall back to
    or_key = os.environ["OPENROUTER_API_KEY"]
    slug = _OPENROUTER_EQUIVALENT.get(model_id)
    if slug is None:
        log.warning(
            "%s has no native key (%s unset) and no OpenRouter equivalent mapped — "
            "leaving as-is (will fail unless a key is set)", model_id, key_env,
        )
        return None
    log.info("%s: %s unset → routing via OpenRouter as %s", model_id, key_env, slug)
    from langchain_openai import ChatOpenAI  # noqa: PLC0415
    return ChatOpenAI(model=slug, base_url=OPENROUTER_BASE_URL, api_key=or_key)


def _litellm_enabled() -> bool:
    """Whether to route model calls through the in-cluster LiteLLM proxy.

    **On by default** — unset means enabled. Only an explicit falsy value
    (`0`/`false`/`no`/`off`) opts out (back to direct provider SDKs). The proxy
    gives provider fallback (HIGH→OpenAI→Google etc., see
    infra/litellm-config.yaml `router_settings`), a Redis response cache,
    spend/budget tracking, and Langfuse observability.

    Anthropic prompt caching still works on the proxy path: deepagents'
    AnthropicPromptCachingMiddleware can't fire (it requires a ChatAnthropic
    instance; the proxy hands deepagents a ChatOpenAI), but LiteLLM injects the
    `cache_control` breakpoints itself when forwarding to an `anthropic/` route.
    Verified on a real Opus run: ~63% of input tokens were cache reads
    (`usage_metadata.input_token_details.cache_read`). NB the OpenAI-format usage
    LiteLLM returns has no cache-*creation* field, so `cache_creation` always
    reads 0 through the proxy even though caches are being written — don't read
    that as "caching off"; `cache_read` is the real signal.

    NB: requires a running proxy at LITELLM_PROXY_URL + LITELLM_MASTER_KEY; on a
    non-Docker local run with neither, set VOIDSTRIKE_USE_LITELLM=false."""
    val = os.environ.get("VOIDSTRIKE_USE_LITELLM", "").strip().lower()
    if val == "":
        return True  # on by default
    return val in {"1", "true", "yes", "on"}


def _litellm_model_name(model_id: str) -> str:
    """Map our internal `provider:model` id to the proxy's `model_name`."""
    if model_id in _LITELLM_NAME_OVERRIDES:
        return _LITELLM_NAME_OVERRIDES[model_id]
    return model_id.replace(":", "/", 1)


def _resolve_litellm(
    model_id: str, *, reasoning_kwargs: dict[str, Any] | None = None
) -> BaseChatModel | None:
    """Route `model_id` through the LiteLLM proxy as an OpenAI-compatible call,
    or None when the proxy is disabled.

    The proxy is OpenAI-compatible, so we use `ChatOpenAI` pointed at it; the
    `model_name` is the LiteLLM-side identifier (see `_litellm_model_name`). When
    enabled this also routes `openrouter:` models (the proxy config disables
    Qwen's thinking mode via extra_body) — so callers resolve litellm *before*
    the direct-openrouter fallback. Note: handing deepagents an
    instance here means the orchestrator won't get the Anthropic HarnessProfile's
    *schema* trimming of fs tools — but those tools are still removed from the
    ToolNode in main.py (`_strip_orchestrator_blocked_tools`), and the grammar-limit
    crash was already fixed by tool-name prefixing (see profile.py); so this is a
    token cost, not a correctness issue.

    `reasoning_kwargs` are extra `ChatOpenAI` kwargs that turn ON reasoning for the
    call — provider-specific, built by `_proxy_reasoning_kwargs` (OpenAI gets a
    `reasoning_effort`; Anthropic gets the adaptive `thinking` form via
    `extra_body`). The proxy forwards them to the model's real provider."""
    if not _litellm_enabled():
        return None
    api_key = os.environ.get("LITELLM_MASTER_KEY")
    if not api_key:
        raise RuntimeError(
            "VOIDSTRIKE_USE_LITELLM is set but LITELLM_MASTER_KEY is not — the "
            "proxy requires it for auth (see .env.example / infra/litellm-config.yaml)."
        )
    from langchain_openai import ChatOpenAI  # noqa: PLC0415
    return ChatOpenAI(
        model=_litellm_model_name(model_id),
        base_url=os.environ.get("LITELLM_PROXY_URL", DEFAULT_LITELLM_PROXY_URL),
        api_key=api_key,
        **(reasoning_kwargs or {}),
    )


def routing_summary() -> str:
    """One-line description of how model calls are routed right now — logged once
    at engagement start so the operator can confirm whether the LiteLLM proxy is
    in use. Mirrors the precedence in `spec_model`."""
    if _litellm_enabled():
        url = os.environ.get("LITELLM_PROXY_URL", DEFAULT_LITELLM_PROXY_URL)
        key = "set" if os.environ.get("LITELLM_MASTER_KEY") else "MISSING (calls will fail)"
        return (
            f"LiteLLM proxy ENABLED → {url} (master key: {key}); all models routed "
            f"through it (fallback/cache/budget active; LiteLLM injects Anthropic "
            f"prompt-cache breakpoints on anthropic/ routes — verified ~63% cache "
            f"reads on a real Opus run)"
        )
    msg = (
        "direct provider SDKs (LiteLLM proxy OFF via VOIDSTRIKE_USE_LITELLM=false; "
        "unset it to use the proxy, which is the default)"
    )
    if _has_key("OPENROUTER_API_KEY"):
        fellback = [
            prov for prov, env in _NATIVE_KEY_ENV.items() if not _has_key(env)
        ]
        if fellback:
            msg += (
                f"; OpenRouter key-fallback active for missing native keys: "
                f"{', '.join(sorted(fellback))}"
            )
    return msg


def spec_model(profile: Profile, role: Role) -> str | BaseChatModel:
    """Model value for subagent specs (and the orchestrator) that do NOT use
    extended thinking. Use in place of `model_for(...)["model"]` so an
    `openrouter:` string never reaches deepagents' resolver.

    Resolution order:
    - VOIDSTRIKE_USE_LITELLM set → everything (openrouter included) routes
      through the LiteLLM proxy (see `_resolve_litellm`).
    - else `openrouter:` models → a direct `ChatOpenAI` with thinking disabled
      (see `_resolve_openrouter`).
    - else if the model's native provider key is missing but OPENROUTER_API_KEY
      is set → route it via OpenRouter (see `_openrouter_fallback`).
    - else → the plain `provider:model` string deepagents resolves itself."""
    model_id = model_for(profile, role)["model"]
    return (
        _resolve_litellm(model_id)
        or _resolve_openrouter(model_id)
        or _openrouter_fallback(model_id)
        or model_id
    )


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
    # Every role on Qwen3.7-max via OpenRouter. A single-model profile (like
    # `test`) for running an engagement entirely off Anthropic — cost/eval lane.
    "qwen": {
        "orchestrator": _chain(QWEN),
        "surface": _chain(QWEN),
        "exploit": _chain(QWEN),
        "postex": _chain(QWEN),
        "analyst": _chain(QWEN),
        "researcher": _chain(QWEN),
    },
    # Every role on gpt-5.5. Single-model profile for running an engagement
    # entirely on OpenAI's gpt-5.5 — cost/eval lane (served native or via the
    # OpenRouter fallback, like any openai: model).
    "gpt": {
        "orchestrator": _chain(GPT),
        "surface": _chain(GPT),
        "exploit": _chain(GPT),
        "postex": _chain(GPT),
        "analyst": _chain(GPT),
        "researcher": _chain(GPT),
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
# these (xhigh/max are Opus-tier). `budget_tokens` and the `{type:"enabled"}`
# thinking form are *removed* on Opus 4.8 (they 400), as are
# `temperature`/`top_p`/`top_k` — see the claude-api skill.
_OPUS_EFFORTS = ("low", "medium", "high", "xhigh", "max")

# Our adaptive-thinking effort → LiteLLM's unified `reasoning_effort`
# (low|medium|high), which the proxy maps to each provider's native reasoning
# surface. Our scale runs to the Opus-only xhigh/max, so those clamp down to high.
_PROXY_REASONING_EFFORT = {
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",
    "max": "high",
}


def _proxy_reasoning_kwargs(model_id: str, role: Role) -> dict[str, Any]:
    """`ChatOpenAI` kwargs that turn ON reasoning for `(model_id, role)` over the
    proxy, or `{}` for none.

    Provider-specific, because the proxy forwards to each model's *real* provider
    and they don't share a reasoning surface — and, crucially, our agent binds
    `tool_choice="any"` on every turn (ToolStrategy structured output, see
    langchain `factory.py`), which thinking is often incompatible with:

    - **OpenAI gpt-5.x** → LiteLLM's unified `reasoning_effort` (low|medium|high).
      OpenAI reasoning models reason fine under a forced tool_choice. (Verified.)
    - **Anthropic Opus 4.7/4.8** → the *adaptive* thinking form via `extra_body`
      (`{thinking:{type:adaptive,...}, output_config:{effort}}`). Opus adaptive is
      the *only* Anthropic thinking that survives a forced tool_choice; it reaches
      Anthropic only **natively** — set ANTHROPIC_API_KEY so the bootstrap routes
      Claude native rather than via OpenRouter, which doesn't forward the adaptive
      form (verified: reasoning_tokens=0 there).
    - **Anthropic Sonnet/Haiku → nothing.** Verified against the native API: every
      thinking form (adaptive *and* classic) 400s under a forced tool_choice
      ("Thinking may not be enabled when tool_choice forces tool use") — only Opus
      adaptive is exempt. Through the proxy LiteLLM silently strips it (a no-op),
      so attaching it would just be misleading.
    - **Gemini / others** → unified `reasoning_effort`; `drop_params` strips it
      where unsupported.
    - **Qwen / ollama → nothing** (Qwen's thinking rejects forced tool_choice;
      ollama is local/no-reasoning)."""
    effort = _thinking_effort()
    if not effort or role not in _THINKING_ROLES:
        return {}
    if model_id.startswith(("openrouter:qwen/", "ollama:")):
        return {}
    if model_id.startswith("anthropic:"):
        if "opus-4" not in model_id:
            return {}  # Sonnet/Haiku: thinking ⊥ forced tool_choice (see above)
        eff = effort if effort in _OPUS_EFFORTS else "high"
        return {
            # Adaptive thinking tokens count toward the output cap; mirror the
            # native path's headroom (ChatAnthropic's 1024 default is too low once
            # tool-call args are also emitted). Stay under the SDK's ~16k guard.
            "max_tokens": 8192,
            "extra_body": {
                # `display: summarized` populates the thinking-block text so the
                # CLI can render the model's reasoning (omitted by default on 4.8).
                "thinking": {"type": "adaptive", "display": "summarized"},
                "output_config": {"effort": eff},
            },
        }
    # OpenAI / Gemini / other reasoning-capable models — unified effort knob.
    return {"reasoning_effort": _PROXY_REASONING_EFFORT.get(effort, "high")}


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
    # Proxy routing wins when enabled — it takes everything (openrouter included).
    # The deepagents `init_chat_model` adaptive path below (ChatAnthropic) is
    # bypassed, but reasoning still happens over the proxy, attached per provider
    # for the thinking roles: OpenAI gets a reasoning_effort, Anthropic the
    # adaptive thinking form (see `_proxy_reasoning_kwargs`).
    if _litellm_enabled():
        rk = _proxy_reasoning_kwargs(model_id, role)
        return _resolve_litellm(model_id, reasoning_kwargs=rk)
    # OpenRouter (direct) — ChatOpenAI w/ thinking disabled; deepagents can't
    # resolve it, and adaptive thinking below is Anthropic-only anyway.
    if (resolved := _resolve_openrouter(model_id)) is not None:
        return resolved
    # Native key missing but OpenRouter key present → route via OpenRouter. This
    # also forfeits Anthropic-native adaptive thinking (no native key to use it),
    # so it correctly short-circuits the thinking logic below.
    if (resolved := _openrouter_fallback(model_id)) is not None:
        return resolved
    effort = _thinking_effort()
    if not effort or role not in _THINKING_ROLES:
        return model_id
    if "opus-4" not in model_id:
        # Adaptive thinking only on Opus 4.7/4.8. Sonnet 4.6 / Haiku 400 on
        # thinking under the agent's forced tool_choice ("Thinking may not be
        # enabled when tool_choice forces tool use"; verified against the native
        # API), and non-Anthropic tiers have no adaptive surface — leave a plain
        # string so deepagents resolves it normally.
        return model_id
    eff = effort if effort in _OPUS_EFFORTS else "high"
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
