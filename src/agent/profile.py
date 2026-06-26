"""Harness profile registration for deepagents.

Anthropic's tool-use API compiles every bound tool into a grammar, and bare
function-name tools from older `langchain-mcp-adapters` versions plus
deepagents' six filesystem tools (`ls`, `read_file`, `write_file`,
`edit_file`, `glob`, `grep`) blow past Anthropic's compile-time limit.

The grammar fix is the *tool-name prefixing* shim in `main.py` (each MCP
tool gets `<server>__<name>` at load time). The harness profile here is
about a *separate* concern: hiding the six heavy filesystem tools from the
model surface so the prompt + tool schemas remain compact (token savings
+ smaller grammar).

We KEEP `AnthropicPromptCachingMiddleware` in place. An earlier round of
this code excluded it because we mistakenly attributed strict-tool binding
to it — the actual cause was the tool-name issue, and excluding the
middleware just disabled prompt caching for no gain. Prompt caching is
high-leverage: with a stable system prompt + tools, second and subsequent
calls within ~5 minutes cost ~10% of the input price (huge on Opus runs).

NB this middleware only fires on the *direct* path (ChatAnthropic instance —
`VOIDSTRIKE_USE_LITELLM=false`). On the default proxy path the model is a
ChatOpenAI, so it no-ops and LiteLLM injects the cache breakpoints instead
(see models._litellm_enabled). Caching works either way.

Per the LangChain docs (https://docs.langchain.com/oss/python/deepagents/harness):

    >>> from deepagents import HarnessProfile, register_harness_profile
    >>> register_harness_profile(
    ...     "anthropic:claude-sonnet-4-6",
    ...     HarnessProfile(
    ...         excluded_tools=frozenset(
    ...             {"ls", "read_file", "write_file", "edit_file", "glob", "grep"}
    ...         ),
    ...     ),
    ... )

`excluded_tools` hides the heavy filesystem tools from the model surface
(the FilesystemMiddleware stays in place for skill loading etc.).

This module also disables deepagents' auto-added `general-purpose` subagent on
every model (via `GeneralPurposeSubagentProfile(enabled=False)`): it has only
the vfs + episode tools, so it cannot run target tooling and just flails when
the orchestrator delegates real work to it. Our own role subagents still expose
`task`.

This module is import-side-effecting: `register()` is called once per process
when `build_agent` first runs. Re-registration is idempotent.
"""

from __future__ import annotations

import logging

log = logging.getLogger("voidstrike.profile")

# Heavy fs tools — schema bulk is mostly here. Hiding them from the model
# surface (the middleware remains; skills/memory still work).
#
# NB: `read_file` is intentionally NOT excluded. deepagents' skills use
# progressive disclosure — the model loads a SKILL.md body on demand via
# `read_file(path)` (see SkillsMiddleware). Excluding it would let the agent
# see the skill list but never read any skill's instructions. The filesystem
# backend (see build_agent) is sandboxed to the project root via
# `virtual_mode=True`, so read_file only ever reaches skills + scratchpad.
_EXCLUDED_FS_TOOLS = frozenset({
    "ls", "write_file", "edit_file", "glob", "grep",
})

_REGISTERED = False


def register() -> None:
    """Register the anthropic harness profile. Idempotent."""
    global _REGISTERED
    if _REGISTERED:
        return

    try:
        from deepagents import (  # type: ignore[import-untyped]
            GeneralPurposeSubagentProfile,
            HarnessProfile,
            register_harness_profile,
        )
    except ImportError as exc:
        log.warning("deepagents HarnessProfile API unavailable (%s) — skipping", exc)
        return

    # NB: previously this code also excluded `AnthropicPromptCachingMiddleware`
    # on a wrong theory that it forced strict-tool binding. The grammar limit
    # was actually about tool-name prefixing (fixed in `_load_prefixed_mcp_tools`).
    # We leave the middleware in place because prompt caching cuts cached input
    # cost by ~90% — material on Opus runs.

    # Disable deepagents' auto-added `general-purpose` subagent on EVERY model.
    # It only has the filesystem + episode/lab-tracking tools — no shell exec —
    # so when the orchestrator delegates a real recon/ACL task to it (which it
    # does), it can't run any target tooling and just flails reading the vfs.
    # Our own role subagents (surface/exploit/postex/...) still expose `task`;
    # this removes only the useless general-purpose option.
    no_general_purpose = GeneralPurposeSubagentProfile(enabled=False)

    # Anthropic models: keep `excluded_tools` (Anthropic grammar limit + token
    # savings) AND disable general-purpose.
    anthropic_profile = HarnessProfile(
        excluded_tools=_EXCLUDED_FS_TOOLS,
        general_purpose_subagent=no_general_purpose,
    )
    anthropic_keys = [
        "anthropic",
        "anthropic:claude-opus-4-8",
        "anthropic:claude-sonnet-4-6",
        "anthropic:claude-haiku-4-5",
    ]
    for key in anthropic_keys:
        register_harness_profile(key, anthropic_profile)

    # Non-anthropic models (gpt-5.5, qwen, ...) resolve to `ChatOpenAI`
    # instances that report `ls_provider="openai"`, so the provider-only
    # fallback in deepagents' `_harness_profile_for_model` picks this up. We
    # only disable general-purpose here — no `excluded_tools`, to leave those
    # models' tool surface exactly as it was.
    register_harness_profile(
        "openai",
        HarnessProfile(general_purpose_subagent=no_general_purpose),
    )

    log.info(
        "registered harness profiles: anthropic (%d keys, excluded_tools=%d) + "
        "openai provider; general-purpose subagent disabled on all; "
        "prompt-caching kept enabled",
        len(anthropic_keys),
        len(_EXCLUDED_FS_TOOLS),
    )
    _REGISTERED = True
