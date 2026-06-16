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
        from deepagents import HarnessProfile, register_harness_profile  # type: ignore[import-untyped]
    except ImportError as exc:
        log.warning("deepagents HarnessProfile API unavailable (%s) — skipping", exc)
        return

    # NB: previously this code also excluded `AnthropicPromptCachingMiddleware`
    # on a wrong theory that it forced strict-tool binding. The grammar limit
    # was actually about tool-name prefixing (fixed in `_load_prefixed_mcp_tools`).
    # We leave the middleware in place because prompt caching cuts cached input
    # cost by ~90% — material on Opus runs.

    profile_kwargs: dict = {"excluded_tools": _EXCLUDED_FS_TOOLS}

    # Register under both the provider key and every specific model we ship
    # in models.py. Provider-level should be enough, but per-model keys are
    # belt-and-suspenders against version drift in deepagents' lookup.
    keys = [
        "anthropic",
        "anthropic:claude-opus-4-8",
        "anthropic:claude-sonnet-4-6",
        "anthropic:claude-haiku-4-5",
    ]
    for key in keys:
        register_harness_profile(key, HarnessProfile(**profile_kwargs))

    log.info(
        "registered anthropic harness profile under %d keys (excluded_tools=%d, "
        "prompt-caching kept enabled)",
        len(keys),
        len(_EXCLUDED_FS_TOOLS),
    )
    _REGISTERED = True
