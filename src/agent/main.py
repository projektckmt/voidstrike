"""Main agent assembly."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from langchain_mcp_adapters.client import MultiServerMCPClient

from ..schemas.engagement import EngagementSpec
from .middleware import (
    action_class_gate,
    block_fs_tools,
    browse_budget,
    budget_guard,
    command_logger,
    curl_budget,
    flag_completion_gate,
    fuzz_guard,
    http_stall_guard,
    idle_read_guard,
    model_retry,
    no_progress_guard,
    repeat_guard,
    require_episode_log,
    require_structured_response,
    research_budget,
    roe_gate,
    serialize_tasks,
    step_budget,
    stuck_detector,
    suggest_unknown_tool,
    tool_error_guard,
    vhost_guard,
)
from .middleware.require_episode_log import structured_tool_name
from .modes import resolve_mode
from .subagents import (
    ad_spec,
    analyst_spec,
    exploit_spec,
    postex_spec,
    researcher_spec,
    surface_spec,
)
from .tools import ANALYST_TOOLS, ORCHESTRATOR_TOOLS

log = logging.getLogger("voidstrike.agent")

PG_URL = os.environ.get(
    "POSTGRES_URL",
    "postgresql://voidstrike:changeme@postgres:5432/voidstrike",
)

# Offensive scan tools (nuclei all-severity, nmap_full, long ffuf) legitimately
# run for many minutes. The MCP streamable-http transport's default
# `sse_read_timeout` is 5 min, which would sever a long tool call mid-scan and
# orphan the process. Raise the idle-gap ceiling so a blocking scan can run to
# completion; the tool itself decides whether to bound its own runtime.
_MCP_SSE_READ_TIMEOUT = timedelta(seconds=3600)
_MCP_REQUEST_TIMEOUT = timedelta(seconds=60)


def _mcp_url(service: str) -> str:
    """Return the MCP HTTP URL for a service, honouring overrides for local dev."""
    override = os.environ.get(f"MCP_{service.upper()}_URL")
    if override:
        return override
    return f"http://{service}-mcp:8080/mcp"


async def _build_mcp_config() -> dict[str, dict[str, str]]:
    """Build the MCP server config, probing each URL first and skipping any
    that don't respond. Without this, a single unreachable server (typo'd
    env var, container that didn't start, opt-in profile not enabled) crashes
    the whole engagement startup at `get_tools()` time.

    We probe at the TCP level (just a connect + close). An HTTP probe against
    a `streamable-http` MCP endpoint can hang waiting for an SSE event, which
    would yield false negatives.
    """
    import asyncio  # noqa: PLC0415
    from urllib.parse import urlparse  # noqa: PLC0415

    candidates = {
        "surface": _mcp_url("surface"),
        "exploit": _mcp_url("exploit"),
        "postex": _mcp_url("postex"),
        "browser": _mcp_url("browser"),
        "shell": _mcp_url("shell"),
        "episodes": _mcp_url("episodes"),
        "research": _mcp_url("research"),
    }
    if os.environ.get("MCP_AD_URL"):
        candidates["ad"] = _mcp_url("ad")

    async def _probe(name: str, url: str) -> tuple[str, str | None]:
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not host:
            log.warning("MCP server %s has unparseable URL %s — skipping", name, url)
            return name, None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return name, url
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "MCP server %s at %s://%s:%s unreachable (%s: %s) — skipping",
                name, parsed.scheme, host, port, type(exc).__name__, exc,
            )
            return name, None

    results = await asyncio.gather(*[_probe(n, u) for n, u in candidates.items()])
    config: dict[str, dict[str, Any]] = {}
    for name, url in results:
        if url is not None:
            config[name] = {
                "transport": "streamable_http",
                "url": url,
                # Don't let the transport cut off a long-running scan tool call.
                "sse_read_timeout": _MCP_SSE_READ_TIMEOUT,
                "timeout": _MCP_REQUEST_TIMEOUT,
            }
    return config


async def _load_prefixed_mcp_tools(mcp: MultiServerMCPClient,
                                    mcp_config: dict[str, dict[str, Any]]):
    """Load tools from every configured MCP server and rename each so its
    `name` is `<server>__<original_name>`.

    The `langchain-mcp-adapters` version installed here returns tools with
    only their bare function name (no per-server prefix). Our subagent
    allowlists, action_class table, and `required_tools` sets all expect the
    `<server>__<tool>` convention. Rather than changing every site to bare
    names (which loses provenance and risks collisions), we add the prefix
    once at load time.

    Falls back to whatever `get_tools()` returns if the per-server API
    isn't available in this adapter version.
    """
    # Try the per-server API. Newer langchain-mcp-adapters expose
    # `get_tools(server_name=...)` which returns just that server's tools.
    all_tools: list[Any] = []
    for server_name in mcp_config.keys():
        try:
            server_tools = await mcp.get_tools(server_name=server_name)
        except TypeError:
            # Older API: only `get_tools()` with no args. Fall through.
            log.warning(
                "MultiServerMCPClient.get_tools(server_name=...) not supported "
                "in this langchain-mcp-adapters version; loading flat and "
                "skipping prefix (tools won't be `<server>__<tool>` form)."
            )
            return await mcp.get_tools()
        except Exception as exc:  # noqa: BLE001
            log.warning("get_tools(server_name=%r) failed: %s", server_name, exc)
            continue

        for tool in server_tools:
            original = tool.name
            new_name = f"{server_name}__{original}"
            # langchain BaseTool's `name` is a Pydantic field but assignable.
            try:
                tool.name = new_name
            except Exception:  # noqa: BLE001
                # If the tool is frozen, copy with the new name.
                try:
                    tool = tool.model_copy(update={"name": new_name})
                except Exception:
                    log.warning("could not rename tool %r → %r", original, new_name)
                    continue
            all_tools.append(tool)

    return all_tools


def _mcp_client_sync() -> MultiServerMCPClient:
    """Sync-only client (no probing). Used by tests / introspection."""
    config = {
        "surface": {"transport": "streamable_http", "url": _mcp_url("surface")},
        "exploit": {"transport": "streamable_http", "url": _mcp_url("exploit")},
        "postex": {"transport": "streamable_http", "url": _mcp_url("postex")},
        "browser": {"transport": "streamable_http", "url": _mcp_url("browser")},
        "shell": {"transport": "streamable_http", "url": _mcp_url("shell")},
        "episodes": {"transport": "streamable_http", "url": _mcp_url("episodes")},
    }
    if os.environ.get("MCP_AD_URL"):
        config["ad"] = {"transport": "streamable_http", "url": _mcp_url("ad")}
    return MultiServerMCPClient(config)


@asynccontextmanager
async def build_agent(
    spec_path: str | Path,
    profile: str | None = None,
    engagement_id: str | None = None,
) -> AsyncIterator[Any]:
    """Materialize the agent graph for one engagement.

    `engagement_id` is the run's LangGraph `thread_id`; when provided, the
    offensive subagents carry a `command_logger` that records each target-facing
    tool call (verbatim command + output) to the episode log, so the analyst's
    methodology section is a real command-and-output writeup.

    Yields the compiled agent. Wrapped in a context manager because the
    Postgres checkpointer is itself a context manager — entering it sets up
    the connection pool and ensures the checkpoint tables exist; exiting it
    releases the pool.

    Usage:
        async with build_agent(spec_path) as agent:
            async for event in agent.astream(...):
                ...
    """
    # Lazy imports so this module loads in environments without the full deps.
    from deepagents import create_deep_agent  # type: ignore[import-untyped]
    from deepagents.backends import FilesystemBackend  # type: ignore[import-untyped]
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

    # Register the anthropic harness profile that excludes heavy filesystem
    # tools + the prompt-caching middleware. Without this, Anthropic's tool
    # grammar compiler trips on our subagent tool surfaces and every model
    # call fails with "compiled grammar is too large".
    from .profile import register as register_harness_profile
    register_harness_profile()

    spec = EngagementSpec.from_yaml(spec_path)
    if profile:
        spec.profile = profile

    mode = resolve_mode(spec)
    log.info("engagement mode=%s profile=%s targets=%s", spec.mode, spec.profile, spec.targets)

    mcp_config = await _build_mcp_config()
    if not mcp_config:
        raise RuntimeError(
            "No MCP servers reachable. Check `docker compose ps` and the per-server "
            "logs (`docker compose logs surface-mcp exploit-mcp shell-mcp ...`)."
        )
    log.info("MCP client config: %d server(s) reachable: %s", len(mcp_config), sorted(mcp_config))
    mcp = MultiServerMCPClient(mcp_config)
    tools = await _load_prefixed_mcp_tools(mcp, mcp_config)
    tool_names = sorted({t.name for t in tools})
    log.info("loaded %d MCP tools: %s", len(tools), tool_names)
    if not tools:
        raise RuntimeError(
            "Reached MCP servers but they returned zero tools. "
            "One or more servers likely crashed on startup — check their logs."
        )

    # Orchestrator carries ONLY in-process lab-state tools. Everything
    # offensive is delegated via the `task` tool deepagents injects
    # automatically. Keeping this list short is what avoids Anthropic's
    # "compiled grammar is too large" failure during planning — even a few
    # MCP tools combined with deepagents' built-ins push past the limit.
    orchestrator_tools = list(ORCHESTRATOR_TOOLS)
    analyst_tools = [
        t for t in tools
        if t.name in {"episodes__list_findings", "episodes__read_engagement"}
    ] + ANALYST_TOOLS

    # NOTE: `KaliSandboxBackend` is for managing the *Kali container lifecycle*
    # (VPN tunnel up, ops-net joined). The `backend=` kwarg on create_deep_agent
    # is something different — deepagents' *virtual filesystem* for skill loading
    # and the agent scratchpad.
    #
    # We pass an explicit FilesystemBackend rooted at the project dir. deepagents'
    # default is an in-memory StateBackend, which is EMPTY unless files are passed
    # on invoke — so skills (which load from the backend) never appear and the
    # progressive-disclosure read_file path returns nothing. The filesystem
    # backend reads the real `skills/` tree. `virtual_mode=True` sandboxes all
    # vfs paths under the project root (no absolute/`..` escape to the gateway
    # host), so read_file/skills only ever touch the project tree.
    fs_backend = FilesystemBackend(root_dir=os.getcwd(), virtual_mode=True)

    # Surface guards are stateful and must be attached to whichever agent loop
    # actually calls the surface tools — that's the surface subagent's own loop,
    # not the orchestrator. Orchestrator-level middleware doesn't intercept tool
    # calls made inside subagent runtimes.
    fuzz_guard_mw = fuzz_guard(max_attempts=15, max_empty=10, max_missing_wordlists=3)
    # vhost_guard stops the "bigger wordlist will fix it" loop against a wildcard
    # responder — a bigger DNS list can't beat a box that serves a uniform page
    # for every unknown Host; the agent must pivot to context-derived Host probes.
    vhost_guard_mw = vhost_guard(max_unproductive=2)
    surface = surface_spec(spec.profile, tools)
    surface["middleware"] = [
        *surface.get("middleware", []),
        fuzz_guard_mw,
        vhost_guard_mw,
    ]

    subagents = [
        surface,
        exploit_spec(spec.profile, tools),
        postex_spec(spec.profile, tools),
        analyst_spec(spec.profile, analyst_tools),
    ]
    if any(t.name.startswith("ad__") for t in tools):
        subagents.append(ad_spec(spec.profile, tools))
    subagents.append(researcher_spec(spec.profile, tools))

    # Subagents that drive target-facing commands: they get the command_logger
    # (verbatim methodology writeup) and the provided-credentials prompt block.
    # The researcher (browser/API research) and analyst (report writer) don't run
    # box commands, so neither applies to them.
    offensive_subagents = {"surface", "exploit", "postex", "ad"}
    credentials_block = spec.credentials_block()

    # Per-subagent middleware — the orchestrator's stack is per-loop and never
    # intercepts tool calls made inside a subagent runtime:
    #   * repeat_guard — break loops where a subagent re-issues the same failing
    #     call (e.g. exploit__deliver_via_web with no payload).
    #   * require_episode_log — for subagents that both emit a ToolStrategy
    #     structured response AND can write episodes, make logging a hard
    #     precondition for returning that response. A ToolStrategy ends the loop
    #     the instant findings are emitted, so without this the model folds its
    #     "log findings" plan step into "return findings" and skips the write.
    for s in subagents:
        # Surface assumed-breach credentials into the offensive subagents' system
        # prompts (durable: prompts aren't summarized away mid-run). The
        # orchestrator gets the same block at create_deep_agent below.
        if credentials_block and s["name"] in offensive_subagents:
            s["system_prompt"] = f"{s['system_prompt']}\n\n{credentials_block}"
        # block_fs_tools — deepagents binds the six vfs tools to every subagent
        # via FilesystemMiddleware; the harness profile only hides them from the
        # model schema, so the model still calls them and the ToolNode runs them
        # against the empty vfs. The orchestrator strip doesn't reach subagent
        # subgraphs, so block at the tool-call boundary here.
        tool_names = {getattr(t, "name", "") for t in s.get("tools", [])}
        # suggest_unknown_tool redirects a wrong-prefix call (e.g. the model
        # invents shell__get_cookies when only browser__get_cookies exists) to
        # the real tool, using this subagent's own tool names.
        extra: list[Any] = [
            # model_retry rides out transient provider errors (Anthropic 529
            # Overloaded, 429, 5xx) so one doesn't crash the engagement.
            model_retry(),
            suggest_unknown_tool(tool_names),
            block_fs_tools(),
            repeat_guard(max_repeats=3),
        ]
        # idle_read_guard breaks spin-polling a settled tmux pane — a success
        # (ok:True, empty delta) that repeat_guard deliberately exempts. Attach
        # it to any subagent that actually drives shell__tmux_read.
        if "shell__tmux_read" in tool_names:
            extra.append(idle_read_guard(max_idle=6))
        # no_progress_guard breaks semantically-repetitive flailing — N sends of
        # the same file-read/enum verb with tweaked args and no finding (e.g.
        # brute-guessing file paths against a permission wall). Iterative tools
        # (sshpass/hydra/nc/curl credential-spray + probing) are exempt so a
        # legitimate spray isn't cut off.
        if {"shell__tmux_send", "shell__tmux_exec"} & tool_names:
            extra.append(no_progress_guard(max_sends=8))
            # step_budget caps the shell-driving loop length: a single subagent
            # grinding hundreds of steps gets expensive (each step re-sends the
            # whole transcript → O(N²)). Forcing a handback lets the orchestrator
            # re-task with fresh context, resetting the quadratic. Sessions
            # persist by name, so nothing operational is lost. Set high so it's a
            # backstop against a runaway loop, not a routine interruption.
            extra.append(step_budget(max_steps=130))
        # HTTP JSON calls can "succeed" at the transport layer while the app
        # keeps returning the same 4xx/5xx blocker. Cap that semantic stall
        # before exploit burns turns retrying a locked auth/session path.
        if "shell__http_json_request" in tool_names:
            extra.append(http_stall_guard(max_repeats=5))
        # browse_budget caps page loads so a browser-driven subagent (researcher,
        # exploit) can't spiral into endless research without returning — it
        # browsed 92 pages and never emitted a result in one run.
        if "browser__goto" in tool_names:
            extra.append(browse_budget(max_browses=25))
        # curl_budget caps surface's request grind — it should characterize the
        # surface and hand off, not fire 90 curls exploiting one endpoint.
        if "surface__curl" in tool_names:
            extra.append(curl_budget(max_calls=40))
        # research_budget bounds the researcher's *total* read/search calls so it
        # converges to a ResearchResult instead of relocating its spiral across
        # tools (goto -> grep -> read_file). Per-tool caps alone are whack-a-mole.
        if s["name"] == "researcher":
            extra.append(research_budget(max_calls=50))
        response_tool = structured_tool_name(s.get("response_format"))
        if response_tool:
            # Force the subagent to actually emit its ToolStrategy response —
            # without this the model can end on a plain/empty AIMessage and
            # task() returns nothing (the researcher's empty-output failure).
            extra.append(require_structured_response(response_tool))
        if "episodes__write_episode" in tool_names and response_tool:
            extra.append(require_episode_log(response_tool))
        # command_logger sits just outside tool_error_guard: it records every
        # target-facing tool call (verbatim command + output) to the episode log
        # so the analyst's methodology reads like a writeup. Placed here it only
        # logs calls that pass every guard and actually execute (a guard
        # short-circuit never reaches it), and it still captures tool-level
        # errors that tool_error_guard converts to an error ToolMessage. Only the
        # offensive subagents run target commands worth a writeup line.
        if engagement_id and s["name"] in offensive_subagents:
            extra.append(command_logger(engagement_id, s["name"]))
        # tool_error_guard goes INNERMOST (last) so it wraps only tool execution:
        # an MCP ToolException (e.g. a malformed tmux_send) becomes a recoverable
        # ToolMessage instead of panicking the engagement, and outer guards like
        # repeat_guard still see the status="error" result.
        extra.append(tool_error_guard())
        s["middleware"] = [*s.get("middleware", []), *extra]

    # Validate each subagent has its critical tools bound — and strip the
    # `required_tools` key before passing to deepagents (it's our own
    # convention, not part of the deepagents SubAgent spec).
    _assert_required_tools(subagents, catalogue=tools)
    for s in subagents:
        log.info(
            "subagent %s built with %d tools: %s",
            s["name"],
            len(s["tools"]),
            sorted(t.name for t in s["tools"]),
        )
        s.pop("required_tools", None)

    # AsyncPostgresSaver.from_conn_string returns an async context manager;
    # entering it sets up the pool. `setup()` is idempotent — call once per
    # process before first use to create the checkpoint tables.
    async with AsyncPostgresSaver.from_conn_string(PG_URL) as checkpointer:
        try:
            await checkpointer.setup()
        except Exception as exc:  # noqa: BLE001
            log.warning("checkpointer.setup() raised %s — continuing (likely already set up)", exc)

        orchestrator_prompt = mode.orchestrator_prompt
        if credentials_block:
            orchestrator_prompt = f"{orchestrator_prompt}\n\n{credentials_block}"

        agent = create_deep_agent(
            model=_orchestrator_model(spec.profile),
            tools=orchestrator_tools,
            system_prompt=orchestrator_prompt,
            subagents=subagents,
            backend=fs_backend,
            # No `skills=` for the orchestrator: it triages and delegates via
            # task(); each subagent loads its own role skills (skills/<role>/).
            # The old `skills=["skills/"]` was a no-op anyway — the loader scans
            # one level deep, and our layout is skills/<category>/<skill>/SKILL.md.
            interrupt_on=mode.interrupt_policy,
            middleware=[
                # model_retry rides out transient provider errors (529/429/5xx)
                # on the orchestrator's own model calls too.
                model_retry(),
                roe_gate(mode.allowlist),
                action_class_gate(mode.allowlist, set(mode.interrupt_policy.keys())),
                budget_guard(mode.budget_usd),
                # serialize_tasks: one subagent delegation per turn. A parallel
                # task() dispatch runs subagents concurrently (shared tmux state)
                # and blocks the orchestrator until BOTH return — a dead-end
                # branch stalls the run. See serialize_tasks.py / debug_reactor3.
                serialize_tasks(),
                stuck_detector(threshold=15),
                *(
                    [flag_completion_gate(spec.expected_flags)]
                    if spec.expected_flags and spec.expected_flags > 0
                    else []
                ),
                # Innermost — wraps tool execution only, so a tool exception
                # becomes a recoverable ToolMessage rather than crashing the run,
                # without swallowing the HITL interrupts the gates above raise.
                tool_error_guard(),
            ],
            checkpointer=checkpointer,
        )

        _strip_orchestrator_fs_tools(agent)
        yield agent


def _assert_required_tools(
    subagents: list[dict[str, Any]],
    catalogue: list[Any] | None = None,
) -> None:
    """Fail loudly if any subagent is missing its declared `required_tools`.

    When firing, includes the *full MCP catalogue* in the error so the
    operator can see whether the tool names just don't match (different
    `langchain-mcp-adapters` naming convention, for example) versus the
    MCP server actually being unreachable.
    """
    problems: list[str] = []
    for s in subagents:
        required = s.get("required_tools") or set()
        if not required:
            continue
        bound = {t.name for t in s.get("tools") or []}
        missing = set(required) - bound
        if missing:
            problems.append(
                f"  subagent '{s['name']}' is missing required tools: "
                f"{sorted(missing)}. Bound tools were: {sorted(bound) or '[NONE]'}"
            )
    if problems:
        catalog_names = sorted({t.name for t in (catalogue or [])})
        catalog_blurb = (
            f"\nFull MCP catalogue ({len(catalog_names)} tools): "
            f"{catalog_names if catalog_names else '[NONE — all MCP servers failed get_tools()]'}"
        )
        raise RuntimeError(
            "Subagents cannot start — required tools missing.\n"
            "Possible causes:\n"
            "  (a) The MCP server's container wasn't reachable at probe time.\n"
            "  (b) The MCP server WAS reachable, but its tools are exposed under\n"
            "      different names than the subagent's allowlist expects.\n"
            "      Compare 'required tools' below to the catalogue at the end.\n"
            "  (c) The MCP HTTP handshake is failing (server up but `get_tools()`\n"
            "      returns empty for that server). Curl the /mcp endpoint directly.\n\n"
            + "\n".join(problems)
            + catalog_blurb
        )


# read_file is intentionally NOT stripped — skills load their SKILL.md bodies
# via read_file (progressive disclosure). See profile.py / block_fs_tools.py.
_ORCHESTRATOR_BLOCKED_FS_TOOLS = frozenset({
    "ls", "write_file", "edit_file", "glob", "grep",
})


def _strip_orchestrator_fs_tools(agent: Any) -> None:
    """Actually remove the deepagents vfs tools from the orchestrator's ToolNode.

    The HarnessProfile's `excluded_tools` only filters the **schema** the
    model sees on each call. Anthropic's models (heavily trained on these
    tool names from Claude Code) still emit `tool_use` blocks for them
    anyway — and the ToolNode dutifully executes whatever name it has bound.
    The result was the orchestrator wasting turns ls'ing the empty vfs
    looking for skill files that aren't there (and never will be — skills
    live in the prompt, not the vfs).

    This walks the compiled graph, finds the orchestrator's tools node, and
    removes the six fs tool names from `tools_by_name`. Subsequent calls
    return an "unknown tool" error — clear feedback the model can act on,
    instead of misleading empty results. Subagents have their own ToolNodes
    in their own subgraphs and are unaffected.
    """
    try:
        tools_node = agent.builder.nodes.get("tools")
        if tools_node is None:
            log.warning("could not locate orchestrator 'tools' node — skipping fs-tool strip")
            return
        runnable = getattr(tools_node, "runnable", tools_node)
        tools_by_name = getattr(runnable, "tools_by_name", None)
        if not isinstance(tools_by_name, dict):
            log.warning("ToolNode.tools_by_name not a dict (got %s) — skipping fs-tool strip",
                        type(tools_by_name).__name__)
            return
        stripped = [n for n in _ORCHESTRATOR_BLOCKED_FS_TOOLS if tools_by_name.pop(n, None) is not None]
        log.info("stripped %d fs tool(s) from orchestrator ToolNode: %s",
                 len(stripped), sorted(stripped))
    except Exception:  # noqa: BLE001
        log.exception("failed to strip orchestrator fs tools — continuing")


def _orchestrator_model(profile: str) -> str:
    """Return the `provider:model` identifier for the orchestrator.

    We pass the string (not a model instance) so that deepagents can look up
    and apply our registered HarnessProfile (see [profile.py]) — that profile
    is what excludes the heavy filesystem tools AND the Anthropic prompt-
    caching middleware. Without those exclusions, the bound tools blow past
    Anthropic's compile-time grammar limit.
    """
    from .models import model_for
    return model_for(profile, "orchestrator")["model"]  # type: ignore[arg-type]
