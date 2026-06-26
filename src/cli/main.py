"""Terminal CLI."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

import httpx
import typer
import yaml
from rich.console import Console
from rich.markup import escape as _esc
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

app = typer.Typer(no_args_is_help=True, help="Voidstrike — autonomous offensive security agent")
console = Console()

GATEWAY_URL = os.environ.get("VOIDSTRIKE_GATEWAY", "http://localhost:8000")

_BANNER_TAGLINE = "autonomous offensive security agent"


def _print_banner() -> None:
    """Print the compact VOIDSTRIKE wordmark once at the top of an interactive
    run. Cyan to match the interface's accent (every section rule is cyan), with
    a dim tagline — deliberately one line so it reads as a header, not a splash.
    The `▓▒░` is a small nod to the old block art without the height."""
    console.print(
        f"\n[bold cyan]▓▒░ VOIDSTRIKE[/bold cyan] [dim]· {_BANNER_TAGLINE}[/dim]\n"
    )


AGENT_COLORS = {
    "orchestrator": "cyan",
    "surface": "green",
    "exploit": "red",
    "postex": "magenta",
    "analyst": "yellow",
    "researcher": "blue",
    "ad": "magenta",
}


_ENGAGEMENT_ID_PREFIX = re.compile(
    # Tolerate punctuation/casing variants the orchestrator uses when it
    # follows the kickoff template ("Engagement id: <uuid>. ...").
    r"^\s*engagement[\s_-]*id\s*[:=]?\s*"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"[.,;:\s]*",
    re.IGNORECASE,
)


from collections import deque  # noqa: E402

# Maps a langgraph subgraph namespace UUID (e.g. `tools:55c5e535-...`) to the
# subagent that's actually running there ("surface", "exploit", etc.). The
# event stream doesn't include this mapping anywhere — langgraph emits
# subagent activity under opaque task UUIDs, so we have to derive it from
# the orchestrator's task() tool_use blocks.
_NAMESPACE_SUBAGENT_CACHE: dict[str, str] = {}

# FIFO queue of pending task() dispatches that haven't yet been claimed by a
# subagent step event. Each entry is the `subagent_type` from a `task(...)`
# call the orchestrator emitted. When we see a new (uncached) namespace
# UUID, we pop the front and assign.
_PENDING_TASK_ASSIGNEES: deque[str] = deque()


def _reset_subagent_tracking() -> None:
    """Called on engagement boundary (start event) to clear stale state."""
    _NAMESPACE_SUBAGENT_CACHE.clear()
    _PENDING_TASK_ASSIGNEES.clear()


def _record_task_dispatch(assignee: str) -> None:
    """Append a task dispatch to the FIFO queue so the next unclaimed
    namespace can pick it up."""
    if assignee:
        _PENDING_TASK_ASSIGNEES.append(assignee)


def _strip_engagement_id_prefix(text: str) -> str:
    """Strip the `Engagement id: <uuid>.` prefix the orchestrator prepends to
    every `task` delegation (per the engagement prompt). The operator
    already knows the id from the engagement header; repeating it on every
    delegation line is noise."""
    if not text:
        return text
    return _ENGAGEMENT_ID_PREFIX.sub("", text).lstrip()


def _is_internal_node(name: str) -> bool:
    """LangGraph emits step events keyed by every middleware lifecycle hook
    (`SkillsMiddleware.before_agent`, `BudgetGuard.after_model`, etc.) with
    `None` / empty payloads. They're useless noise for the operator —
    skip anything that smells like a middleware hook key."""
    if not isinstance(name, str):
        return False
    return (
        "Middleware." in name
        or name.endswith((".before_agent", ".after_model",
                          ".before_model", ".wrap_tool_call",
                          ".after_agent"))
        # Per-subagent internal nodes — surface/exploit/etc. show their own
        # output through the `model`/`tools` nodes; their containing-node
        # entry just duplicates.
        or name in {"PatchToolCallsMiddleware", "TodoListMiddleware",
                    "BudgetGuard", "StuckDetector", "HumanInTheLoopMiddleware",
                    "SkillsMiddleware"}
    )


def _agent_label(agent: str, subagent_label: str | None) -> tuple[str, str]:
    """Return (color, display_name) for an agent stream node.

    `model` from the root graph → "orchestrator" cyan.
    `model` from a subagent subgraph → the subagent's friendly name + its color.
    """
    if subagent_label:
        return AGENT_COLORS.get(subagent_label, "white"), subagent_label
    if agent == "model":
        return "cyan", "orchestrator"
    return AGENT_COLORS.get(agent, "white"), agent


@app.command()
def init() -> None:
    """One-time onboarding: write .env from .env.example and confirm gateway up."""
    env_path = Path(".env")
    example = Path(".env.example")
    if not env_path.exists() and example.exists():
        env_path.write_text(example.read_text())
        console.print(f"[green]Wrote[/green] {env_path}. Edit it before running engagements.")
    else:
        console.print(f"{env_path} already exists — leaving it.")

    try:
        r = httpx.get(f"{GATEWAY_URL}/healthz", timeout=2.0)
        ok = r.status_code == 200
    except Exception:
        ok = False
    if ok:
        console.print(f"[green]✓[/green] Gateway up at {GATEWAY_URL}")
    else:
        console.print(f"[red]✗[/red] Gateway not reachable at {GATEWAY_URL}. Run `docker compose up`.")


@app.command()
def engage(
    spec: Path = typer.Argument(..., help="Path to engagement YAML spec"),
    vpn: Path | None = typer.Option(
        None,
        "--vpn",
        help=(
            "Override the spec's `vpn_config:` field with a different .ovpn. "
            "Resolution precedence: --vpn > VPN_FILE env > spec's vpn_config."
        ),
    ),
    skip_vpn: bool = typer.Option(
        False,
        "--skip-vpn",
        help="Don't bring up the vpn sidecar (use when it's already running, or for non-VPN runs).",
    ),
    profile: str = typer.Option("eco", "--profile", help="eco | max | test | qwen | gpt"),
    attach: bool = typer.Option(True, "--attach/--detach", help="Stream output to this terminal"),
    debug_log: Path | None = typer.Option(
        None,
        "--debug-log",
        help=(
            "Append the raw agent event stream (tool calls, results, model "
            "messages) to this file as JSON Lines — a machine-readable transcript "
            "for an LLM to analyze. Captured only while attached."
        ),
    ),
) -> None:
    """Start an engagement and (by default) stream output here.

    The spec drives the target. With an `htb:` block, the **gateway** spawns the
    named HackTheBox machine via the HTB API, fills in its IP, submits captured
    flags, and tears it down per `htb.teardown` — so any client (CLI or web) gets
    provisioning from the spec alone. An HTB run is atomic: Ctrl-C cancels it and
    the gateway still tears the box down. A static run (no `htb:` block) targets
    the IPs in `targets:`, and Ctrl-C pauses it for `voidstrike resume`.

    If the spec has a `vpn_config:` field (or `--vpn` / `VPN_FILE` is provided),
    the vpn sidecar is brought up with that .ovpn before the engagement starts.
    Pass `--skip-vpn` to leave compose alone.
    """
    from ..schemas.engagement import EngagementSpec  # noqa: PLC0415

    _print_banner()
    if not spec.exists():
        console.print(f"[red]Spec not found:[/red] {spec}")
        raise typer.Exit(2)
    parsed = EngagementSpec.from_yaml(spec)

    # VPN sidecar — both static and HTB runs reach the target over the lab tunnel.
    # The gateway can't bring this up (it's a sibling compose service), so the
    # host CLI does it before starting the run.
    vpn_path = _resolve_vpn_path(spec, vpn)
    if vpn_path is not None and not skip_vpn:
        project_root = _find_project_root(spec)
        if project_root is None:
            console.print(
                "[red]Could not locate infra/docker-compose.yml.[/red] "
                "Run from the repo root, or pass --skip-vpn if the sidecar is "
                "already up."
            )
            raise typer.Exit(2)
        _ensure_vpn_up(vpn_path, project_root)

    # Post the spec as-is — including any `htb:` block. The gateway provisions
    # from it (spawn → fill IP → submit flags → teardown); we just stream.
    files: dict[str, tuple[str, bytes, str]] = {"spec": (spec.name, spec.read_bytes(), "application/yaml")}
    if vpn:
        files["vpn_config"] = (vpn.name, vpn.read_bytes(), "application/octet-stream")
    data = {"profile": profile}

    try:
        resp = httpx.post(f"{GATEWAY_URL}/engagements", files=files, data=data, timeout=30.0)
    except httpx.HTTPError as exc:
        console.print(f"[red]Gateway error:[/red] {exc}")
        raise typer.Exit(1) from exc
    if resp.status_code != 200:
        console.print(f"[red]Gateway returned {resp.status_code}:[/red] {resp.text}")
        raise typer.Exit(1)
    payload = resp.json()
    engagement_id = payload["engagement_id"]
    console.print(Panel.fit(
        f"[bold]engagement_id:[/bold] {engagement_id}\n[bold]thread_id:[/bold] {payload['thread_id']}",
        title="started",
    ))
    if attach:
        # HTB runs are atomic → `cancel` on Ctrl-C (the gateway tears the box
        # down on cancel). Static runs `pause` so the operator can `resume`
        # later; an explicit `voidstrike cancel <id>` still terminates either.
        on_interrupt = "cancel" if parsed.htb is not None else "pause"
        _attach_stream(engagement_id, on_interrupt=on_interrupt, debug_log=debug_log)


def _resolve_vpn_path(spec_path: Path, vpn_flag: Path | None) -> Path | None:
    """Pick the .ovpn for this engagement.

    Precedence: --vpn flag > VPN_FILE env > spec's `vpn_config:` field.
    Relative paths in the spec are resolved against the spec file's parent
    directory — compose's "relative paths are relative to the compose file"
    footgun (see the comment block in infra/docker-compose.vpn.yml) is avoided
    by always returning an absolute path.
    """
    if vpn_flag is not None:
        return vpn_flag.expanduser().resolve()

    env_path = os.environ.get("VPN_FILE")
    if env_path:
        return Path(env_path).expanduser().resolve()

    try:
        with open(spec_path) as fh:
            data = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return None

    raw = data.get("vpn_config") if isinstance(data, dict) else None
    if not raw:
        return None

    candidate = Path(str(raw)).expanduser()
    if not candidate.is_absolute():
        candidate = (spec_path.parent / candidate).resolve()
    else:
        candidate = candidate.resolve()
    return candidate


def _find_project_root(start: Path) -> Path | None:
    """Walk up from `start` looking for infra/docker-compose.yml.

    Falls back to walking up from the CWD if the spec lives outside the repo
    (e.g. an operator stores specs in ~/engagements/). Returns the directory
    containing the `infra/` folder, or None if nothing matches.
    """
    candidates: list[Path] = []
    start_resolved = start.resolve()
    candidates.append(start_resolved if start_resolved.is_dir() else start_resolved.parent)
    candidates.append(Path.cwd().resolve())

    seen: set[Path] = set()
    for base in candidates:
        for parent in [base, *base.parents]:
            if parent in seen:
                continue
            seen.add(parent)
            if (parent / "infra" / "docker-compose.yml").exists():
                return parent
    return None


def _ensure_vpn_up(vpn_path: Path, project_root: Path) -> None:
    """Bring up the compose vpn sidecar with `vpn_path` mounted as the config.

    Idempotent: `docker compose up -d` only recreates containers whose
    definition changed. We always pass both -f flags (base + vpn overlay) so
    the overlay's network-mode/cap_add tweaks for the offensive MCP servers
    take effect; without the base file you get "no such service: vpn".
    """
    if not vpn_path.exists():
        console.print(f"[red].ovpn file not found:[/red] {vpn_path}")
        raise typer.Exit(2)

    env = os.environ.copy()
    env["VPN_FILE"] = str(vpn_path)

    cmd = [
        "docker", "compose",
        "-f", "infra/docker-compose.yml",
        "-f", "infra/docker-compose.vpn.yml",
        "up", "-d",
    ]
    console.print(
        f"[dim]Bringing up vpn sidecar with[/dim] [cyan]{vpn_path}[/cyan]"
    )
    try:
        result = subprocess.run(
            cmd,
            cwd=str(project_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except FileNotFoundError as exc:
        console.print(
            "[red]`docker` not on PATH.[/red] Install Docker, or pass "
            "--skip-vpn if the sidecar is already up."
        )
        raise typer.Exit(1) from exc
    except subprocess.TimeoutExpired as exc:
        console.print("[red]VPN bring-up timed out after 180s.[/red]")
        raise typer.Exit(1) from exc

    if result.returncode != 0:
        console.print(f"[red]docker compose failed:[/red]\n{result.stderr.strip()}")
        raise typer.Exit(1)


@app.command(name="attach")
def attach(
    engagement_id: str = typer.Argument(...),
    debug_log: Path | None = typer.Option(
        None, "--debug-log",
        help="Append the raw event stream to this file as JSON Lines for analysis.",
    ),
) -> None:
    """Observe a running engagement.

    Ctrl-C detaches without stopping the engagement. Use `voidstrike pause`
    to pause it (resumable) or `voidstrike cancel` to terminate."""
    _print_banner()
    _attach_stream(engagement_id, on_interrupt="detach", debug_log=debug_log)


@app.command(name="resume")
def resume(
    engagement_id: str = typer.Argument(...),
    detach: bool = typer.Option(
        False, "--detach",
        help="Don't attach to the stream after resuming.",
    ),
    debug_log: Path | None = typer.Option(
        None, "--debug-log",
        help="Append the raw event stream to this file as JSON Lines for analysis.",
    ),
) -> None:
    """Resume a paused engagement from its last Postgres checkpoint."""
    status = _request_resume(engagement_id)
    if status != "resuming":
        console.print(f"[red]Cannot resume:[/red] gateway returned {status!r}")
        raise typer.Exit(1)
    console.print(f"[green]resuming[/green] {engagement_id}")
    if detach:
        return
    _attach_stream(engagement_id, on_interrupt="pause", debug_log=debug_log)


@app.command(name="cancel")
def cancel(
    engagement_id: str | None = typer.Argument(
        None,
        help="The engagement ID to cancel. Omit when using --all.",
    ),
    all_running: bool = typer.Option(
        False, "--all",
        help="Cancel every running engagement on the gateway.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y",
        help="Skip the confirmation prompt for --all.",
    ),
) -> None:
    """Stop one or all running engagements on the gateway."""
    if all_running and engagement_id:
        console.print("[red]Pass either an engagement_id OR --all, not both.[/red]")
        raise typer.Exit(2)
    if not all_running and not engagement_id:
        console.print("[red]Need an engagement_id (or use --all).[/red]")
        raise typer.Exit(2)

    if all_running:
        _cancel_all(skip_confirm=yes)
        return

    status = _request_cancel(engagement_id)  # type: ignore[arg-type]
    console.print(f"[yellow]cancel:[/yellow] {status}")


def _cancel_all(*, skip_confirm: bool) -> None:
    """Hit `/engagements/cancel_all`. Prompts for confirmation unless
    `skip_confirm` is True."""
    # Show what's running so the operator knows what they're about to kill.
    try:
        resp = httpx.get(
            f"{GATEWAY_URL}/engagements",
            params={"running": "true"},
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        console.print(f"[red]Gateway unreachable:[/red] {exc}")
        raise typer.Exit(1) from exc
    if resp.status_code != 200:
        console.print(f"[red]Gateway returned {resp.status_code}:[/red] {resp.text}")
        raise typer.Exit(1)
    running = resp.json().get("engagements", [])
    if not running:
        console.print("[dim]No running engagements to cancel.[/dim]")
        return

    console.print(f"[yellow]About to cancel {len(running)} running engagement(s):[/yellow]")
    for e in running:
        console.print(
            f"  • {e['engagement_id'][:8]}  {e.get('name', '—')}"
            f"  [{e.get('mode', '—')}/{e.get('profile', '—')}]"
        )

    if not skip_confirm:
        if not typer.confirm("Cancel all?", default=False):
            console.print("[dim]Aborted.[/dim]")
            return

    try:
        resp = httpx.post(
            f"{GATEWAY_URL}/engagements/cancel_all",
            timeout=30.0,
        )
    except httpx.HTTPError as exc:
        console.print(f"[red]Gateway unreachable:[/red] {exc}")
        raise typer.Exit(1) from exc
    if resp.status_code != 200:
        console.print(f"[red]Gateway returned {resp.status_code}:[/red] {resp.text}")
        raise typer.Exit(1)
    body = resp.json()
    console.print(
        f"[yellow]Cancelled {body.get('cancelled_count', 0)}/{body.get('total', 0)} "
        "engagements.[/yellow]"
    )
    for e in body.get("engagements", []):
        console.print(f"  → {e['engagement_id'][:8]}  {e['status']}")


STATUS_COLOR = {
    "running":   "green",
    "paused":    "yellow",
    "finished":  "cyan",
    "cancelled": "yellow",
    "failed":    "red",
    "stopped":   "dim",
    "unknown":   "dim",
}


@app.command(name="ls")
def ls(
    running: bool = typer.Option(
        False, "--running", "-r",
        help="Show only engagements currently running on the gateway.",
    ),
) -> None:
    """List engagements known to the gateway.

    Without flags, shows every engagement on disk plus an in-memory status.
    Use `-r` / `--running` to filter to live runs only (handy when you want
    a quick list of IDs to attach to or cancel)."""
    try:
        resp = httpx.get(
            f"{GATEWAY_URL}/engagements",
            params={"running": "true"} if running else None,
            timeout=10.0,
        )
    except httpx.HTTPError as exc:
        console.print(f"[red]Gateway unreachable:[/red] {exc}")
        raise typer.Exit(1) from exc
    if resp.status_code != 200:
        console.print(f"[red]Gateway returned {resp.status_code}:[/red] {resp.text}")
        raise typer.Exit(1)

    entries = resp.json().get("engagements", [])
    if not entries:
        msg = "No running engagements." if running else "No engagements yet."
        console.print(f"[dim]{msg}[/dim]")
        return

    table = Table("id", "status", "name", "mode", "profile", "targets")
    for e in entries:
        status = e.get("status", "unknown")
        color = STATUS_COLOR.get(status, "white")
        table.add_row(
            e["engagement_id"][:8],
            f"[{color}]{status}[/{color}]",
            e.get("name") or "—",
            e.get("mode") or "—",
            e.get("profile") or "—",
            ", ".join(e.get("targets") or []) or "—",
        )
    console.print(table)


def _request_cancel(engagement_id: str) -> str:
    """POST /cancel for the engagement. Returns the gateway's status string
    or a short error description; never raises so the CLI's Ctrl-C path
    stays robust."""
    return _post_action(engagement_id, "cancel")


def _request_pause(engagement_id: str) -> str:
    """POST /pause. Same robustness contract as _request_cancel."""
    return _post_action(engagement_id, "pause")


def _request_resume(engagement_id: str) -> str:
    """POST /resume."""
    return _post_action(engagement_id, "resume")


def _post_action(engagement_id: str, action: str) -> str:
    try:
        resp = httpx.post(
            f"{GATEWAY_URL}/engagements/{engagement_id}/{action}",
            timeout=10.0,
        )
        if resp.status_code != 200:
            return f"gateway returned {resp.status_code}: {resp.text[:200]}"
        return resp.json().get("status", "unknown")
    except httpx.HTTPError as exc:
        return f"gateway unreachable ({exc})"


def _open_debug_log(path: Path, engagement_id: str, *, announce: bool = True) -> TextIO | None:
    """Open the debug JSONL sink (append) and write a run-delimiter header.

    Append mode so a pause→resume (or re-attach) extends the same transcript
    instead of clobbering it. Returns None on failure — debug logging must never
    take down the stream.
    """
    try:
        path = path.expanduser()
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        fh = path.open("a", encoding="utf-8")
    except OSError as exc:
        console.print(f"[yellow]Could not open --debug-log {path}: {exc}[/yellow]")
        return None
    fh.write(json.dumps({
        "event": "_debug_meta",
        "engagement_id": engagement_id,
        "attached_at": datetime.now(UTC).isoformat(),
        "note": "raw voidstrike event stream; one JSON event per line",
    }) + "\n")
    fh.flush()
    if announce:
        console.print(f"[dim]Debug log → {path}[/dim]")
    return fh


def _write_debug(fh: TextIO | None, event: object) -> None:
    """Append one event to the debug log as a JSON line. Best-effort."""
    if fh is None:
        return
    try:
        fh.write(json.dumps(event, default=str) + "\n")
        fh.flush()
    except (OSError, TypeError):
        pass


def _attach_stream(
    engagement_id: str, *, on_interrupt: str = "detach", debug_log: Path | None = None,
    announce_debug_log: bool = True,
) -> None:
    """Attach to the engagement's SSE stream.

    `on_interrupt` ∈ {"detach", "pause", "cancel"} — what to do when the
    operator presses Ctrl-C:
      - detach: leave the engagement running on the gateway (default for
        `voidstrike attach`).
      - pause: cancel the running task but keep the checkpoint; the
        engagement can be resumed with `voidstrike resume <id>`. Used by
        `voidstrike engage` and `voidstrike resume`.
      - cancel: terminate the engagement permanently.

    `debug_log`, if set, receives every raw event as a JSON line — a complete
    machine-readable transcript for offline / LLM analysis.
    """
    url = f"{GATEWAY_URL}/engagements/{engagement_id}/stream"
    console.print(f"[dim]Streaming {url}[/dim]")
    hint = {
        "pause": "(Ctrl-C pauses; resume with `voidstrike resume <id>`)",
        "cancel": "(Ctrl-C cancels the engagement on the gateway)",
        "detach": "(Ctrl-C detaches; engagement stays running)",
    }.get(on_interrupt, "")
    if hint:
        console.print(f"[dim]{hint}[/dim]")
    debug_fh = _open_debug_log(debug_log, engagement_id, announce=announce_debug_log) if debug_log else None
    interrupted = False
    # The SSE stream can drop mid-engagement — a gateway restart, a proxy
    # timeout, a network blip — surfacing as httpx.RemoteProtocolError. The
    # engagement keeps running on the gateway (Postgres checkpoint + Redis
    # backlog), so a drop must NOT crash the CLI with a traceback. Reconnect
    # with bounded backoff; on reconnect, suppress the replayed backlog (the
    # gateway replays up to 500 events then emits a `subscribed` sentinel) so
    # the operator doesn't get a flood of already-seen lines.
    terminal_kinds = {"end", "complete", "cancelled"}
    max_reconnects = 10
    saw_terminal = False
    first_connect = True
    reconnects = 0
    try:
        while not saw_terminal:
            replaying = not first_connect  # skip backlog we already rendered
            got_live = False
            error: Exception | None = None
            try:
                with httpx.stream("GET", url, timeout=None) as resp:
                    for line in resp.iter_lines():
                        line = (line or "").strip()
                        if not line.startswith("data:"):
                            continue
                        payload = line[len("data:"):].strip()
                        try:
                            event = json.loads(payload)
                        except json.JSONDecodeError:
                            if not replaying:
                                _write_debug(debug_fh, {"event": "_raw", "data": payload})
                                console.print(payload)
                            continue
                        kind = event.get("event")
                        if replaying:
                            # Resume rendering at the post-replay sentinel.
                            if kind == "subscribed":
                                replaying = False
                                console.print("[dim](reconnected — live)[/dim]")
                            continue
                        got_live = True
                        _write_debug(debug_fh, event)
                        _render_event(event)
                        if kind in terminal_kinds:
                            saw_terminal = True
            except httpx.HTTPError as exc:
                error = exc
            first_connect = False
            if saw_terminal:
                break
            # Either an error, or the stream closed without a terminal event —
            # the gateway dropped us. Reconnect (resetting the budget if we made
            # live progress this attempt), or give up cleanly after the cap.
            _set_inflight(None)
            if got_live:
                reconnects = 0
            reconnects += 1
            if reconnects > max_reconnects:
                label = f" ({type(error).__name__})" if error else ""
                console.print(
                    f"\n[yellow]Lost the event stream{label}. The engagement may "
                    f"still be running on the gateway — reattach with "
                    f"[bold]voidstrike attach {engagement_id}[/bold].[/yellow]"
                )
                break
            label = type(error).__name__ if error else "stream closed"
            console.print(
                f"[dim]stream dropped ({label}); reconnecting "
                f"({reconnects}/{max_reconnects})…[/dim]"
            )
            time.sleep(min(2 ** reconnects, 8))
    except KeyboardInterrupt:
        interrupted = True
    finally:
        _set_inflight(None)  # clear the spinner so it doesn't hang on exit
        if debug_fh is not None:
            debug_fh.close()

    if not interrupted:
        return

    if on_interrupt == "detach":
        console.print("[yellow]Detached.[/yellow] Engagement still running on the gateway.")
        return

    if on_interrupt == "pause":
        console.print("\n[yellow]Pausing engagement on the gateway...[/yellow]")
        status = _request_pause(engagement_id)
        console.print(f"[yellow]→ {status}[/yellow]")
        console.print(f"[dim]resume with: voidstrike resume {engagement_id}[/dim]")
        terminal_events = {"end", "paused"}
    else:
        console.print("\n[yellow]Cancelling engagement on the gateway...[/yellow]")
        status = _request_cancel(engagement_id)
        console.print(f"[yellow]→ {status}[/yellow]")
        terminal_events = {"end", "cancelled"}
    # After the action we re-attach briefly to render the final events so
    # the operator sees clean closure. A second Ctrl-C bails immediately.
    console.print("[dim](press Ctrl-C again to exit immediately)[/dim]")
    try:
        with httpx.stream("GET", url, timeout=15.0) as resp:
            for line in resp.iter_lines():
                line = (line or "").strip()
                if not line.startswith("data:"):
                    continue
                payload = line[len("data:"):].strip()
                try:
                    event = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                _render_event(event)
                if event.get("event") in terminal_events:
                    break
    except (httpx.HTTPError, KeyboardInterrupt):
        pass


def _render_event(event: dict) -> None:
    """Render one SSE event. Splits the rendering by event shape:

      - lifecycle (`start`, `subscribed`, `complete`, `cancelling`,
        `cancelled`, `end`, `error`) get short distinctive lines
      - model events get one line per text block, plus one `→ calling X`
        line per tool_use block. Then the in-flight tool name is shown on a
        live status line so the operator sees what's currently running.
      - tool-result events get a `✓ X returned: <preview>` line and clear
        the live status.

    The previous flat `agent: ...` line dump truncated everything to 240
    chars, which buried tool dispatches and made the stream look frozen
    during long-running tool calls.
    """
    kind = event.get("event")
    if kind == "start":
        _reset_subagent_tracking()
        console.rule(f"engagement {event.get('engagement_id', '')}")
        return
    if kind == "subscribed":
        console.print("[dim](attached — live)[/dim]")
        return
    if kind == "complete":
        _set_inflight(None)
        console.rule("[green]engagement complete[/green]")
        return
    if kind == "cancelling":
        _set_inflight(None)
        reason = _esc(str(event.get("reason", "(no reason given)")))
        console.print(f"[yellow]cancelling:[/yellow] {reason}")
        return
    if kind == "cancelled":
        _set_inflight(None)
        console.rule("[yellow]engagement cancelled[/yellow]")
        return
    if kind == "paused":
        _set_inflight(None)
        reason = _esc(str(event.get("reason", "operator")))
        console.rule(f"[yellow]paused ({reason})[/yellow]")
        return
    if kind == "resumed":
        _set_inflight(None)
        console.rule("[green]engagement resumed[/green]")
        return
    if kind == "end":
        _set_inflight(None)
        console.rule("end of stream")
        return
    if kind == "error":
        _set_inflight(None)
        err = _esc(str(event.get("error", "")))
        console.print(f"[bold red]error:[/bold red] {err}")
        if event.get("traceback"):
            tb = _esc(str(event["traceback"]))
            console.print(f"[red]{tb}[/red]")
        return
    if kind == "htb":
        # Gateway-side HTB provisioning progress (spawn / ready / flag / teardown).
        stage = _esc(str(event.get("stage", "")))
        msg = _esc(str(event.get("message", "")))
        console.print(f"[dim]htb[/dim] [cyan]{stage}[/cyan] {msg}")
        return

    # `step` events have shape:
    #   {"event": "step", "namespace": [...], "data": {<node_name>: <state>}}
    # where <node_name> is "model", "tools", etc. `namespace` (added when
    # `subgraphs=True` is set on agent.astream) identifies which subgraph
    # produced this event — empty list = root, otherwise a path like
    # `["task:abc", "surface"]` meaning "the surface subagent dispatched
    # from a task() call".
    data = event.get("data", {})
    namespace = event.get("namespace") or []
    subagent = _subagent_from_namespace(namespace)
    if isinstance(data, dict):
        for agent, payload in data.items():
            if _is_internal_node(agent):
                continue
            _render_agent_payload(agent, payload, subagent_label=subagent)
    else:
        if subagent:
            color = AGENT_COLORS.get(subagent, "white")
            console.print(
                f"[{color}]{_esc(subagent)}[/{color}]: {_esc(str(data))}"
            )
        else:
            console.print(_esc(str(data)))


def _subagent_from_namespace(namespace: list[str]) -> str | None:
    """Map a subgraph namespace to the running subagent's friendly name.

    langgraph emits subagent events under opaque task UUIDs like
    `tools:55c5e535-...`. We can't decode the subagent from the UUID, so
    instead we track the orchestrator's `task(subagent_type=...)` calls in
    a FIFO queue (see `_PENDING_TASK_ASSIGNEES`) and claim the next
    pending assignment the first time we see a new namespace.

    Still falls back to the old name-in-namespace heuristic in case some
    deepagents/langgraph version surfaces the name directly.
    """
    if not namespace:
        return None
    first = str(namespace[0])

    # Cache hit — this namespace has been mapped before.
    cached = _NAMESPACE_SUBAGENT_CACHE.get(first)
    if cached:
        return cached

    # Defensive: if the namespace happens to include the subagent name
    # literally, prefer that over the FIFO assumption.
    for part in namespace:
        candidate = str(part).rsplit(":", 1)[-1].lower()
        if candidate in AGENT_COLORS and candidate != "orchestrator":
            _NAMESPACE_SUBAGENT_CACHE[first] = candidate
            return candidate

    # First sighting of a `tools:<uuid>` namespace — pop the next pending
    # task assignment. If the queue is empty, return None (will fall
    # through to a generic label rather than mislabeling as orchestrator).
    if _PENDING_TASK_ASSIGNEES:
        assignee = _PENDING_TASK_ASSIGNEES.popleft()
        _NAMESPACE_SUBAGENT_CACHE[first] = assignee
        return assignee

    return None


def _render_agent_payload(agent: str, payload, *, subagent_label: str | None = None) -> None:
    """Render a single agent's update from a step event.

    `subagent_label` (if set) is the friendly name of the subagent that
    produced this event — used as a prefix so the operator can tell
    `surface` vs `exploit` vs orchestrator events apart.

    Every dynamic value interpolated below is run through `_esc`
    (rich.markup.escape) — tool output / model text frequently contains
    bracketed text like `[/app]` from msfconsole, `[+]` from exploit POCs,
    or vendor banner strings — which Rich would otherwise parse as markup
    and crash with MarkupError.
    """
    color, display_name = _agent_label(agent, subagent_label)
    safe_label = _esc(display_name)
    prefix = f"[{color} bold]{safe_label}[/{color} bold]"

    if not isinstance(payload, dict):
        console.print(f"{prefix}  {_esc(_short(str(payload)))}")
        return

    msgs = payload.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return  # Non-message state update — no useful operator-facing line.

    last = msgs[-1]

    # A model turn can come back as a `refusal` (Anthropic's real-time cyber
    # safeguard, `stop_details.category == "cyber"`). It carries no content, so
    # without this it renders as a confusing silent/empty turn — which is exactly
    # what made a real engagement look like it was "truncating returns". Surface
    # it loudly with the legitimate unblock path (README: Cyber Verification
    # Program). Visibility only — we do not work around the safeguard.
    refusal = _refusal_note(last)
    if refusal:
        console.print(f"{prefix}  [bold yellow]⚠ model refused[/bold yellow] {_esc(refusal)}")

    text_parts, tool_calls, tool_results = _split_message(last)

    # 0. Extended-thinking summary (when adaptive thinking + display=summarized
    #    is on for this subagent). Dimmed + italic so it reads as the model's
    #    inner reasoning, distinct from its prose. Escaped like everything else.
    for thought in _thinking_parts(last):
        console.print(f"{prefix}  [dim italic]✻ {_esc(_short(thought, 320))}[/dim italic]")

    # 1. Prose from the model, one line per non-empty block.
    for text in text_parts:
        if text.strip():
            console.print(f"{prefix}  {_esc(_short(text))}")

    # 2. Tool dispatches. Per-tool formatters give compact, contextual lines
    #    (e.g. `surface ▸ ffuf http://target/FUZZ (common.txt)`). Hidden tools
    #    (write_episode/write_finding/write_todos/write_objective) suppress
    #    the dispatch line entirely — their result is what carries the signal.
    for call in tool_calls:
        name = str(call.get("name", "?"))
        args = call.get("input") or call.get("args") or {}
        formatted = _format_tool_call(name, args)
        if formatted is None:
            _set_inflight(name)
            continue  # Hidden tool — no call line, result will speak for itself.
        verb, label, arg_text = formatted
        verb_md = f"[dim] {verb} [/dim]" if verb else " [dim]▸[/dim] "
        console.print(f"{prefix}{verb_md}[cyan]{_esc(label)}[/cyan]  {_esc(arg_text)}")
        _set_inflight(name)

    # 3. Tool results. Specific renderers for the structured-output tools;
    #    everything else gets the clean `└─ name: <one-line>` form.
    for result in tool_results:
        name = str(result.get("name") or "tool")
        full = result.get("preview", "")
        if _render_tool_result(name, full):
            _set_inflight(None)
            continue
        # Generic fallback — short preview, no raw JSON dump.
        text = _generic_result_summary(full)
        console.print(f"[dim]  └─[/dim] [cyan]{_esc(name)}[/cyan]: {_esc(text)}")
        _set_inflight(None)


# Tools whose dispatch line is just noise — the result is what matters.
_HIDDEN_TOOL_CALLS = frozenset({
    "episodes__write_episode",
    "episodes__write_finding",
    "write_todos",
    "write_opplan",
})


def _format_tool_call(name: str, args) -> tuple[str, str, str] | None:
    """Map a tool dispatch to a compact `(verb, label, args)` triple, or
    `None` to suppress the dispatch line.

    Mirrors the Ink CLI's `formatToolCall` — keeps the contextual verbs
    ("scans", "fuzzes", "fingerprints") that read naturally, and falls
    through to the generic chevron form for everything else.
    """
    if name in _HIDDEN_TOOL_CALLS:
        return None

    a = args if isinstance(args, dict) else {}

    if name == "write_objective":
        # Render the objective as the dispatch line itself — there's no
        # meaningful "result" beyond `ok` so showing the call IS the value.
        objective = str(a.get("objective", "")).strip()
        return ("objective", "", objective or "(empty)")

    if name == "task":
        assignee = str(a.get("subagent_type") or a.get("agent") or "subagent")
        description = _strip_engagement_id_prefix(str(a.get("description", "")).strip())
        # Record the dispatch so subsequent subagent step events get
        # attributed to `assignee` instead of falling back to "orchestrator".
        _record_task_dispatch(assignee)
        return ("delegates to", assignee, _short(description, n=160))

    if name in {"surface__nmap_quick", "surface__nmap_full", "surface__nmap_udp"}:
        target = str(a.get("target", "target"))
        if name.endswith("udp"):
            ports = f"top {a['top_ports']} UDP" if a.get("top_ports") else "UDP"
        else:
            ports = f"top {a['top_ports']}" if a.get("top_ports") else (
                "quick" if name.endswith("quick") else "full"
            )
        scripts = f", scripts {a['scripts']}" if a.get("scripts") else ""
        return ("scans", "nmap", f"{target} ({ports}{scripts})")

    if name == "surface__httpx_fingerprint":
        targets = a.get("targets") or []
        preview = (
            str(targets[0]) if len(targets) == 1
            else f"{len(targets)} targets"
        )
        return ("fingerprints", "httpx", preview)

    if name == "surface__ffuf":
        url = str(a.get("url", ""))
        wl = str(a.get("wordlist", "")).rsplit("/", 1)[-1] or "wordlist"
        exts = a.get("extensions") or []
        ext_text = f", extensions {','.join(exts)}" if exts else ""
        return ("fuzzes", "ffuf", f"{url} ({wl}{ext_text})")

    if name == "surface__vhost_enum":
        base = str(a.get("base_url", ""))
        wl = str(a.get("wordlist", "")).rsplit("/", 1)[-1] or "wordlist"
        return ("fuzzes vhosts", "vhost_enum", f"{base} ({wl})")

    if name == "surface__web_intake":
        return ("profiles", "web_intake", str(a.get("url", "")))

    if name == "surface__smb_enum":
        target = str(a.get("target", ""))
        port = a.get("port")
        suffix = f" (:{port})" if port and port != 445 else ""
        return ("enumerates SMB", "smb_enum", f"{target}{suffix}")

    if name == "surface__service_triage":
        target = str(a.get("target", ""))
        svcs = a.get("services") or []
        suffix = f" ({len(svcs)} service{'' if len(svcs) == 1 else 's'})" if svcs else ""
        return ("triages services", "service_triage", f"{target}{suffix}")

    if name == "research__exploitdb_fetch":
        return ("fetches", "exploit-db", str(a.get("edb_id_or_url", "")))
    if name == "research__cve_lookup":
        q = a.get("cve_id") or " ".join(str(x) for x in (a.get("product"), a.get("version")) if x)
        return ("looks up", "CVEs", str(q))
    if name == "research__vendor_advisory_search":
        return ("searches", "advisories", str(a.get("cve_id") or a.get("product") or ""))
    if name == "research__epss_lookup":
        ids = a.get("cve_ids") or []
        return ("scores", "EPSS", ", ".join(map(str, ids[:3])) + (" …" if len(ids) > 3 else ""))
    if name == "research__cisa_kev_lookup":
        ids = a.get("cve_ids") or []
        return ("checks", "CISA KEV", str(a.get("query") or ", ".join(map(str, ids))))
    if name == "research__web_search":
        return ("searches", "web", str(a.get("query", "")))
    if name == "research__github_poc_search":
        return ("searches", "github POCs", str(a.get("query", "")))
    if name == "research__fetch_poc":
        return ("fetches", "POC", str(a.get("url_or_repo", "")))
    if name == "research__poc_static_review":
        return ("reviews POCs", "", f"{len(a.get('files') or [])} file(s)")
    if name == "research__affected_version_check":
        return ("checks version", str(a.get("current_version", "")), str(a.get("product") or ""))

    if name == "surface__curl":
        method = str(a.get("method") or "GET").upper()
        url = str(a.get("url", ""))
        return ("", "curl", f"{method} {url}")

    if name == "shell__run_oneshot":
        cmd = str(a.get("command", "")).strip()
        return ("$", cmd.split(None, 1)[0] or "shell", _short(cmd, n=120))

    if name == "shell__start_listener":
        kind = str(a.get("kind", ""))
        port = a.get("port", "?")
        sess = str(a.get("session_name", ""))
        return ("listener", kind, f"port {port} → {sess}")

    if name == "shell__tmux_new_session":
        return ("opens session", str(a.get("name", "?")), "")

    if name in {"shell__tmux_send", "shell__tmux_exec"}:
        session = str(a.get("session_name", "?"))
        cmd = str(a.get("command", "")).strip()
        return ("$", session, _short(cmd, n=120))

    if name == "shell__tmux_read":
        return ("reads", str(a.get("session_name", "?")),
                f"timeout {a.get('timeout_s', '?')}s")

    if name == "shell__http_json_request":
        method = str(a.get("method") or "POST").upper()
        url = str(a.get("url") or "")
        return ("http", method, url)

    if name in {"mark_host_owned", "mark_host_skipped", "mark_host_dead"}:
        host = str(a.get("host", "?"))
        verb = name.replace("mark_host_", "")
        return ("marks", host, verb)

    if name == "record_flag":
        return ("captures flag", "", str(a.get("flag", "?")))

    # Generic fallback
    arg_text = _short(_format_args(a), n=120)
    return ("", name, f"({arg_text})")


def _render_tool_result(name: str, content: str) -> bool:
    """Dispatch to a tool-specific result renderer. Return True if handled."""
    if name == "write_todos":
        return _render_todo_list(content)
    if name == "write_opplan":
        return _render_opplan(content)
    if name in {"episodes__write_episode", "episodes__write_finding",
                "write_objective"}:
        return True  # Silent — the call line already conveyed it.
    if name == "write_objective":
        return True
    if name.startswith("shell__tmux_"):
        return _render_shell_tmux_output(name, content)
    if name == "shell__run_oneshot":
        return _render_run_oneshot_result(content)
    if name == "shell__http_json_request":
        return _render_http_json_request_result(content)
    if name in {"surface__nmap_quick", "surface__nmap_full", "surface__nmap_udp"}:
        return _render_nmap_result(content)
    if name == "surface__ffuf":
        return _render_ffuf_result(content)
    if name == "surface__nuclei":
        return _render_nuclei_result(content)
    if name == "surface__vhost_enum":
        return _render_vhost_result(content)
    if name == "surface__httpx_fingerprint":
        return _render_httpx_result(content)
    if name == "surface__curl":
        return _render_curl_result(content)
    if name == "surface__web_intake":
        return _render_web_intake_result(content)
    if name == "surface__smb_enum":
        return _render_smb_enum_result(content)
    if name == "surface__service_triage":
        return _render_service_triage_result(content)
    if name.startswith("research__"):
        return _render_research_result(name, content)
    if name in {"postex__linux_basic_enum", "postex__windows_basic_enum",
                "postex__loot_credentials"}:
        return _render_postex_cmd_sweep(name, content)
    if name == "postex__suid_enum":
        return _render_postex_suid_result(content)
    if name == "postex__kernel_suggester":
        return _render_postex_kernel_result(content)
    if name == "postex__linpeas":
        return _render_postex_linpeas_result(content)
    if name == "task":
        return _render_task_result(content)
    return False


def _generic_result_summary(content: str) -> str:
    """One-line summary of a generic tool result.

    Tries `ok`/`error`/`status` field detection; falls back to a short
    truncated preview. Used for tools without a dedicated renderer."""
    if not content:
        return "(no output)"
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return _short(str(content).replace("\n", " "), n=160)
    if isinstance(data, dict):
        if data.get("ok") is True:
            # Compact "ok" with the most informative scalar field if there is one.
            for key in ("status", "count", "path", "session_name"):
                if key in data:
                    return f"ok ({key}={data[key]})"
            return "ok"
        if data.get("ok") is False:
            return f"error: {data.get('error', '(unspecified)')}"
        return _short(json.dumps(data), n=160)
    return _short(str(data), n=160)


# Status → display glyph + color for the todo checklist.
_TODO_STATUS_DISPLAY = {
    "completed":   ("[green]✓[/green]", "green"),
    "in_progress": ("[yellow]◐[/yellow]", "yellow"),
    "pending":     ("[dim]○[/dim]", "white"),
    "cancelled":   ("[red]✗[/red]", "dim"),
    "blocked":     ("[red]‼[/red]", "red"),
}


def _render_todo_list(content: str) -> bool:
    """If `content` is a write_todos result, render the embedded list as a
    checklist and return True. Otherwise return False so the caller falls
    back to the generic truncated preview.

    The TodoListMiddleware returns content shaped like:
        Updated todo list to [{'content': '...', 'status': 'pending'}, ...]
    We extract the bracketed Python literal and `ast.literal_eval` it
    (json doesn't accept single-quoted strings).
    """
    import ast  # noqa: PLC0415
    import re  # noqa: PLC0415

    match = re.search(r"\[\s*\{.*\}\s*\]", content, flags=re.DOTALL)
    if not match:
        return False
    try:
        todos = ast.literal_eval(match.group(0))
    except (ValueError, SyntaxError):
        return False
    if not isinstance(todos, list) or not todos:
        return False

    console.print("[dim]✓[/dim] [cyan]write_todos[/cyan] updated the plan:")
    for item in todos:
        if not isinstance(item, dict):
            console.print(f"   • {_esc(str(item))}")
            continue
        status = str(item.get("status", "pending"))
        text = str(item.get("content", ""))
        glyph, _ = _TODO_STATUS_DISPLAY.get(
            status, ("[dim]•[/dim]", "white")
        )
        console.print(f"   {glyph} {_esc(text)}  [dim]({_esc(status)})[/dim]")
    return True


# Status → glyph for OPPLAN phases (write_opplan; distinct vocabulary from todos).
_OPPLAN_STATUS_DISPLAY = {
    "done":    "[green]✓[/green]",
    "active":  "[yellow]◐[/yellow]",
    "pending": "[dim]○[/dim]",
    "dead":    "[red]✗[/red]",
}


def _render_opplan(content: str) -> bool:
    """Render a write_opplan result: mission + phased plan. Returns True if
    handled, else False so the caller falls back to the generic preview.

    The tool's ToolMessage is `Updated OPPLAN to {json}` (see opplan.py
    _opplan_update); extract and parse that JSON payload.
    """
    import re  # noqa: PLC0415

    match = re.search(r"\{.*\}", content, flags=re.DOTALL)
    if not match:
        return False
    try:
        plan = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(plan, dict):
        return False
    phases = plan.get("phases")
    if not isinstance(phases, list) or not phases:
        return False

    mission = str(plan.get("mission", "")).strip()
    head = f"  [dim]—[/dim] {_esc(mission)}" if mission else ""
    console.print(f"[dim]✓[/dim] [cyan]OPPLAN[/cyan]{head}")
    for ph in phases:
        if not isinstance(ph, dict):
            console.print(f"   • {_esc(str(ph))}")
            continue
        status = str(ph.get("status", "pending"))
        glyph = _OPPLAN_STATUS_DISPLAY.get(status, "[dim]•[/dim]")
        label = str(ph.get("phase", "?"))
        intent = str(ph.get("intent", "")).replace("\n", " ")
        console.print(f"   {glyph} [bold]{_esc(label)}[/bold]  {_esc(_short(intent, n=140))}")
        decision = str(ph.get("decision", "")).replace("\n", " ")
        if decision:
            console.print(f"       [dim]→ {_esc(_short(decision, n=150))}[/dim]")
    return True


_SHELL_TMUX_MAX_LINES = 80


def _normalize_tool_content(content) -> str:
    """Flatten MCP tool content to a string.

    MCP tool results arrive as a list of Anthropic content blocks —
    `[{"type": "text", "text": "<actual payload>"}]` — not as a bare
    string. `str()` on that list produces the Python repr (`[{'type': ...`)
    which then defeats any downstream JSON parsing. Concatenate the text
    blocks instead.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
            else:
                parts.append(str(block))
        return "".join(parts)
    return str(content)


def _render_shell_tmux_output(name: str, content: str) -> bool:
    """Render shell__tmux_* results as a Panel that preserves newlines.

    The MCP shell server returns JSON: {"ok": true, "output": "..."}
    We extract the output and show it verbatim so the operator can read
    tmux panes without single-line truncation mangling multi-line output.

    Returns True if rendered, False to fall back to the generic preview.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    output = data.get("output", "")
    if not isinstance(output, str) or not output.strip():
        # Only an explicit `ok: False` is an error. Many tmux tools succeed
        # without an `output` field — `tmux_list_sessions` returns
        # `{"sessions": [...]}` — so a *missing* `ok` is not a failure.
        if data.get("ok") is False:
            err = _short(str(data.get("error", "(unspecified)")), n=160)
            console.print(
                f"[dim]✓[/dim] [cyan]{_esc(name)}[/cyan] returned: [red]error[/red]: {_esc(err)}"
            )
        elif isinstance(data.get("sessions"), list):
            sessions = data["sessions"]
            names = ", ".join(
                str(s.get("name", "?")) for s in sessions if isinstance(s, dict)
            )
            summary = f"{len(sessions)} session(s)" + (f": {names}" if names else "")
            console.print(
                f"[dim]✓[/dim] [cyan]{_esc(name)}[/cyan] returned: {_esc(summary)}"
            )
        else:
            console.print(
                f"[dim]✓[/dim] [cyan]{_esc(name)}[/cyan] returned: [green]ok[/green]"
            )
        return True
    lines = output.splitlines()
    omitted = max(0, len(lines) - _SHELL_TMUX_MAX_LINES)
    visible = lines[-_SHELL_TMUX_MAX_LINES:] if omitted else lines
    # Render as a Text (never parsed as markup). Per-line `_esc` is NOT safe
    # here: tmux wraps long prompts mid-bracket (e.g. `[/` at the column limit,
    # `app]` on the next line), and Rich's markup parser matches tags ACROSS
    # newlines — so an escaped-then-joined body can still re-form a stray tag
    # like `[/\napp]` and raise MarkupError. Text sidesteps markup entirely.
    body = Text("\n".join(visible))
    if omitted:
        body = Text.assemble(
            Text(f"… {omitted} earlier lines omitted …\n", style="dim"), body
        )
    console.print(f"[dim]✓[/dim] [cyan]{_esc(name)}[/cyan] returned:")
    console.print(Panel(body, expand=False, padding=(0, 1)))
    return True


_HTTP_JSON_BODY_PREVIEW_CHARS = 400
_HTTP_JSON_REDACT_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}


def _redact_http_json_headers(headers: dict) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        skey = str(key)
        if skey.lower() in _HTTP_JSON_REDACT_HEADER_KEYS:
            redacted[skey] = "[redacted]"
        else:
            redacted[skey] = str(value)
    return redacted


def _render_http_json_request_result(content: str) -> bool:
    """Render shell__http_json_request with the HTTP status and body preview.

    The generic renderer collapses any {"ok": true, ...} payload to just "ok",
    which hides the actual request outcome from the operator. This keeps the
    live interface compact while still surfacing 4xx/5xx bodies such as
    Flowise's SQLITE_BUSY errors.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(
            f"[dim]  └─[/dim] [red]http[/red]: {_esc(str(data.get('error', 'request failed')))}"
        )
        return True

    status = str(data.get("status_code", "?"))
    col = _status_color(status)
    elapsed = data.get("elapsed_ms")
    meta = f" in {elapsed}ms" if isinstance(elapsed, int) else ""
    suffix = " [dim](body truncated)[/dim]" if data.get("body_truncated") else ""
    console.print(
        f"[dim]  └─[/dim] [cyan]http[/cyan]: [{col} bold]{_esc(status)}[/{col} bold]{_esc(meta)}{suffix}"
    )

    body = data.get("body")
    if isinstance(body, str) and body.strip():
        console.print(
            f"      [dim]body:[/dim] {_esc(_short(body, n=_HTTP_JSON_BODY_PREVIEW_CHARS))}"
        )

    headers = data.get("headers")
    if isinstance(headers, dict):
        redacted = _redact_http_json_headers(headers)
        interesting = {
            k: v for k, v in redacted.items()
            if k.lower() in {"content-type", "content-length", "location", "set-cookie"}
        }
        if interesting:
            console.print(
                f"      [dim]headers:[/dim] {_esc(json.dumps(interesting, sort_keys=True))}"
            )
    return True


# ---------------------------------------------------------------------------
# Per-tool result renderers (mirror Ink's nmapResultEntries, ffufResultEntries
# etc. — compact structured output instead of raw JSON).
# ---------------------------------------------------------------------------


def _status_color(code) -> str:
    try:
        n = int(code)
    except (TypeError, ValueError):
        return "white"
    if n >= 500: return "red"
    if n >= 400: return "yellow"
    if n >= 300: return "cyan"
    if n >= 200: return "green"
    return "white"


def _render_nmap_result(content: str) -> bool:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]nmap[/red]: {_esc(str(data.get('error','scan failed')))}")
        return True
    hosts = data.get("hosts") or []
    total_open = sum(len(h.get("ports") or []) for h in hosts if isinstance(h, dict))
    if total_open == 0:
        console.print("[dim]  └─[/dim] [cyan]nmap[/cyan]: no open ports")
        return True
    plural = "" if total_open == 1 else "s"
    console.rule(f"[cyan]nmap found {total_open} open port{plural}[/cyan]", align="left")
    for host in hosts:
        if not isinstance(host, dict): continue
        addr = host.get("address") or ""
        if addr and len(hosts) > 1:
            console.print(f"  [dim]{_esc(addr)}[/dim]")
        for port in host.get("ports") or []:
            if not isinstance(port, dict): continue
            p = str(port.get("port", "?"))
            proto = port.get("protocol") or "tcp"
            service = port.get("service") or "unknown"
            detail = " ".join(filter(None, [
                port.get("product"), port.get("version"), port.get("extrainfo"),
            ]))
            console.print(
                f"  [green bold]{p:>5}[/green bold][dim]/{proto}[/dim] "
                f"[cyan]{_esc(str(service)[:12]):<12}[/cyan] [dim]{_esc(detail)}[/dim]"
            )
            for script in port.get("scripts") or []:
                if not isinstance(script, dict): continue
                out = str(script.get("output", "")).split("\n", 1)[0].strip()
                if any(k in out.upper() for k in ("CVE-", "VULNERABLE", "EXPLOIT")):
                    sid = script.get("id", "")
                    console.print(f"      [dim]{_esc(sid)}: {_esc(out[:160])}[/dim]")
    return True


def _render_ffuf_result(content: str) -> bool:
    if content.startswith("FFUF_BUDGET_EXHAUSTED"):
        console.print(
            "[yellow]  └─ ffuf budget exhausted for this web root; "
            "pivoting away from directory fuzzing.[/yellow]"
        )
        return True
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        msg = data.get("error") or data.get("stderr") or "failed"
        console.print(f"[dim]  └─[/dim] [red]ffuf[/red]: {_esc(str(msg))}")
        return True
    results = data.get("results") or []
    if not results:
        console.print("[dim]  └─[/dim] [dim]ffuf found no matching paths[/dim]")
        return True
    n = len(results)
    plural = "" if n == 1 else "s"
    console.rule(f"[cyan]ffuf found {n} path{plural}[/cyan]", align="left")
    for row in results[:25]:
        if not isinstance(row, dict): continue
        status = str(row.get("status") or row.get("status-code") or "-")
        url = row.get("url") or (row.get("input") or {}).get("FUZZ", "")
        length = row.get("length")
        detail = f"  [dim]{length} bytes[/dim]" if length is not None else ""
        col = _status_color(status)
        console.print(f"  [{col} bold]{status:>3}[/{col} bold]  {_esc(str(url))}{detail}")
    if n > 25:
        console.print(f"  [dim]… {n - 25} more paths omitted[/dim]")
    return True


# nuclei severity → display color, worst to least.
_NUCLEI_SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
    "unknown": "white",
}
_NUCLEI_ROW_CAP = 25


def _render_nuclei_result(content: str) -> bool:
    """Render surface__nuclei — template-vuln-scan matches as a severity-ranked
    list. Three shapes: a hard error, a benign 0-template-match (with guidance),
    and a list of findings."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        msg = data.get("error") or data.get("stderr") or "failed"
        console.print(f"[dim]  └─[/dim] [red]nuclei[/red]: {_esc(str(msg))}")
        return True
    findings = data.get("findings") or []
    target = str(data.get("target", ""))
    if not findings:
        # Benign empty — surface the guidance note if the filter matched nothing.
        note = data.get("note")
        if note:
            console.print(f"[dim]  └─[/dim] [yellow]nuclei: no templates matched[/yellow] — {_esc(str(note))}")
        else:
            console.print(f"[dim]  └─[/dim] [dim]nuclei found nothing on {_esc(target)}[/dim]")
        return True
    total = data.get("finding_count", len(findings))
    plural = "" if total == 1 else "s"
    console.rule(f"[cyan]nuclei: {total} finding{plural} on {_esc(target)}[/cyan]", align="left")
    for f in findings[:_NUCLEI_ROW_CAP]:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "unknown").lower()
        col = _NUCLEI_SEVERITY_COLOR.get(sev, "white")
        tid = str(f.get("template_id") or "?")
        name = str(f.get("name") or "")
        cve = f.get("cve")
        where = str(f.get("matched_at") or "")
        tail = f"  [dim]{_esc(_short(where, n=70))}[/dim]" if where else ""
        cve_tag = f"  [magenta]{_esc(str(cve))}[/magenta]" if cve else ""
        console.print(
            f"  [{col}]{sev:>8}[/{col}]  [bold]{_esc(tid)}[/bold]"
            f"{('  ' + _esc(_short(name, n=60))) if name else ''}{cve_tag}{tail}"
        )
    shown = min(len(findings), _NUCLEI_ROW_CAP)
    if total > shown:
        console.print(f"  [dim]… {total - shown} more finding(s) omitted (worst shown first)[/dim]")
    return True


def _render_httpx_result(content: str) -> bool:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return False
    results = data["results"]
    if not results:
        console.print("[dim]  └─[/dim] [dim]httpx found no live web targets[/dim]")
        return True
    n = len(results)
    plural = "" if n == 1 else "s"
    console.rule(f"[cyan]httpx fingerprinted {n} target{plural}[/cyan]", align="left")
    for row in results[:25]:
        if not isinstance(row, dict): continue
        status = str(row.get("status_code") or row.get("status-code") or "-")
        url = row.get("url") or row.get("input") or ""
        bits = []
        if row.get("title"): bits.append(str(row["title"]))
        for s in (row.get("server"), row.get("webserver")):
            if s: bits.append(str(s))
        tech = row.get("tech") or row.get("technologies") or []
        if isinstance(tech, list) and tech:
            bits.append(" | ".join(str(t) for t in tech[:5]))
        col = _status_color(status)
        detail = " | ".join(bits)
        console.print(
            f"  [{col} bold]{status:>3}[/{col} bold]  {_esc(str(url))}"
            f"  [dim]{_esc(detail)}[/dim]"
        )
    if n > 25:
        console.print(f"  [dim]… {n - 25} more targets omitted[/dim]")
    return True


# Per-line width cap for curl body previews — minified JS/CSS arrives as one
# multi-thousand-char line that the terminal soft-wraps into a wall of text.
_CURL_BODY_LINE_CHARS = 200

# Content-types whose bodies are static-asset noise (no recon signal) — show a
# size note instead of dumping the bytes.
_NOISE_CONTENT_TYPE_HINTS = (
    "javascript", "ecmascript", "css", "font", "image/", "audio/", "video/",
    "octet-stream", "application/wasm", "application/pdf", "application/zip",
    "x-protobuf",
)


def _is_noise_content_type(ctype: str) -> bool:
    return any(hint in ctype for hint in _NOISE_CONTENT_TYPE_HINTS)


def _render_curl_result(content: str) -> bool:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]curl[/red]: {_esc(str(data.get('error','failed')))}")
        return True
    status = str(data.get("status", "?"))
    reason = str(data.get("reason", ""))
    head = f"{status} {reason}".strip()
    col = _status_color(status)
    final_url = str(data.get("final_url", ""))
    meta_bits = []
    if (hops := data.get("hop_count", 1)) and hops > 1:
        meta_bits.append(f"{hops} hops")
    if (t := data.get("time_total_ms")) is not None:
        meta_bits.append(f"{t}ms")
    meta = f" [dim]({' · '.join(meta_bits)})[/dim]" if meta_bits else ""
    console.print(
        f"[dim]  └─[/dim] [{col} bold]{head}[/{col} bold]  {_esc(final_url)}{meta}"
    )
    headers = data.get("headers") or {}
    ctype = ""
    if isinstance(headers, dict):
        ct_key = next((k for k in headers if k.lower() == "content-type"), None)
        if ct_key:
            ctype = str(headers[ct_key]).lower()
        for key in ("Server", "Content-Type", "Location", "Set-Cookie",
                    "WWW-Authenticate", "X-Powered-By"):
            actual = next((k for k in headers if k.lower() == key.lower()), None)
            if actual:
                val = str(headers[actual])[:200]
                console.print(f"      [dim]{_esc(actual)}: {_esc(val)}[/dim]")
    body = str(data.get("body", ""))
    # Static assets (JS/CSS/fonts/images/binaries) carry no recon signal and
    # their minified one-liners blow up the terminal — note the size, skip the dump.
    if body.strip() and _is_noise_content_type(ctype):
        console.print(f"      [dim]{_esc(ctype.split(';')[0])} body, {len(body)} bytes (not shown)[/dim]")
        return True
    if body.strip():
        lines = body.splitlines()
        visible = lines[:15]
        for line in visible:
            # Cap each line so a single minified line can't flood the terminal.
            console.print(f"      {_esc(_short(line, n=_CURL_BODY_LINE_CHARS))}")
        omitted = len(lines) - len(visible)
        if omitted > 0 or data.get("body_truncated"):
            note = "body truncated" if data.get("body_truncated") else f"… {omitted} more lines omitted"
            console.print(f"      [dim]{note}[/dim]")
    return True


def _render_vhost_result(content: str) -> bool:
    """Render surface__vhost_enum — discovered virtual hosts (Host-header fuzzing).

    Shares ffuf's result shape `{results:[{fuzz,url,status,length,...}], ...}`,
    but the signal is the `fuzz` value (the vhost name), not the URL path.
    """
    if content.startswith("CURL_BUDGET_EXHAUSTED"):
        console.print("[yellow]  └─ vhost budget exhausted; returning findings.[/yellow]")
        return True
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        msg = data.get("error") or data.get("stderr") or "failed"
        console.print(f"[dim]  └─[/dim] [red]vhost_enum[/red]: {_esc(str(msg))}")
        return True
    results = data.get("results") or []
    if not results:
        console.print("[dim]  └─[/dim] [dim]vhost_enum found no distinct vhosts[/dim]")
        return True
    n = len(results)
    plural = "" if n == 1 else "s"
    console.rule(f"[cyan]vhost_enum found {n} vhost{plural}[/cyan]", align="left")
    for row in results[:25]:
        if not isinstance(row, dict):
            continue
        vhost = row.get("fuzz") or (row.get("input") or {}).get("FUZZ") or row.get("url") or ""
        status = str(row.get("status") or "-")
        length = row.get("length")
        words = row.get("words")
        bits = []
        if length is not None:
            bits.append(f"{length} bytes")
        if words is not None:
            bits.append(f"{words} words")
        detail = f"  [dim]{_esc(', '.join(bits))}[/dim]" if bits else ""
        col = _status_color(status)
        console.print(f"  [{col} bold]{status:>3}[/{col} bold]  {_esc(str(vhost))}{detail}")
    if n > 25:
        console.print(f"  [dim]… {n - 25} more vhosts omitted[/dim]")
    if data.get("truncated") and (total := data.get("total_matches")):
        console.print(f"  [dim](showing {n} of {total} matches; likely a wildcard — narrow the filter)[/dim]")
    return True


def _render_web_intake_result(content: str) -> bool:
    """Render surface__web_intake — compact one-shot HTTP recon of a web root."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]web_intake[/red]: {_esc(str(data.get('error', 'failed')))}")
        return True

    status = str(data.get("status", "?"))
    col = _status_color(status)
    final_url = str(data.get("final_url") or data.get("url") or "")
    title = str(data.get("title") or "")
    title_md = f"  [dim]{_esc(_short(title, n=80))}[/dim]" if title else ""
    console.rule(f"[cyan]web_intake[/cyan] [{col} bold]{status}[/{col} bold] {_esc(final_url)}", align="left")
    if title_md:
        console.print(f"      [white]{_esc(_short(title, n=120))}[/white]")

    server = str(data.get("server") or "")
    ctype = str(data.get("content_type") or "")
    srv_bits = " · ".join(b for b in (server, ctype) if b)
    if srv_bits:
        console.print(f"      [dim]{_esc(srv_bits)}[/dim]")

    def _line(label: str, items, cap: int = 8) -> None:
        if not items:
            return
        if isinstance(items, list):
            shown = [str(x) for x in items[:cap]]
            extra = f" [dim]+{len(items) - cap} more[/dim]" if len(items) > cap else ""
            console.print(f"      [cyan]{label}[/cyan]: {_esc(', '.join(shown))}{extra}")
        else:
            console.print(f"      [cyan]{label}[/cyan]: {_esc(str(items))}")

    _line("tech", data.get("technologies"))
    _line("cookies", data.get("cookie_names"))
    _line("interesting", data.get("interesting_paths"))
    forms = data.get("forms") or []
    if forms:
        actions = [str((f or {}).get("action") or "?") for f in forms if isinstance(f, dict)]
        _line(f"forms ({len(forms)})", actions or None)
    _line("hints", data.get("body_hints"))

    probes = data.get("probes") or {}
    if isinstance(probes, dict):
        probe_bits = []
        for key in ("robots", "sitemap", "favicon"):
            p = probes.get(key)
            if isinstance(p, dict) and p.get("status") is not None:
                st = str(p.get("status"))
                if st.isdigit() and int(st) < 400:
                    probe_bits.append(f"{key} {st}")
        if probe_bits:
            console.print(f"      [dim]probes: {_esc(', '.join(probe_bits))}[/dim]")
    return True


def _render_smb_enum_result(content: str) -> bool:
    """Render surface__smb_enum — shares, anonymous-readable loot, null-session users.

    The recon payoff for SMB boxes: an anon-readable share holding a creds file,
    or a null session leaking the user list. Surface the readable shares (and
    their files) and the enumerated users prominently — that's the foothold.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]smb_enum[/red]: {_esc(str(data.get('error', 'failed')))}")
        hint = data.get("hint")
        if hint:
            console.print(f"      [dim]{_esc(_short(str(hint), n=200))}[/dim]")
        return True

    shares = data.get("shares") or []
    readable = data.get("anonymous_readable_shares") or []
    contents = data.get("readable_share_contents") or {}
    users = data.get("null_session_users") or []

    console.rule(
        f"[cyan]smb_enum[/cyan] [dim]{_esc(str(data.get('target', '')))}[/dim] "
        f"— {len(shares)} share(s), {len(readable)} anon-readable, {len(users)} user(s)",
        align="left",
    )

    # Shares, with access color — readable ones are the prize.
    _access_col = {"read": "green bold", "denied": "red", "skipped": "dim"}
    for sh in shares:
        if not isinstance(sh, dict):
            continue
        access = str(sh.get("access") or "?")
        col = _access_col.get(access, "yellow")
        comment = str(sh.get("comment") or "")
        cmt = f"  [dim]{_esc(_short(comment, n=50))}[/dim]" if comment else ""
        console.print(
            f"  [{col}]{access:>7}[/{col}]  [white]{_esc(str(sh.get('name', '?')))}[/white]"
            f"  [dim]{_esc(str(sh.get('type', '')))}[/dim]{cmt}"
        )

    # Files inside each readable share — this is where the loot file shows up.
    for name, files in contents.items():
        if not isinstance(files, list) or not files:
            continue
        console.print(f"      [green]//{_esc(str(name))}[/green]:")
        for f in files[:15]:
            console.print(f"        [dim]{_esc(_short(str(f), n=110))}[/dim]")
        if len(files) > 15:
            console.print(f"        [dim]… {len(files) - 15} more[/dim]")

    if users:
        shown = ", ".join(str(u) for u in users[:20])
        extra = f" [dim]+{len(users) - 20} more[/dim]" if len(users) > 20 else ""
        console.print(f"      [cyan]users[/cyan]: {_esc(shown)}{extra}")
    return True


def _render_service_triage_result(content: str) -> bool:
    """Render surface__service_triage — read-only exposure checks per service.

    Lead with the confirmed exposures (anon FTP, SMB null listing, open Redis,
    etc.) since those are the actionable signal; fall back to "no exposures" so
    the operator sees the check ran and found nothing rather than a bare `ok`.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]service_triage[/red]: {_esc(str(data.get('error', 'failed')))}")
        return True

    exposures = data.get("exposures") or []
    checks = data.get("checks") or []
    target = str(data.get("target", ""))

    if not exposures:
        n = len(checks)
        console.print(
            f"[dim]  └─[/dim] [cyan]service_triage[/cyan] [dim]{_esc(target)}[/dim]: "
            f"no anonymous/default exposure across {n} check{'' if n == 1 else 's'}"
        )
        return True

    n = len(exposures)
    console.rule(
        f"[yellow]service_triage[/yellow] [dim]{_esc(target)}[/dim] "
        f"— {n} exposure{'' if n == 1 else 's'}",
        align="left",
    )
    for exp in exposures:
        if not isinstance(exp, dict):
            continue
        kind = str(exp.get("kind") or "?")
        port = str(exp.get("port") or "?")
        summary = str(exp.get("summary") or "")
        console.print(
            f"  [yellow bold]{kind:>14}[/yellow bold][dim]:{port}[/dim]  "
            f"[white]{_esc(_short(summary, n=90))}[/white]"
        )
        evidence = exp.get("evidence")
        if evidence:
            for line in str(evidence).splitlines()[:4]:
                if line.strip():
                    console.print(f"        [dim]{_esc(_short(line.strip(), n=110))}[/dim]")
    return True


def _short_name(name: str) -> str:
    """Strip the `server__` prefix for display (postex__suid_enum → suid_enum)."""
    return name.split("__", 1)[-1]


def _render_postex_cmd_sweep(name: str, content: str) -> bool:
    """Render the enum sweeps that return {results: [{cmd, output}], warning?}.

    Covers linux_basic_enum, windows_basic_enum, loot_credentials. Shows each
    command with a few lines of its captured output so the operator sees the
    actual enum signal (id, sudo -l, SUIDs, creds) instead of a bare `ok`.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    short = _short_name(name)
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]{_esc(short)}[/red]: {_esc(str(data.get('error', 'failed')))}")
        return True

    results = data.get("results") or []
    console.rule(f"[magenta]{_esc(short)}[/magenta] — {len(results)} command(s)", align="left")
    for item in results:
        if not isinstance(item, dict):
            continue
        cmd = str(item.get("cmd", ""))
        out = str(item.get("output", "")).strip()
        console.print(f"  [cyan]${_esc(_short(cmd, n=90))}[/cyan]")
        if not out:
            console.print("      [dim](no output)[/dim]")
            continue
        lines = out.splitlines()
        for line in lines[:8]:
            # emoji=False: captured output (passwd/shadow) is full of `:x:`-style
            # colons that rich would otherwise turn into emoji.
            console.print(f"      [dim]{_esc(_short(line, n=140))}[/dim]", emoji=False)
        if len(lines) > 8:
            console.print(f"      [dim]… {len(lines) - 8} more line(s)[/dim]")

    warning = data.get("warning")
    if warning:
        console.print(f"  [yellow]⚠ {_esc(_short(str(warning), n=200))}[/yellow]")
    return True


def _render_postex_suid_result(content: str) -> bool:
    """Render postex__suid_enum — lead with GTFOBins privesc candidates."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]suid_enum[/red]: {_esc(str(data.get('error', 'failed')))}")
        return True

    suids = data.get("suids_found") or []
    candidates = data.get("privesc_candidates") or []
    console.rule(
        f"[magenta]suid_enum[/magenta] — {len(suids)} SUID binary(ies), "
        f"{len(candidates)} privesc candidate(s)",
        align="left",
    )
    for c in candidates:
        if not isinstance(c, dict):
            continue
        console.print(
            f"  [yellow bold]{_esc(str(c.get('binary', '?')))}[/yellow bold] "
            f"[dim]{_esc(str(c.get('path', '')))}[/dim]"
        )
        console.print(f"      [white]{_esc(_short(str(c.get('technique', '')), n=160))}[/white]")
    if not candidates and suids:
        for path in suids[:20]:
            console.print(f"  [dim]{_esc(str(path))}[/dim]")
        if len(suids) > 20:
            console.print(f"  [dim]… {len(suids) - 20} more[/dim]")
    if data.get("warning"):
        console.print(f"  [yellow]⚠ {_esc(_short(str(data['warning']), n=200))}[/yellow]")
    return True


def _render_postex_kernel_result(content: str) -> bool:
    """Render postex__kernel_suggester — uname banner + candidate kernel CVEs."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]kernel_suggester[/red]: {_esc(str(data.get('error', 'failed')))}")
        return True

    suggestions = data.get("suggestions") or []
    console.rule(
        f"[magenta]kernel_suggester[/magenta] — {len(suggestions)} suggestion(s)",
        align="left",
    )
    banner = str(data.get("uname", "")).strip()
    if banner:
        console.print(f"  [dim]{_esc(_short(banner, n=160))}[/dim]")
    for s in suggestions:
        if not isinstance(s, dict):
            continue
        console.print(
            f"  [yellow bold]{_esc(str(s.get('cve', '?')))}[/yellow bold] "
            f"[white]{_esc(str(s.get('name', '')))}[/white] "
            f"[dim]({_esc(str(s.get('kernels', '')))})[/dim]"
        )
        verify = s.get("verify")
        if verify:
            console.print(f"      [cyan]verify:[/cyan] [dim]{_esc(str(verify))}[/dim]")
    return True


def _render_postex_linpeas_result(content: str) -> bool:
    """Render postex__linpeas — the grepped PE highlight lines.

    linpeas returns {ok, output, warning?} where `output` is the highlighted
    leads (NOPASSWD, SUID, CVEs, writable paths…). Show those lines instead of
    collapsing the whole report to a bare `ok`.
    """
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]linpeas[/red]: {_esc(str(data.get('error', 'failed')))}")
        return True

    out = str(data.get("output", "")).strip()
    if "LINPEAS_FETCH_FAILED" in out:
        console.print(
            "[dim]  └─[/dim] [yellow]linpeas[/yellow]: no source reachable "
            "[dim](stage on Kali, re-call with url=)[/dim]"
        )
        return True

    lines = [ln for ln in out.splitlines() if ln.strip()]
    console.rule(f"[magenta]linpeas[/magenta] — {len(lines)} highlight line(s)", align="left")
    for ln in lines[:60]:
        # emoji=False: linpeas leads are full of `:` (paths, version strings)
        # that rich would otherwise turn into emoji.
        console.print(f"  [dim]{_esc(_short(ln.strip(), n=160))}[/dim]", emoji=False)
    if len(lines) > 60:
        console.print(f"  [dim]… {len(lines) - 60} more — grep /tmp/linpeas.out[/dim]")
    return True


def _render_research_result(name: str, content: str) -> bool:
    """Render research MCP tool results (CVE / advisory / POC lookups).

    One dispatcher for all `research__*` tools so the researcher's reading is
    visible instead of a bare `ok`.
    """
    short = name.split("__", 1)[-1]
    if content.startswith("RESEARCH_BUDGET_EXHAUSTED"):
        console.print("[yellow]  └─ research budget exhausted; synthesize and return.[/yellow]")
        return True
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]{_esc(short)}[/red]: {_esc(str(data.get('error', 'failed')))}")
        return True

    def kv(label: str, items, cap: int = 6) -> None:
        if not items:
            return
        if isinstance(items, (list, tuple)):
            shown = [str(x) for x in items[:cap]]
            extra = f" [dim]+{len(items) - cap} more[/dim]" if len(items) > cap else ""
            console.print(f"      [cyan]{_esc(label)}[/cyan]: {_esc(', '.join(shown))}{extra}")
        else:
            console.print(f"      [cyan]{_esc(label)}[/cyan]: {_esc(str(items))}")

    if short == "exploitdb_fetch":
        hints = data.get("hints") or {}
        size = data.get("size_chars")
        trunc = " · truncated" if data.get("truncated") else ""
        console.rule(
            f"[cyan]exploit-db {_esc(str(data.get('edb_id', '?')))}[/cyan]  [dim]{size} chars{trunc}[/dim]",
            align="left",
        )
        kv("CVEs", hints.get("cves"))
        flags = [k.replace("mentions_", "").replace("has_", "")
                 for k in ("has_usage", "mentions_reverse_shell", "mentions_auth")
                 if hints.get(k)]
        if flags:
            console.print(f"      [dim]signals: {_esc(', '.join(flags))}[/dim]")
        for ln in str(hints.get("first_lines") or "").splitlines()[:15]:
            console.print(f"      [dim]{_esc(ln)}[/dim]")
        return True

    if short == "cve_lookup":
        results = data.get("results") or []
        total = data.get("total_results")
        n = len(results)
        suffix = f" [dim](of {total})[/dim]" if total else ""
        console.rule(f"[cyan]NVD: {n} CVE{'' if n == 1 else 's'}[/cyan]{suffix}", align="left")
        for r in results[:8]:
            if not isinstance(r, dict):
                continue
            cvss = r.get("cvss") or {}
            score = cvss.get("base_score")
            sev = cvss.get("base_severity") or cvss.get("severity") or ""
            col = "red" if isinstance(score, (int, float)) and score >= 7 else "yellow"
            score_md = f"[{col}]{score}[/{col}]" if score is not None else "-"
            console.print(f"  [bold]{_esc(str(r.get('id', '?')))}[/bold]  [dim]CVSS[/dim] {score_md} [dim]{_esc(str(sev))}[/dim]")
            desc = str(r.get("description") or "").replace("\n", " ")
            if desc:
                console.print(f"      [dim]{_esc(_short(desc, n=170))}[/dim]")
            kv("CWE", r.get("weaknesses"), cap=4)
        if n > 8:
            console.print(f"  [dim]… {n - 8} more[/dim]")
        return True

    if short == "vendor_advisory_search":
        ghs = data.get("github_advisories") or []
        nvd = data.get("nvd_references") or []
        console.rule(f"[cyan]advisories: {len(ghs)} GHSA · {len(nvd)} NVD refs[/cyan]", align="left")
        for adv in ghs[:6]:
            if not isinstance(adv, dict):
                continue
            ident = adv.get("ghsa_id") or adv.get("cve_id") or "?"
            sev = adv.get("severity") or ""
            console.print(f"  [bold]{_esc(str(ident))}[/bold] [dim]{_esc(str(sev))}[/dim]  {_esc(str(adv.get('url') or ''))}")
            ranges = [str((af or {}).get("vulnerable_version_range") or "")
                      for af in (adv.get("affected") or []) if isinstance(af, dict)]
            kv("affected", [r for r in ranges if r], cap=4)
        for ref in nvd[:6]:
            if isinstance(ref, dict) and ref.get("url"):
                console.print(f"  [dim]{_esc(str(ref.get('cve') or ''))}[/dim] {_esc(str(ref['url']))}")
        return True

    if short == "epss_lookup":
        results = data.get("results") or []
        console.rule(f"[cyan]EPSS: {len(results)} CVE{'' if len(results) == 1 else 's'}[/cyan]", align="left")
        for r in results:
            if not isinstance(r, dict):
                continue
            try:
                pct = f"{float(r.get('epss', 0)) * 100:.1f}%"
            except (TypeError, ValueError):
                pct = str(r.get("epss"))
            try:
                perc = f"{float(r.get('percentile', 0)) * 100:.0f}th pct"
            except (TypeError, ValueError):
                perc = ""
            console.print(f"  [bold]{_esc(str(r.get('cve', '?')))}[/bold]  [yellow]{pct}[/yellow] [dim]{perc}[/dim]")
        return True

    if short == "cisa_kev_lookup":
        known = data.get("known_exploited")
        results = data.get("results") or []
        head = "[red bold]KNOWN EXPLOITED[/red bold]" if known else "[dim]not in CISA KEV[/dim]"
        console.print(f"[dim]  └─[/dim] CISA KEV: {head} [dim]({len(results)} match)[/dim]")
        for r in results[:6]:
            if not isinstance(r, dict):
                continue
            rw = " [red](ransomware)[/red]" if str(r.get("known_ransomware_campaign_use", "")).lower() == "known" else ""
            console.print(f"  [bold]{_esc(str(r.get('cve', '?')))}[/bold]  {_esc(str(r.get('vulnerability_name') or r.get('product') or ''))}{rw}")
        return True

    if short == "github_poc_search":
        results = data.get("results") or []
        console.rule(f"[cyan]github POCs: {len(results)}[/cyan] [dim](of {data.get('total_count', '?')})[/dim]", align="left")
        for r in results[:8]:
            if not isinstance(r, dict):
                continue
            stars = r.get("stars")
            lang = r.get("language") or ""
            flags = r.get("red_flags") or []
            flag_md = f"  [red]⚠ {_esc(', '.join(map(str, flags)))}[/red]" if flags else ""
            console.print(f"  [bold]{_esc(str(r.get('full_name', '?')))}[/bold] [dim]★{stars} {_esc(str(lang))}[/dim]{flag_md}")
        return True

    if short == "fetch_poc":
        files = data.get("files") or []
        console.rule(f"[cyan]fetched {data.get('file_count', len(files))} POC file(s)[/cyan]", align="left")
        for f in files:
            if not isinstance(f, dict):
                continue
            trunc = " · truncated" if f.get("truncated") else ""
            console.print(f"  [bold]{_esc(str(f.get('path') or f.get('url') or '?'))}[/bold] [dim]{f.get('size_chars', '?')} chars{trunc}[/dim]")
            for ln in str(f.get("content") or "").splitlines()[:8]:
                console.print(f"      [dim]{_esc(ln)}[/dim]")
        return True

    if short == "poc_static_review":
        verdict = str(data.get("verdict", "?"))
        vcol = {"vetted": "green", "needs_review": "yellow", "red_flags": "red"}.get(verdict, "white")
        console.print(
            f"[dim]  └─[/dim] POC review: [{vcol} bold]{_esc(verdict)}[/{vcol} bold] "
            f"[dim]({data.get('files_reviewed', 0)} files)[/dim]"
        )
        for cat, hits in (data.get("red_flags") or {}).items():
            kv(f"⚠ {cat}", hits, cap=4)
        for cat, hits in (data.get("useful_signals") or {}).items():
            kv(cat, hits, cap=3)
        return True

    if short == "affected_version_check":
        affected = data.get("affected")
        cur = str(data.get("current_version", "?"))
        head = "[red bold]AFFECTED[/red bold]" if affected else "[green]not affected[/green]"
        console.print(f"[dim]  └─[/dim] {_esc(cur)}: {head}")
        for r in data.get("results") or []:
            if not isinstance(r, dict):
                continue
            glyph = {True: "[red]✓[/red]", False: "[dim]✗[/dim]"}.get(r.get("matches"), "[yellow]?[/yellow]")
            console.print(f"      {glyph} {_esc(str(r.get('range', '')))}")
        return True

    if short == "web_search":
        results = data.get("results") or []
        src = str(data.get("source") or "web")
        query = _short(str(data.get("query") or ""), n=80)
        console.rule(
            f"[cyan]{_esc(src)}: {len(results)} result"
            f"{'' if len(results) == 1 else 's'}[/cyan]  [dim]{_esc(query)}[/dim]",
            align="left",
        )
        answer = str(data.get("answer") or "").strip()
        if answer:
            console.print(f"      [green]⮞[/green] {_esc(_short(answer, n=200))}")
        for r in results[:8]:
            if not isinstance(r, dict):
                continue
            title = _short(str(r.get("title") or "(untitled)"), n=90)
            console.print(f"  [bold]{_esc(title)}[/bold]")
            console.print(f"      [dim blue]{_esc(str(r.get('url') or ''))}[/dim blue]")
            snippet = str(r.get("snippet") or r.get("content") or "").replace("\n", " ")
            if snippet:
                console.print(f"      [dim]{_esc(_short(snippet, n=170))}[/dim]")
        if len(results) > 8:
            console.print(f"  [dim]… {len(results) - 8} more[/dim]")
        return True

    return False  # unknown research tool — generic summary handles it


def _render_run_oneshot_result(content: str) -> bool:
    """Render shell__run_oneshot output, stripping tmux prompt cruft + ANSI."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("ok") is False:
        console.print(f"[dim]  └─[/dim] [red]shell[/red]: {_esc(str(data.get('error','failed')))}")
        return True
    raw = str(data.get("output", ""))
    cleaned = _strip_tmux_cruft(raw)
    if not cleaned:
        text = "(no output before timeout)" if data.get("timed_out") else "(no output)"
        console.print(f"[dim]  └─[/dim] [cyan]shell[/cyan]: {_esc(text)}")
        return True
    lines = cleaned.splitlines()
    visible = lines[:30]
    for line in visible:
        console.print(f"      {_esc(line)}")
    omitted = len(lines) - len(visible)
    if omitted > 0:
        console.print(f"      [dim]… {omitted} more lines omitted[/dim]")
    if data.get("timed_out"):
        console.print("      [yellow](timed out — partial output)[/yellow]")
    return True


_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _strip_tmux_cruft(raw: str) -> str:
    """Remove ANSI escapes and the repeating tmux prompt lines from a
    capture-pane dump. Mirrors the Ink CLI's stripTmuxCruft."""
    if not raw:
        return ""
    cleaned = _ANSI_RE.sub("", raw)
    lines = cleaned.splitlines()
    trailing = next((line.strip() for line in reversed(lines) if line.strip()), "")
    import re as _re  # noqa: PLC0415
    m = _re.match(r"^([\w\-./~:@]+\s*[#$])\s*$", trailing)
    prompt_prefix = m.group(1) if m else None
    filtered = [
        line for line in lines
        if not (prompt_prefix and line.strip().startswith(prompt_prefix))
    ]
    while filtered and not filtered[0].strip():
        filtered.pop(0)
    while filtered and not filtered[-1].strip():
        filtered.pop()
    return "\n".join(filtered)


def _render_task_result(content: str) -> bool:
    """Subagent task() result — often a structured Pydantic dump. Surface
    only the high-signal fields so the operator isn't blasted with the
    full SurfaceFindings/ExploitResult JSON."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    summary = str(data.get("summary") or "").strip()
    if not summary:
        # Pick the next-most-informative fields if present.
        counts = []
        for key in ("findings", "credentials", "services", "results", "candidates"):
            v = data.get(key)
            if isinstance(v, list) and v:
                counts.append(f"{len(v)} {key}")
        summary = ", ".join(counts) if counts else "ok"
    console.print(f"[dim]  └─[/dim] [cyan]task[/cyan]: {_esc(_short(summary, n=200))}")
    return True


def _refusal_note(msg) -> str | None:
    """If a model message is a safety refusal, return a short operator-facing
    note; else None. Anthropic sets `stop_reason == "refusal"` with a
    `stop_details.category` (e.g. `"cyber"` for the real-time cyber safeguard).
    Returns a concise reason — NOT the full token-bearing URL from the API."""
    if not isinstance(msg, dict):
        return None
    rm = msg.get("response_metadata") or {}
    if rm.get("stop_reason") != "refusal":
        return None
    details = rm.get("stop_details") or {}
    category = details.get("category")
    if category == "cyber":
        return ("(Anthropic real-time cyber safeguard). The fix is operator "
                "verification — see README → Cyber safeguard / Verification Program.")
    return f"(safety refusal{f', category: {category}' if category else ''})."


def _thinking_parts(msg) -> list[str]:
    """Pull extended-thinking text out of a message's content blocks.

    Adaptive thinking (Opus 4.7/4.8) streams `thinking`-type blocks; with
    `display: "summarized"` their text is populated. langchain may normalize
    these as `reasoning` blocks instead, so accept both, and read the text from
    whichever field carries it (`thinking` / `reasoning` / `text`). Returns the
    non-empty thinking strings in order; `[]` when thinking is off or omitted.
    """
    if not isinstance(msg, dict):
        return []
    content = msg.get("content", "")
    if not isinstance(content, list):
        return []
    out: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") in ("thinking", "reasoning"):
            text = block.get("thinking") or block.get("reasoning") or block.get("text") or ""
            if isinstance(text, str) and text.strip():
                out.append(text)
    return out


def _split_message(msg) -> tuple[list[str], list[dict], list[dict]]:
    """Walk a message and pull out its text parts, tool_use blocks, and
    tool_result blocks. Returns (text_parts, tool_calls, tool_results)."""
    text_parts: list[str] = []
    tool_calls: list[dict] = []
    tool_results: list[dict] = []

    # langchain ToolMessage shape (when emitted by the tool node).
    # Capture the FULL content here — let the renderer decide how to display
    # it (truncate, pretty-print as checklist, etc.) based on the tool.
    if isinstance(msg, dict) and msg.get("type") == "tool":
        tool_results.append({
            "name": msg.get("name", ""),
            "preview": _normalize_tool_content(msg.get("content", "")),
        })
        return text_parts, tool_calls, tool_results

    # Streamed dicts: content may be a string or a list of blocks
    if isinstance(msg, dict):
        # Track seen tool_use IDs so we don't double-count between the raw
        # Anthropic `content` blocks AND the langchain-normalized `tool_calls`
        # attribute — they describe the same calls and both arrive on AIMessage
        # after `model_dump()`. The block carries `id`; the normalized form
        # carries the same string in `id`.
        seen_call_ids: set[str] = set()

        content = msg.get("content", "")
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    text_parts.append(str(block))
                    continue
                btype = block.get("type")
                if btype == "text":
                    text_parts.append(block.get("text", ""))
                elif btype == "tool_use":
                    call_id = block.get("id") or ""
                    tool_calls.append({
                        "name": block.get("name", ""),
                        "input": block.get("input", {}),
                        "id": call_id,
                    })
                    if call_id:
                        seen_call_ids.add(call_id)
                elif btype == "tool_result":
                    tool_results.append({
                        "name": block.get("name", "tool"),
                        "preview": _normalize_tool_content(block.get("content", "")),
                    })
                elif btype in ("thinking", "reasoning"):
                    # Extended-thinking blocks are pulled out separately by
                    # `_thinking_parts` and rendered dimmed — skip here so they
                    # don't get JSON-dumped into the prose stream.
                    continue
                else:
                    text_parts.append(json.dumps(block))
        else:
            text_parts.append(str(content))

        # langchain AIMessage shape: `tool_calls` is a normalized mirror of
        # the tool_use blocks above. Only add entries whose id we haven't
        # already recorded — otherwise every dispatch prints twice.
        for tc in msg.get("tool_calls") or []:
            if not isinstance(tc, dict):
                continue
            call_id = tc.get("id") or ""
            if call_id and call_id in seen_call_ids:
                continue
            tool_calls.append({
                "name": tc.get("name", ""),
                "input": tc.get("args") or tc.get("input") or {},
                "id": call_id,
            })
            if call_id:
                seen_call_ids.add(call_id)
        return text_parts, tool_calls, tool_results

    if isinstance(msg, str):
        text_parts.append(msg)
        return text_parts, tool_calls, tool_results

    # langchain message object fallback
    text_parts.append(str(getattr(msg, "content", msg)))
    return text_parts, tool_calls, tool_results


def _format_args(args) -> str:
    """Render tool args as `k=v, k=v`. Falls back to JSON for nested values."""
    if not isinstance(args, dict):
        return _short(str(args), n=120)
    parts = []
    for k, v in args.items():
        if isinstance(v, (str, int, float, bool)):
            parts.append(f"{k}={v!r}")
        else:
            parts.append(f"{k}={_short(json.dumps(v), n=40)}")
    return ", ".join(parts)


def _summarize(payload) -> str:
    """Legacy helper kept for tests/back-compat. Newer rendering goes
    through `_render_agent_payload`."""
    if isinstance(payload, dict):
        msgs = payload.get("messages")
        if isinstance(msgs, list) and msgs:
            return _short(_message_content(msgs[-1]))
        return _short(json.dumps(payload)[:400])
    return _short(str(payload))


def _message_content(msg) -> str:
    """Pull a printable string from whatever shape the streamed message has."""
    if isinstance(msg, dict):
        content = msg.get("content", "")
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        parts.append(block.get("text", ""))
                    elif block.get("type") == "tool_use":
                        name = block.get("name", "?")
                        parts.append(f"<tool_use {name}>")
                    elif block.get("type") == "tool_result":
                        parts.append("<tool_result>")
                    else:
                        parts.append(json.dumps(block))
                else:
                    parts.append(str(block))
            return " ".join(parts)
        return str(content)
    if isinstance(msg, str):
        return msg
    return str(getattr(msg, "content", msg))


def _short(text: str, n: int = 240) -> str:
    text = text.replace("\n", " ").strip()
    return text if len(text) <= n else text[:n] + "…"


# ---------------------------------------------------------------------------
# Live in-flight status line
# ---------------------------------------------------------------------------

_inflight_status = None  # type: ignore[var-annotated]


def _set_inflight(name) -> None:
    """Update the live status line shown while a tool call is in-flight.

    Uses rich.Status under the hood — produces a single re-rendered spinner
    line that updates without spamming the scrollback.
    """
    global _inflight_status
    if name is None:
        if _inflight_status is not None:
            _inflight_status.stop()
            _inflight_status = None
        return

    from rich.status import Status  # noqa: PLC0415
    message = f"[cyan]{name}[/cyan] running..."
    if _inflight_status is None:
        _inflight_status = Status(message, console=console, spinner="dots")
        _inflight_status.start()
    else:
        _inflight_status.update(message)


@app.command()
def approve(
    engagement_id: str = typer.Argument(...),
    decision: str = typer.Option("accept", "--decision", help="accept | reject | edit | respond"),
    guidance: str = typer.Option("", "--guidance", help="Operator guidance for respond"),
) -> None:
    """Respond to a pending HITL interrupt."""
    resp = httpx.post(
        f"{GATEWAY_URL}/engagements/{engagement_id}/approve",
        json={"decision": decision, "guidance": guidance},
        timeout=30.0,
    )
    if resp.status_code != 200:
        console.print(f"[red]{resp.status_code}:[/red] {resp.text}")
        raise typer.Exit(1)
    console.print("[green]ok[/green]")


skills_app = typer.Typer(help="Review proposed skills")
app.add_typer(skills_app, name="skills")


@skills_app.command("review")
def skills_review() -> None:
    """List proposed skills awaiting operator review."""
    resp = httpx.get(f"{GATEWAY_URL}/skills/_proposed", timeout=10.0)
    if resp.status_code != 200:
        console.print(f"[red]{resp.status_code}:[/red] {resp.text}")
        raise typer.Exit(1)
    proposals = resp.json().get("proposals", [])
    if not proposals:
        console.print("[dim]No pending proposals.[/dim]")
        return
    for p in proposals:
        console.print(Panel(p["preview"], title=p["name"], subtitle=p["path"]))


@skills_app.command("accept")
def skills_accept(
    name: str = typer.Argument(...),
    target_dir: str = typer.Option(..., "--into", help="Target subdir under skills/ (e.g. exploit)"),
) -> None:
    """Move a proposed SKILL.md into the active skill tree."""
    resp = httpx.post(
        f"{GATEWAY_URL}/skills/_proposed/{name}/accept",
        params={"target_dir": target_dir},
        timeout=10.0,
    )
    if resp.status_code != 200:
        console.print(f"[red]{resp.status_code}:[/red] {resp.text}")
        raise typer.Exit(1)
    console.print(f"[green]Accepted into[/green] {resp.json().get('path')}")


@app.command()
def episodes(
    engagement_id: str = typer.Argument(...),
    n: int = typer.Option(50, "--n", help="Number of recent episodes to show"),
) -> None:
    """Show the recent episode log for an engagement."""
    resp = httpx.get(
        f"{GATEWAY_URL}/engagements/{engagement_id}/episodes",
        params={"n": n},
        timeout=30.0,
    )
    if resp.status_code != 200:
        console.print(f"[red]{resp.status_code}:[/red] {resp.text}")
        raise typer.Exit(1)
    table = Table("ts", "agent", "action", "outcome", "cost")
    for ep in resp.json().get("episodes", []):
        table.add_row(
            ep["timestamp"][:19],
            ep["agent_name"],
            ep["action"][:48],
            ep["outcome_tag"],
            f"${ep['cost_usd']:.4f}",
        )
    console.print(table)


if __name__ == "__main__":
    app()
