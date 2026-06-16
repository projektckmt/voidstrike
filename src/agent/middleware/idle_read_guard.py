"""Guard against spin-polling a settled tmux pane.

A subagent that issues a command into a tmux session, then keeps calling
`shell__tmux_read` after the command has already completed, gets stuck in a
read-loop: each read returns `ok: True` with an empty incremental delta
(`new_output: False`), so nothing ever changes and the agent never decides to
act. This slips past both existing safety nets:

  * `stuck_detector` is on the orchestrator loop and never intercepts tool
    calls made inside a subagent runtime.
  * `repeat_guard` only counts *failing* calls — an empty read is a success
    (`ok: True`), so it resets the counter every time and deliberately exempts
    tmux polling (it can't tell a settled prompt from a listener still waiting).

This middleware closes that gap deterministically. It counts *consecutive*
`tmux_read` calls per session that come back with no new output, and after
`max_idle` returns a directive telling the model to stop polling and act. Any
read that brings new output resets the counter.

Listeners are NOT special-cased. An earlier version exempted any read carrying
a `connection: null` field (the shell server's "listener still waiting" signal),
but that field is unreliable: the server's connection detector only recognizes
nc/ncat-style callbacks, so an msfconsole/sliver listener reports `connection:
null` *even after a session has landed* — and the guard then reset forever and
never fired (the `msf-main` spin). The robust rule: a real callback produces new
output, which resets the counter on its own; if nothing is arriving across
`max_idle` reads, blind-polling is unproductive whether the pane is a settled
shell or a listener whose payload never called back — in both cases the agent
should act (check sessions, re-fire, hand back) rather than read again.
"""

from __future__ import annotations

import json
import re
from collections import deque
from difflib import SequenceMatcher
from typing import Any

# Strip escape sequences / control bytes so two reads are compared by their
# visible text. A wedged PTY (line-wrap redraw at the wrong COLUMNS) emits new
# *bytes* on every read while the visible content barely changes; comparing raw
# strings would see "new output" every time and the streak would never build.
_ANSI_OSC_RE = re.compile(
    r"\x1b\[[0-9;?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f]"
)


def _normalize(text: str) -> str:
    return " ".join(_ANSI_OSC_RE.sub("", text).replace("\r", "").split())


def _is_churn(norm: str, recent: deque[str], *, threshold: float = 0.9) -> bool:
    """True if `norm` is a near-duplicate of a recent read.

    A wedged shell keeps re-emitting ~the same garbled pane (only a few chars of
    freshly-echoed command differ), so each read is >threshold similar to the
    last few. Genuinely fresh command output scores low and resets the streak.
    Comparison is tail-bounded so a busy 12 KB pane stays cheap.
    """
    if not norm:
        return False
    tail = norm[-1500:]
    return any(
        SequenceMatcher(None, tail, prev[-1500:]).ratio() >= threshold
        for prev in recent
    )


def _parse_tool_content(result: Any) -> Any:
    content = getattr(result, "content", result)
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text", block)))
            else:
                parts.append(str(getattr(block, "text", block)))
        content = "".join(parts)
    if not isinstance(content, str):
        return content
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return None


def idle_read_guard(max_idle: int = 6):
    """Break loops where a subagent re-reads a settled tmux pane.

    Deterministic — the prompt can tell the model to stop polling and act, but
    this stops the spin regardless. Attach one instance per subagent loop that
    drives `shell__tmux_read` (postex, exploit).
    """
    from langchain.agents.middleware import AgentMiddleware  # noqa: PLC0415
    from langchain_core.messages import ToolMessage  # noqa: PLC0415

    idle_counts: dict[str, int] = {}
    block_counts: dict[str, int] = {}
    # Consecutive near-duplicate ("churn") reads per session, plus a rolling
    # window of recent normalized outputs to compare against. Unlike idle_counts,
    # churn is NOT reset by a fresh `tmux_send`: a wedged shell keeps echoing the
    # same garble no matter what you send into it, and the send/read recovery
    # spiral is exactly what we need to break. A read with genuinely fresh,
    # distinct output is what resets it.
    churn_counts: dict[str, int] = {}
    recent_outputs: dict[str, deque[str]] = {}

    class IdleReadGuard(AgentMiddleware):
        async def awrap_tool_call(self, request, handler):  # noqa: ANN001
            tool = getattr(request, "tool", None)
            tool_name = getattr(tool, "name", "") or ""
            if tool_name == "shell__tmux_send":
                tool_call = getattr(request, "tool_call", {}) or {}
                args = tool_call.get("args", {}) or {}
                session = str(args.get("session_name", ""))
                if session:
                    # A fresh command is the agent acting, not blind-polling, so
                    # the idle (no-new-output) streak resets. Churn does NOT —
                    # see the comment on churn_counts above.
                    idle_counts[session] = 0
                return await handler(request)

            if tool_name != "shell__tmux_read":
                return await handler(request)

            tool_call = getattr(request, "tool_call", {}) or {}
            args = tool_call.get("args", {}) or {}
            tool_call_id = tool_call.get("id", "") or ""
            session = str(args.get("session_name", ""))

            wedged = churn_counts.get(session, 0) >= max_idle
            if idle_counts.get(session, 0) >= max_idle or wedged:
                block_counts[session] = block_counts.get(session, 0) + 1
                severe = block_counts[session] >= 2
                # Reset both streaks so the session stays usable the moment the
                # model does something productive. A second block escalates.
                idle_counts[session] = 0
                churn_counts[session] = 0
                recent_outputs.pop(session, None)
                if wedged:
                    return ToolMessage(
                        content=(
                            f"WEDGED_SHELL_BLOCKED: `shell__tmux_read` on session "
                            f"{session!r} keeps returning near-identical output that "
                            f"never settles to a clean prompt ({max_idle}x). The shell "
                            "is almost certainly corrupted (a line-wrap/redraw loop on a "
                            "raw PTY). Reading or sending more will NOT recover it. "
                            "Re-establish a fresh shell — re-fire your payload to a NEW "
                            "listener session (try `shell__stabilize_shell` once on the "
                            "fresh one; if it returns healthy:false, the pane is dead) — "
                            "or return your structured result with the evidence you have. "
                            "Do not keep driving this pane."
                        ),
                        tool_call_id=tool_call_id,
                        name=tool_name,
                        status="error",
                    )
                action = (
                    "Return your structured result now with the evidence you have, "
                    "or switch to a different session/technique before reading again."
                    if severe
                    else (
                        "Verify it ran / check your sessions / re-fire with a changed "
                        "payload, or hand back to the orchestrator with what you have."
                    )
                )
                return ToolMessage(
                    content=(
                        f"IDLE_READ_BLOCKED: `shell__tmux_read` on session {session!r} "
                        f"has returned no new output {max_idle} times in a row. "
                        "Re-reading will not change that. If a command finished, act on "
                        "the output you already have. If this is a listener waiting for "
                        "a callback, none has arrived — the payload likely didn't fire: "
                        f"{action} Do not keep blind-polling."
                    ),
                    tool_call_id=tool_call_id,
                    name=tool_name,
                    status="error",
                )

            result = await handler(request)
            parsed = _parse_tool_content(result)
            if not isinstance(parsed, dict):
                return result
            if parsed.get("ok") is not True:
                return result
            # Idle streak: a read with no new output. A genuine callback / command
            # output sets new_output=True and resets it. We never rely on the
            # `connection` field (it under-reports msf/sliver/custom callbacks).
            if parsed.get("new_output") is False:
                idle_counts[session] = idle_counts.get(session, 0) + 1
            else:
                idle_counts[session] = 0
                block_counts[session] = 0
            # Churn streak: a read whose visible output is a near-duplicate of a
            # recent one. Catches a wedged shell that emits fresh *bytes* (so
            # new_output is True) but no real *progress* — the case new_output
            # alone misses. Both streaks share the max_idle threshold.
            norm = _normalize(str(parsed.get("output", "")))
            window = recent_outputs.setdefault(session, deque(maxlen=4))
            if _is_churn(norm, window):
                churn_counts[session] = churn_counts.get(session, 0) + 1
            else:
                churn_counts[session] = 0
            window.append(norm)
            return result

    return IdleReadGuard()
