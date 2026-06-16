"""Tests for the CLI renderer.

The renderer split was added because the original `_summarize`-style
output truncated everything to one line, hiding tool dispatches inside a
text-heavy model response. Operators couldn't tell what the agent was
*currently* running. These tests pin the structure:

  - prose text gets one line, agent-prefixed
  - each tool_use block gets its own `→ calling NAME(args)` line
  - tool results get a `✓ NAME returned: preview` line
  - lifecycle events (start/cancelling/cancelled/complete/end/error) render
"""

from __future__ import annotations


def _content_blocks(*blocks):
    """Helper — build an Anthropic-style content list."""
    return {"content": list(blocks), "type": "ai"}


# ---------------------------------------------------------------------------
# _split_message
# ---------------------------------------------------------------------------


def test_split_message_text_only() -> None:
    from src.cli.main import _split_message
    msg = _content_blocks({"type": "text", "text": "thinking out loud"})
    texts, calls, results = _split_message(msg)
    assert texts == ["thinking out loud"]
    assert calls == []
    assert results == []


def test_split_message_tool_use_only() -> None:
    from src.cli.main import _split_message
    msg = _content_blocks({
        "type": "tool_use",
        "id": "toolu_test",
        "name": "surface__nmap_quick",
        "input": {"target": "10.129.1.221"},
    })
    texts, calls, _ = _split_message(msg)
    assert texts == []
    assert len(calls) == 1
    assert calls[0]["name"] == "surface__nmap_quick"
    assert calls[0]["input"] == {"target": "10.129.1.221"}
    # Each call now carries an `id` so the dedupe between content-blocks
    # and the langchain-normalized `tool_calls` mirror works.
    assert calls[0]["id"] == "toolu_test"


def test_split_message_text_then_tool_use() -> None:
    """The common Anthropic pattern: model says what it'll do, then
    emits a tool_use block. Both should be extracted."""
    from src.cli.main import _split_message
    msg = _content_blocks(
        {"type": "text", "text": "I'll scan the target."},
        {"type": "tool_use", "name": "surface__nmap_quick", "input": {}},
    )
    texts, calls, _ = _split_message(msg)
    assert texts == ["I'll scan the target."]
    assert [c["name"] for c in calls] == ["surface__nmap_quick"]


def test_split_message_handles_tool_result_block() -> None:
    from src.cli.main import _split_message
    msg = _content_blocks({
        "type": "tool_result",
        "name": "surface__nmap_quick",
        "content": "1 host up, 5 services",
    })
    _, _, results = _split_message(msg)
    assert results == [{"name": "surface__nmap_quick",
                         "preview": "1 host up, 5 services"}]


def test_split_message_langchain_tool_message() -> None:
    """The tool node emits a ToolMessage with `type: tool` and a flat
    `content` field. We should treat that as a tool_result."""
    from src.cli.main import _split_message
    msg = {"type": "tool", "name": "write_objective", "content": '{"ok": true}'}
    _, _, results = _split_message(msg)
    assert results == [{"name": "write_objective", "preview": '{"ok": true}'}]


def test_split_message_tool_calls_attribute() -> None:
    """Some langchain AIMessage shapes carry tool_calls at the top level."""
    from src.cli.main import _split_message
    msg = {
        "content": "I'll do two things",
        "tool_calls": [
            {"name": "a", "args": {"x": 1}},
            {"name": "b", "args": {"y": 2}},
        ],
    }
    _, calls, _ = _split_message(msg)
    assert [c["name"] for c in calls] == ["a", "b"]


def test_split_message_dedupes_content_block_and_tool_calls_mirror() -> None:
    """After `model_dump()`, an Anthropic AIMessage carries the same tool
    call in BOTH `content` (as a `tool_use` block) AND `tool_calls` (the
    langchain-normalized mirror). They share the same id. The renderer
    must NOT print the dispatch twice."""
    from src.cli.main import _split_message
    msg = {
        "content": [
            {"type": "text", "text": "Let me scan"},
            {"type": "tool_use", "id": "toolu_abc",
             "name": "surface__nmap_quick", "input": {"target": "10.0.0.1"}},
        ],
        "tool_calls": [
            {"id": "toolu_abc", "name": "surface__nmap_quick",
             "args": {"target": "10.0.0.1"}},
        ],
        "type": "ai",
    }
    _, calls, _ = _split_message(msg)
    # Should appear exactly once, not twice.
    assert len(calls) == 1, f"expected dedup, got {len(calls)} calls: {calls}"
    assert calls[0]["name"] == "surface__nmap_quick"


def test_split_message_tool_calls_only_no_dup() -> None:
    """If only `tool_calls` is present (no content blocks), we still
    surface the call."""
    from src.cli.main import _split_message
    msg = {
        "content": "I'll do one thing",
        "tool_calls": [
            {"id": "toolu_xyz", "name": "write_objective", "args": {"objective": "..."}},
        ],
    }
    _, calls, _ = _split_message(msg)
    assert [c["name"] for c in calls] == ["write_objective"]


def test_split_message_two_distinct_tool_uses_both_render() -> None:
    """When the model emits two genuinely-different tool calls, both
    should still appear — dedup must key on id, not name."""
    from src.cli.main import _split_message
    msg = {
        "content": [
            {"type": "tool_use", "id": "t1", "name": "task", "input": {"a": 1}},
            {"type": "tool_use", "id": "t2", "name": "task", "input": {"a": 2}},
        ],
        "tool_calls": [
            {"id": "t1", "name": "task", "args": {"a": 1}},
            {"id": "t2", "name": "task", "args": {"a": 2}},
        ],
    }
    _, calls, _ = _split_message(msg)
    # Two distinct calls, dedup keeps both.
    assert len(calls) == 2
    assert [c["input"]["a"] for c in calls] == [1, 2]


def test_split_message_plain_string() -> None:
    from src.cli.main import _split_message
    texts, calls, results = _split_message("hello world")
    assert texts == ["hello world"]
    assert calls == [] and results == []


# ---------------------------------------------------------------------------
# _thinking_parts — extended-thinking extraction
# ---------------------------------------------------------------------------


def test_thinking_parts_extracts_thinking_block() -> None:
    from src.cli.main import _thinking_parts
    msg = _content_blocks(
        {"type": "thinking", "thinking": "The DC has no roastable users."},
        {"type": "text", "text": "I'll spray instead."},
    )
    assert _thinking_parts(msg) == ["The DC has no roastable users."]


def test_thinking_parts_accepts_reasoning_alias() -> None:
    from src.cli.main import _thinking_parts
    msg = _content_blocks({"type": "reasoning", "reasoning": "step by step"})
    assert _thinking_parts(msg) == ["step by step"]


def test_thinking_parts_empty_when_no_thinking() -> None:
    from src.cli.main import _thinking_parts
    assert _thinking_parts(_content_blocks({"type": "text", "text": "hi"})) == []
    assert _thinking_parts("plain string") == []


def test_split_message_skips_thinking_blocks() -> None:
    """Thinking blocks must NOT leak into the prose stream as JSON."""
    from src.cli.main import _split_message
    msg = _content_blocks(
        {"type": "thinking", "thinking": "secret reasoning"},
        {"type": "text", "text": "visible prose"},
    )
    texts, _, _ = _split_message(msg)
    assert texts == ["visible prose"]


def test_render_agent_payload_thinking_does_not_crash_on_brackets() -> None:
    """Thinking text with bracketed content must be escaped like all other
    dynamic output (markup-injection regression)."""
    from src.cli.main import _render_agent_payload
    payload = {"messages": [_content_blocks(
        {"type": "thinking", "thinking": "considering [CVE-2024-1234] and [/app] prompts"},
    )]}
    _render_agent_payload("exploit", payload)  # must not raise MarkupError


def test_print_banner_renders() -> None:
    from src.cli.main import _print_banner
    _print_banner()  # must not raise (rich-safe glyphs)


# ---------------------------------------------------------------------------
# _refusal_note — surface Anthropic safety refusals (don't render as empty)
# ---------------------------------------------------------------------------


def test_refusal_note_detects_cyber_safeguard() -> None:
    from src.cli.main import _refusal_note
    msg = {
        "type": "ai", "content": [],
        "response_metadata": {
            "stop_reason": "refusal",
            "stop_details": {"category": "cyber", "explanation": "https://...token..."},
        },
    }
    note = _refusal_note(msg)
    assert note and "cyber safeguard" in note
    assert "token" not in note  # never echo the token-bearing URL


def test_refusal_note_none_for_normal_turn() -> None:
    from src.cli.main import _refusal_note
    assert _refusal_note({"type": "ai", "response_metadata": {"stop_reason": "tool_use"}}) is None
    assert _refusal_note("plain string") is None


def test_render_agent_payload_refusal_does_not_crash() -> None:
    """A refused turn must render a visible warning, not a silent empty line."""
    from src.cli.main import _render_agent_payload
    payload = {"messages": [{
        "type": "ai", "content": [],
        "response_metadata": {"stop_reason": "refusal", "stop_details": {"category": "cyber"}},
    }]}
    _render_agent_payload("exploit", payload)  # must not raise


# ---------------------------------------------------------------------------
# _format_args
# ---------------------------------------------------------------------------


def test_format_args_simple() -> None:
    from src.cli.main import _format_args
    out = _format_args({"target": "10.0.0.1", "ports": 1000})
    assert "target='10.0.0.1'" in out
    assert "ports=1000" in out


def test_format_args_nested_value_uses_json() -> None:
    from src.cli.main import _format_args
    out = _format_args({"params": {"x": 1, "y": 2}})
    assert "params=" in out


# ---------------------------------------------------------------------------
# _render_event end-to-end
# ---------------------------------------------------------------------------


def _captured(fn, *args, **kwargs) -> str:
    """Run `fn(*args)`, return everything printed by rich Console."""
    from io import StringIO

    from rich.console import Console

    from src.cli import main as cli

    buf = StringIO()
    real_console = cli.console
    cli.console = Console(file=buf, force_terminal=False, width=200)
    try:
        fn(*args, **kwargs)
    finally:
        # Cleanup any spinner that the test may have left running.
        cli._set_inflight(None)
        cli.console = real_console
    return buf.getvalue()


def test_render_event_tool_call_shows_dedicated_line(monkeypatch) -> None:
    """A model step containing a tool_use block must print a line saying
    which tool is being called — not bury it in 240-char truncated prose."""
    from src.cli.main import _render_event
    event = {
        "event": "step",
        "data": {
            "model": {
                "messages": [{
                    "content": [
                        {"type": "text", "text": "Let me scan the target."},
                        {"type": "tool_use",
                         "name": "surface__nmap_quick",
                         "input": {"target": "10.129.1.221"}},
                    ],
                }],
            },
        },
    }
    out = _captured(_render_event, event)
    assert "Let me scan the target." in out
    # The tool dispatch must be on its own line. Well-known tools render
    # under their friendly verb ("scans nmap") rather than the raw
    # `surface__nmap_quick` MCP name.
    assert "scans" in out
    assert "nmap" in out
    assert "10.129.1.221" in out


def test_render_event_tool_result_shows_dedicated_line() -> None:
    """A tool result event must show its content on a dedicated line so the
    operator can tell when the long-running tool finished."""
    from src.cli.main import _render_event
    event = {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{
                    "type": "tool",
                    "name": "surface__nmap_quick",
                    "content": "Host is up. 135/tcp open, 445/tcp open.",
                }],
            },
        },
    }
    out = _captured(_render_event, event)
    # Generic fallback renderer uses the `└─` connector + tool name.
    assert "└─" in out
    assert "surface__nmap_quick" in out
    assert "445/tcp" in out


def test_render_event_complete_clears_spinner(monkeypatch) -> None:
    """The live in-flight status must stop when the engagement ends —
    otherwise the operator sees a hanging spinner."""
    from src.cli import main as cli

    stop_calls: list[bool] = []

    class _FakeStatus:
        def __init__(self, *a, **kw): pass
        def start(self): pass
        def update(self, *a, **kw): pass
        def stop(self): stop_calls.append(True)

    cli._inflight_status = _FakeStatus()
    try:
        cli._render_event({"event": "complete"})
    finally:
        cli._inflight_status = None

    assert stop_calls, "spinner.stop() must be called on `complete` event"


def test_render_lifecycle_events_dont_crash() -> None:
    from src.cli.main import _render_event
    for kind in ("start", "subscribed", "complete", "cancelling",
                  "cancelled", "end"):
        _captured(_render_event, {"event": kind, "engagement_id": "x",
                                    "reason": "test"})


def test_render_error_event_prints_traceback() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, {
        "event": "error",
        "error": "BadRequestError: 400",
        "traceback": "File foo.py line 42",
    })
    assert "BadRequestError" in out
    assert "File foo.py" in out


# ---------------------------------------------------------------------------
# Rich markup injection — tool output and model text frequently contain
# bracketed text that Rich would otherwise try to parse as markup tags.
# Every interpolation point must escape its dynamic content.
# ---------------------------------------------------------------------------


def test_nuclei_renderer_lists_findings_severity_first() -> None:
    import json

    from src.cli.main import _render_nuclei_result
    out = _captured(_render_nuclei_result, json.dumps({
        "ok": True, "target": "http://t:3000", "finding_count": 2,
        "findings": [
            {"template_id": "CVE-2025-1", "name": "SQLi [unauth]", "severity": "critical",
             "matched_at": "http://t:3000/a?[x]", "cve": "CVE-2025-1"},
            {"template_id": "apache-detect", "name": "Apache", "severity": "info",
             "matched_at": "http://t/"},
        ],
    }))
    assert "nuclei: 2 findings" in out
    assert "CVE-2025-1" in out and "critical" in out
    assert "[unauth]" in out  # bracketed content escaped, not crashed


def test_nuclei_renderer_benign_no_template_match_shows_note() -> None:
    import json

    from src.cli.main import _render_nuclei_result
    out = _captured(_render_nuclei_result, json.dumps({
        "ok": True, "target": "http://t", "finding_count": 0, "findings": [],
        "note": "nuclei selected 0 templates — the tags/severity filter matched nothing.",
    }))
    assert "no templates matched" in out
    assert "0 templates" in out


def test_nuclei_renderer_error_surfaces_message_with_brackets() -> None:
    import json

    from src.cli.main import _render_nuclei_result
    # error message carries stderr that may contain bracket tokens
    out = _captured(_render_nuclei_result, json.dumps({
        "ok": False, "rc": 1, "error": "nuclei failed: parse error [/tmpl]",
    }))
    assert "nuclei" in out and "parse error" in out


def test_tool_result_with_closing_bracket_does_not_crash() -> None:
    """Regression: a metasploit prompt like `msf6 [/app] >` in tool output
    crashed the renderer with
        MarkupError: closing tag '[/app]' doesn't match any open tag
    The interpolated content must be escaped."""
    from src.cli.main import _render_event
    event = {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{
                    "type": "tool",
                    "name": "shell__tmux_read",
                    "content": "msfconsole output: [+] target found, [/app] prompt visible",
                }],
            },
        },
    }
    # Must not raise.
    out = _captured(_render_event, event)
    assert "/app" in out  # the content survived rendering


def test_model_text_with_brackets_does_not_crash() -> None:
    """Model prose often contains `[CVE-2017-0143]` or markdown-link
    syntax like `[click here](url)`. Must not crash."""
    from src.cli.main import _render_event
    event = {
        "event": "step",
        "data": {
            "model": {
                "messages": [{
                    "content": [
                        {"type": "text",
                         "text": "Found [CVE-2017-0143] — see [link](http://x)"},
                    ],
                }],
            },
        },
    }
    out = _captured(_render_event, event)
    assert "CVE-2017-0143" in out


def test_todo_content_with_brackets_does_not_crash() -> None:
    """Todo list content comes from the model and can include any
    bracketed text."""
    from src.cli.main import _render_event
    payload = (
        "Updated to ["
        "{'content': 'Probe [admin] panel at /admin/ for [/login]',"
        " 'status': 'pending'}"
        "]"
    )
    event = {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{"type": "tool", "name": "write_todos",
                              "content": payload}],
            },
        },
    }
    out = _captured(_render_event, event)
    assert "admin" in out


def test_tool_name_with_brackets_does_not_crash() -> None:
    """Pathological — but if any future MCP tool registered a name with
    brackets, the dispatch line must not crash either."""
    from src.cli.main import _render_event
    event = {
        "event": "step",
        "data": {
            "model": {
                "messages": [{
                    "content": [
                        {"type": "tool_use", "id": "t1",
                         "name": "weird[name]", "input": {}},
                    ],
                }],
            },
        },
    }
    out = _captured(_render_event, event)
    assert "weird" in out


def test_cancelling_reason_with_brackets_does_not_crash() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, {
        "event": "cancelling",
        "reason": "operator hit [Ctrl-C] in [/dev/tty1]",
    })
    assert "Ctrl-C" in out


def test_error_traceback_with_brackets_does_not_crash() -> None:
    """Python tracebacks often contain `[1, 2, 3]` repr-style fragments."""
    from src.cli.main import _render_event
    out = _captured(_render_event, {
        "event": "error",
        "error": "ValueError: bad input [1, 2, 3]",
        "traceback": "File 'x.py', line 1, in func\n    raise ValueError([1, 2, 3])",
    })
    assert "ValueError" in out


# ---------------------------------------------------------------------------
# shell__tmux_* panel renderer
# ---------------------------------------------------------------------------


def _tmux_read_event(output: str) -> dict:
    """Build a step event carrying a shell__tmux_read tool result."""
    import json
    return {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{
                    "type": "tool",
                    "name": "shell__tmux_read",
                    "content": json.dumps({"ok": True, "output": output}),
                }],
            },
        },
    }


def test_shell_tmux_read_preserves_newlines() -> None:
    """Multi-line tmux output must not be collapsed to a single line."""
    from src.cli.main import _render_event
    output = "msf > sessions\nActive sessions:\n  1  meterpreter  10.10.11.5\nmsf > "
    out = _captured(_render_event, _tmux_read_event(output))
    assert "Active sessions" in out
    assert "1  meterpreter" in out
    # Each line should appear, not squished onto one line by _short()
    assert "sessions" in out and "meterpreter" in out


def test_shell_tmux_read_brackets_in_output_does_not_crash() -> None:
    """msfconsole prompts and [+] markers must be escaped before Panel render."""
    from src.cli.main import _render_event
    output = "msf6 [/app] > \n[+] session 1 opened"
    out = _captured(_render_event, _tmux_read_event(output))
    assert "/app" in out
    assert "session 1 opened" in out


def test_shell_tmux_read_bracket_split_across_lines_does_not_crash() -> None:
    """Regression: tmux wraps a long msf prompt mid-bracket, so `[/` lands at a
    line end and `app]` on the next. Per-line escaping leaves the `[/`
    unescaped, and Rich matches tags across newlines → MarkupError. The Text
    renderer must not parse markup at all."""
    from src.cli.main import _render_event
    output = "msf6 exploit(multi/handler) [/\napp] > \n[*] Started reverse handler"
    out = _captured(_render_event, _tmux_read_event(output))
    assert "app]" in out
    assert "Started reverse handler" in out


def test_shell_tmux_read_long_output_omits_head() -> None:
    """Output longer than _SHELL_TMUX_MAX_LINES gets a head-omit notice."""
    from src.cli import main as cli
    from src.cli.main import _render_event
    lines = [f"line {i}" for i in range(cli._SHELL_TMUX_MAX_LINES + 10)]
    output = "\n".join(lines)
    out = _captured(_render_event, _tmux_read_event(output))
    assert "omitted" in out
    # Tail should still be present
    assert f"line {cli._SHELL_TMUX_MAX_LINES + 9}" in out


def test_shell_tmux_read_non_json_falls_back_to_generic() -> None:
    """If the tool content isn't JSON (shouldn't happen, but guard it), fall
    back to the standard truncated-preview path rather than crashing."""
    from src.cli.main import _render_event
    event = {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{
                    "type": "tool",
                    "name": "shell__tmux_read",
                    "content": "msfconsole output: [+] target found, [/app] prompt visible",
                }],
            },
        },
    }
    out = _captured(_render_event, event)
    assert "/app" in out


def test_shell_tmux_read_content_blocks_list_renders_as_panel() -> None:
    """The real wire shape from MCP: content is a list of Anthropic content
    blocks (`[{"type": "text", "text": "<json>"}]`), NOT a bare string.
    Before normalization, str() on the list produced `[{'type': ...` and
    the JSON parse failed, causing fallback to the single-line preview."""
    import json

    from src.cli.main import _render_event

    inner = json.dumps({"ok": True, "output": "msf > sessions\n  1  meterpreter"})
    event = {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{
                    "type": "tool",
                    "name": "shell__tmux_read",
                    "content": [{"type": "text", "text": inner}],
                }],
            },
        },
    }
    out = _captured(_render_event, event)
    assert "meterpreter" in out
    # Must NOT contain the Python repr leaking through
    assert "'type': 'text'" not in out


def test_normalize_tool_content_handles_block_list() -> None:
    from src.cli.main import _normalize_tool_content
    assert _normalize_tool_content("hello") == "hello"
    assert _normalize_tool_content([{"type": "text", "text": "a"},
                                     {"type": "text", "text": "b"}]) == "ab"
    # Unknown block types fall back to str()
    assert "image" in _normalize_tool_content([{"type": "image", "src": "x"}])


def test_shell_tmux_send_also_uses_panel_renderer() -> None:
    """shell__tmux_send (not just read) should also get the panel renderer."""
    import json

    from src.cli.main import _render_event

    event = {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{
                    "type": "tool",
                    "name": "shell__tmux_send",
                    "content": json.dumps({"ok": True, "output": ""}),
                }],
            },
        },
    }
    out = _captured(_render_event, event)
    # Empty output → shows "ok" status, no crash
    assert "shell__tmux_send" in out
    assert "ok" in out


def test_tmux_list_sessions_not_mislabeled_error() -> None:
    """tmux_list_sessions returns {"sessions": [...]} with no `ok` key — the
    renderer must not equate a missing `ok` with failure (regression: it printed
    'returned: error' for a successful listing)."""
    import json

    from src.cli.main import _render_shell_tmux_output

    out = _captured(
        _render_shell_tmux_output,
        "shell__tmux_list_sessions",
        json.dumps({"sessions": [{"name": "lsn"}, {"name": "shell1"}]}),
    )
    assert "error" not in out
    assert "2 session(s)" in out and "lsn" in out


def test_tmux_explicit_failure_still_shows_error_with_message() -> None:
    import json

    from src.cli.main import _render_shell_tmux_output

    out = _captured(
        _render_shell_tmux_output,
        "shell__tmux_send",
        json.dumps({"ok": False, "error": "unknown session 'x' [/app]"}),
    )
    assert "error" in out and "unknown session" in out


def test_http_json_request_result_surfaces_status_and_body() -> None:
    import json

    from src.cli.main import _render_event

    event = {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{
                    "type": "tool",
                    "name": "shell__http_json_request",
                    "content": json.dumps({
                        "ok": True,
                        "status_code": 500,
                        "headers": {
                            "content-type": "application/json",
                            "set-cookie": "connect.sid=secret",
                        },
                        "body": '{"message":"SQLITE_BUSY: database is locked"}',
                        "body_truncated": False,
                        "elapsed_ms": 2192,
                    }),
                }],
            },
        },
    }

    out = _captured(_render_event, event)
    assert "500" in out
    assert "SQLITE_BUSY" in out
    assert "connect.sid=secret" not in out
    assert "[redacted]" in out


def test_http_json_request_call_shows_method_and_url() -> None:
    from src.cli.main import _render_event

    event = {
        "event": "step",
        "data": {
            "model": {
                "messages": [{
                    "content": [{
                        "type": "tool_use",
                        "name": "shell__http_json_request",
                        "input": {
                            "method": "POST",
                            "url": "http://staging.silentium.htb/api/v1/auth/login",
                        },
                    }],
                }],
            },
        },
    }

    out = _captured(_render_event, event)
    assert "http" in out
    assert "POST" in out
    assert "/api/v1/auth/login" in out


# ---------------------------------------------------------------------------
# surface__vhost_enum + surface__web_intake renderers
# ---------------------------------------------------------------------------


def _surface_result_event(name: str, payload: dict) -> dict:
    """Build a step event carrying a surface tool result."""
    import json
    return {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{
                    "type": "tool",
                    "name": name,
                    "content": json.dumps(payload),
                }],
            },
        },
    }


def test_vhost_enum_renders_discovered_vhosts() -> None:
    from src.cli.main import _render_event
    event = _surface_result_event("surface__vhost_enum", {
        "ok": True,
        "results": [
            {"fuzz": "staging", "url": "http://silentium.htb/", "status": 200, "length": 8753, "words": 12},
            {"fuzz": "dev", "url": "http://silentium.htb/", "status": 302, "length": 0},
        ],
        "total_matches": 2,
        "truncated": False,
    })
    out = _captured(_render_event, event)
    assert "vhost_enum found 2 vhosts" in out
    assert "staging" in out and "dev" in out
    assert "200" in out and "302" in out


def test_vhost_enum_no_matches() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, _surface_result_event("surface__vhost_enum",
                                                          {"ok": True, "results": []}))
    assert "no distinct vhosts" in out


def test_vhost_enum_error_and_brackets_do_not_crash() -> None:
    from src.cli.main import _render_event
    # vhost names / errors can carry brackets; must be escaped, not crash.
    out = _captured(_render_event, _surface_result_event("surface__vhost_enum", {
        "ok": True,
        "results": [{"fuzz": "weird[host]name", "status": 403, "length": 10}],
    }))
    assert "weird[host]name" in out
    err = _captured(_render_event, _surface_result_event("surface__vhost_enum",
                                                         {"ok": False, "error": "ffuf: bad [args]"}))
    assert "bad [args]" in err


def test_web_intake_renders_recon_summary() -> None:
    from src.cli.main import _render_event
    event = _surface_result_event("surface__web_intake", {
        "ok": True,
        "url": "http://staging.silentium.htb/",
        "final_url": "http://staging.silentium.htb/login",
        "status": 200,
        "title": "Flowise - [admin]",
        "server": "nginx/1.24.0",
        "content_type": "text/html",
        "technologies": ["Flowise", "Node.js", "Express"],
        "cookie_names": ["session", "csrf"],
        "interesting_paths": ["/api/v1/account", "/api/v1/credentials"],
        "forms": [{"action": "/api/v1/account/login", "method": "POST"}],
        "body_hints": ["json-api"],
        "probes": {
            "robots": {"status": 200, "url": "x"},
            "sitemap": {"status": 404},
            "favicon": {"status": 200, "sha256_16": "abc"},
        },
    })
    out = _captured(_render_event, event)
    assert "web_intake" in out
    assert "staging.silentium.htb/login" in out
    assert "Flowise" in out                       # title (with brackets) + tech, escaped
    assert "/api/v1/credentials" in out           # interesting path
    assert "/api/v1/account/login" in out         # form action
    assert "robots 200" in out and "favicon 200" in out   # only <400 probes
    assert "sitemap" not in out.split("probes:")[-1]      # 404 probe excluded


def test_web_intake_error_renders() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, _surface_result_event("surface__web_intake",
                                                         {"ok": False, "error": "curl failed [timeout]"}))
    assert "web_intake" in out
    assert "timeout" in out


# ---------------------------------------------------------------------------
# surface__smb_enum + surface__service_triage renderers
# ---------------------------------------------------------------------------


def test_smb_enum_renders_shares_loot_and_users() -> None:
    from src.cli.main import _render_event
    event = _surface_result_event("surface__smb_enum", {
        "ok": True,
        "target": "10.129.10.14",
        "shares": [
            {"name": "Reports", "type": "Disk", "comment": "", "access": "read"},
            {"name": "ADMIN$", "type": "Disk", "comment": "Remote Admin", "access": "skipped"},
            {"name": "Users", "type": "Disk", "comment": "", "access": "denied"},
        ],
        "anonymous_readable_shares": ["Reports"],
        "readable_share_contents": {
            "Reports": ["  Currency Volume Report.xlsm   A   12345", "  .", "  .."],
        },
        "null_session_users": ["Administrator", "mssql-svc"],
    })
    out = _captured(_render_event, event)
    assert "smb_enum" in out
    assert "1 anon-readable" in out
    assert "Reports" in out                       # the readable share
    assert "read" in out and "denied" in out      # access states
    assert "Currency Volume Report.xlsm" in out   # the loot file inside it
    assert "Administrator" in out and "mssql-svc" in out  # null-session users


def test_smb_enum_error_and_brackets_do_not_crash() -> None:
    from src.cli.main import _render_event
    # Share names / errors can carry brackets; must be escaped, not crash.
    ok = _captured(_render_event, _surface_result_event("surface__smb_enum", {
        "ok": True, "target": "10.0.0.1",
        "shares": [{"name": "weird[$share]", "type": "Disk", "access": "read"}],
        "anonymous_readable_shares": ["weird[$share]"],
        "readable_share_contents": {"weird[$share]": ["loot[1].txt"]},
        "null_session_users": [],
    }))
    assert "weird[$share]" in ok and "loot[1].txt" in ok
    err = _captured(_render_event, _surface_result_event("surface__smb_enum", {
        "ok": False, "error": "refused [NT_STATUS_ACCESS_DENIED]", "hint": "need creds [auth]",
    }))
    assert "NT_STATUS_ACCESS_DENIED" in err and "need creds" in err


def test_service_triage_renders_exposures() -> None:
    from src.cli.main import _render_event
    event = _surface_result_event("surface__service_triage", {
        "ok": True,
        "target": "10.129.10.14",
        "checks": [{"kind": "smb", "port": 445, "exposed": True}],
        "exposures": [
            {"kind": "smb", "port": 445, "summary": "null session lists shares",
             "evidence": "Disk      Reports\nDisk      Users"},
            {"kind": "redis", "port": 6379, "summary": "unauthenticated INFO", "evidence": ""},
        ],
        "exposure_count": 2,
    })
    out = _captured(_render_event, event)
    assert "service_triage" in out
    assert "2 exposures" in out
    assert "smb" in out and "redis" in out
    assert "null session lists shares" in out
    assert "Reports" in out                        # evidence line surfaced


def test_service_triage_no_exposures_is_explicit() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, _surface_result_event("surface__service_triage", {
        "ok": True, "target": "10.0.0.5",
        "checks": [{"kind": "ftp"}, {"kind": "smb"}], "exposures": [], "exposure_count": 0,
    }))
    # Not a bare "ok": the operator sees the check ran and found nothing.
    assert "no anonymous/default exposure" in out
    assert "2 checks" in out


def test_service_triage_brackets_do_not_crash() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, _surface_result_event("surface__service_triage", {
        "ok": True, "target": "10.0.0.9",
        "exposures": [{"kind": "ftp", "port": 21, "summary": "anon login [OK]",
                       "evidence": "230 Login successful [anonymous]"}],
        "exposure_count": 1,
    }))
    assert "anon login [OK]" in out and "230 Login successful" in out


# ---------------------------------------------------------------------------
# research__* renderers
# ---------------------------------------------------------------------------


def _research_event(name: str, payload: dict) -> dict:
    import json
    return {
        "event": "step",
        "data": {"tools": {"messages": [
            {"type": "tool", "name": name, "content": json.dumps(payload)},
        ]}},
    }


def test_research_exploitdb_fetch_shows_hints_and_head() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, _research_event("research__exploitdb_fetch", {
        "ok": True, "edb_id": "52440", "size_chars": 4200, "truncated": True,
        "hints": {"cves": ["CVE-2025-58434"], "has_usage": True,
                  "mentions_reverse_shell": True, "mentions_auth": True,
                  "first_lines": "# Flowise auth bypass [POC]\nimport requests"},
    }))
    assert "exploit-db 52440" in out
    assert "CVE-2025-58434" in out
    assert "reverse_shell" in out
    assert "Flowise auth bypass" in out   # head shown, brackets escaped


def test_research_cve_lookup_lists_cves() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, _research_event("research__cve_lookup", {
        "ok": True, "total_results": 3,
        "results": [
            {"id": "CVE-2025-58434", "cvss": {"base_score": 9.8, "base_severity": "CRITICAL"},
             "description": "Auth bypass [forgot-password] in Flowise", "weaknesses": ["CWE-287"]},
        ],
    }))
    assert "NVD: 1 CVE" in out
    assert "CVE-2025-58434" in out
    assert "9.8" in out
    assert "forgot-password" in out  # bracketed desc escaped, not crashing


def test_research_github_poc_flags_red_flags() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, _research_event("research__github_poc_search", {
        "ok": True, "total_count": 1,
        "results": [{"full_name": "x/flowise-poc", "stars": 0, "language": "Python",
                     "red_flags": ["zero-stars"]}],
    }))
    assert "x/flowise-poc" in out
    assert "zero-stars" in out


def test_research_affected_version_check_renders() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, _research_event("research__affected_version_check", {
        "ok": True, "current_version": "3.0.5", "affected": True,
        "results": [{"range": "< 3.0.6", "matches": True}, {"range": "weird[range]", "matches": None}],
    }))
    assert "3.0.5" in out
    assert "AFFECTED" in out
    assert "weird[range]" in out  # unparseable range shown, escaped


def test_research_error_renders() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, _research_event("research__cve_lookup",
                                                   {"ok": False, "error": "NVD failed [503]"}))
    assert "cve_lookup" in out and "503" in out


def test_research_budget_exhausted_note() -> None:
    from src.cli.main import _render_event
    out = _captured(_render_event, {
        "event": "step",
        "data": {"tools": {"messages": [
            {"type": "tool", "name": "research__exploitdb_fetch",
             "content": "RESEARCH_BUDGET_EXHAUSTED: you've made 50 ..."},
        ]}},
    })
    assert "budget exhausted" in out
