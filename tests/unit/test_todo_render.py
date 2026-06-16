"""Tests for the `write_todos` checklist renderer.

The TodoListMiddleware returns its update as a string like
    `Updated todo list to [{'content': '...', 'status': 'pending'}, ...]`
The CLI must parse this and render a clear checklist rather than the
generic 160-char truncated preview.
"""

from __future__ import annotations


def _captured(fn, *args, **kwargs) -> str:
    from io import StringIO

    from rich.console import Console

    from src.cli import main as cli

    buf = StringIO()
    real = cli.console
    cli.console = Console(file=buf, force_terminal=False, width=200)
    try:
        fn(*args, **kwargs)
    finally:
        cli._set_inflight(None)
        cli.console = real
    return buf.getvalue()


def test_render_todo_list_returns_true_for_valid_payload() -> None:
    """When parsing succeeds, the helper returns True so the caller knows
    to skip the generic preview path."""
    from src.cli.main import _render_todo_list
    payload = (
        "Updated todo list to ["
        "{'content': 'Run nmap', 'status': 'completed'},"
        "{'content': 'Pick exploit', 'status': 'in_progress'}"
        "]"
    )
    out = _captured(_render_todo_list, payload)
    assert "Run nmap" in out
    assert "Pick exploit" in out
    assert "completed" in out
    assert "in_progress" in out


def test_render_todo_list_returns_false_for_non_todo_string() -> None:
    """A non-todo result must not be hijacked — the helper returns False
    so the caller falls back to the generic preview."""
    from src.cli.main import _render_todo_list
    assert _render_todo_list("just a string with no list") is False


def test_render_todo_list_returns_false_for_unparseable_python_literal() -> None:
    from src.cli.main import _render_todo_list
    # Bracket present but contents aren't valid Python literals.
    assert _render_todo_list("Updated to [<object Foo at 0x123>]") is False


def test_render_todo_list_returns_false_for_empty_list() -> None:
    from src.cli.main import _render_todo_list
    assert _render_todo_list("Updated to []") is False


def test_full_event_renders_each_todo_on_its_own_line() -> None:
    """End-to-end: a tool_result event for write_todos must produce one
    visible line per todo item, with status markers — not a single
    160-char truncated blob."""
    from src.cli.main import _render_event
    long_payload = (
        "Updated todo list to ["
        "{'content': 'Run nmap quick scan against 10.129.4.66', 'status': 'completed'},"
        "{'content': 'Analyze open ports and services', 'status': 'completed'},"
        "{'content': 'Identify exploitable services (CVE-2017-0143 MS17-010)', 'status': 'in_progress'},"
        "{'content': 'Generate reverse-shell payload', 'status': 'pending'},"
        "{'content': 'Deliver payload via SMB', 'status': 'pending'}"
        "]"
    )
    event = {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{"type": "tool", "name": "write_todos",
                              "content": long_payload}],
            },
        },
    }
    out = _captured(_render_event, event)
    # Each of the five todo items must be visible — none should be
    # eaten by the 160-char truncation that applies to other tools.
    for text in (
        "Run nmap quick scan against 10.129.4.66",
        "Analyze open ports and services",
        "Identify exploitable services (CVE-2017-0143 MS17-010)",
        "Generate reverse-shell payload",
        "Deliver payload via SMB",
    ):
        assert text in out, f"missing todo text: {text}"
    # Status markers / labels present.
    assert "completed" in out
    assert "in_progress" in out
    assert "pending" in out


def test_non_write_todos_tool_still_truncates() -> None:
    """The full-content capture must NOT regress other tools — they should
    still get the short truncated preview."""
    from src.cli.main import _render_event
    long_blob = "x" * 1000
    event = {
        "event": "step",
        "data": {
            "tools": {
                "messages": [{"type": "tool", "name": "surface__nmap_quick",
                              "content": long_blob}],
            },
        },
    }
    out = _captured(_render_event, event)
    # The ellipsis from `_short(..., n=160)` should appear.
    assert "…" in out
    # And the rendered length per line shouldn't exceed something sane.
    assert "xxxxxxxxxxxxxxxx" in out  # at least some of the content


def test_split_message_captures_full_tool_result_content() -> None:
    """A previous bug truncated at 400 chars inside `_split_message`,
    making the long-todo rendering impossible. Confirm the full content
    is now preserved at the split stage."""
    from src.cli.main import _split_message
    long_content = "y" * 2000
    msg = {"type": "tool", "name": "write_todos", "content": long_content}
    _, _, results = _split_message(msg)
    assert results[0]["preview"] == long_content


def test_render_todo_list_handles_unknown_status_with_fallback_glyph() -> None:
    """Future status values shouldn't crash the renderer."""
    from src.cli.main import _render_todo_list
    payload = "Updated to [{'content': 'do thing', 'status': 'frobnicated'}]"
    out = _captured(_render_todo_list, payload)
    assert "do thing" in out
    assert "frobnicated" in out
