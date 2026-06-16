"""CLI render-helper tests.

`_message_content` was crashing on non-dict messages in the streamed event
payloads. These tests pin the shapes we actually see in production.
"""

from __future__ import annotations

import json


def test_dict_with_string_content() -> None:
    from src.cli.main import _message_content
    assert _message_content({"content": "hello"}) == "hello"


def test_plain_string_message() -> None:
    from src.cli.main import _message_content
    assert _message_content("just a string") == "just a string"


def test_anthropic_text_blocks() -> None:
    from src.cli.main import _message_content
    msg = {"content": [{"type": "text", "text": "this is text"}]}
    assert _message_content(msg) == "this is text"


def test_anthropic_mixed_blocks_render_tool_use_placeholders() -> None:
    from src.cli.main import _message_content
    msg = {"content": [
        {"type": "text", "text": "calling nmap"},
        {"type": "tool_use", "name": "surface__nmap_quick", "input": {"target": "10.0.0.1"}},
        {"type": "text", "text": "done"},
    ]}
    out = _message_content(msg)
    assert "calling nmap" in out
    assert "<tool_use surface__nmap_quick>" in out
    assert "done" in out


def test_anthropic_tool_result_blocks() -> None:
    from src.cli.main import _message_content
    msg = {"content": [
        {"type": "tool_result", "content": "open: 22/tcp ssh"},
    ]}
    out = _message_content(msg)
    assert "<tool_result>" in out


def test_falls_back_for_object_with_content_attr() -> None:
    from src.cli.main import _message_content

    class FakeMessage:
        content = "object content"

    assert _message_content(FakeMessage()) == "object content"


def test_summarize_handles_list_of_strings_in_messages() -> None:
    """The historical crash: `last.get("content")` on a non-dict."""
    from src.cli.main import _summarize
    payload = {"messages": ["just a string"]}
    # Must not raise — even if the message isn't a dict.
    out = _summarize(payload)
    assert "just a string" in out


def test_summarize_handles_dict_message() -> None:
    from src.cli.main import _summarize
    payload = {"messages": [{"content": "from the model"}]}
    out = _summarize(payload)
    assert "from the model" in out


def test_summarize_dumps_payload_when_no_messages() -> None:
    from src.cli.main import _summarize
    payload = {"some_state": "value"}
    out = _summarize(payload)
    # Should fall back to a JSON dump prefix.
    assert "some_state" in out
