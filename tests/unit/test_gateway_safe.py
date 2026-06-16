"""Tests for the gateway's `_safe` / `_dump` payload serializer.

The first version of `_safe` used `default=str` which collapsed langchain
BaseMessage objects into their Python repr, hiding the structured content
blocks the CLI needs to extract tool_use / tool_result blocks. These tests
pin the structured-preservation behavior so it can't regress.
"""

from __future__ import annotations

import pytest


def test_dump_passes_through_plain_types() -> None:
    from src.gateway.main import _dump
    assert _dump(None) is None
    assert _dump(42) == 42
    assert _dump("hello") == "hello"
    assert _dump([1, 2, "x"]) == [1, 2, "x"]
    assert _dump({"a": 1, "b": [{"c": 2}]}) == {"a": 1, "b": [{"c": 2}]}


def test_dump_preserves_anthropic_content_blocks_inside_dicts() -> None:
    """The shape we actually see during a run: a dict with a 'messages'
    list, each message being a dict whose `content` is a list of blocks.
    `_dump` must NOT collapse the blocks to a string."""
    from src.gateway.main import _dump
    payload = {
        "model": {
            "messages": [
                {
                    "content": [
                        {"type": "text", "text": "About to scan"},
                        {"type": "tool_use", "name": "surface__nmap_quick",
                         "input": {"target": "10.0.0.1"}},
                    ],
                    "type": "ai",
                },
            ],
        },
    }
    result = _dump(payload)
    msg = result["model"]["messages"][0]
    assert isinstance(msg["content"], list), \
        "content list must survive — collapsing it to str() hides tool_use blocks"
    assert msg["content"][1]["type"] == "tool_use"
    assert msg["content"][1]["name"] == "surface__nmap_quick"


def test_dump_converts_basemessage_to_dict() -> None:
    """If a real BaseMessage is in the payload, it should be converted via
    model_dump() into its dict form — not str()'d."""
    try:
        from langchain_core.messages import AIMessage  # type: ignore[import-not-found]
    except ImportError:
        pytest.skip("langchain_core not available in this venv")

    from src.gateway.main import _dump
    msg = AIMessage(content=[
        {"type": "text", "text": "scanning"},
        {"type": "tool_use", "id": "x", "name": "nmap_quick",
         "input": {"target": "1.2.3.4"}},
    ])
    out = _dump({"messages": [msg]})
    first = out["messages"][0]
    assert isinstance(first, dict)
    # The content list survives:
    content = first.get("content")
    assert isinstance(content, list), f"expected list of blocks, got {type(content)}"
    block_types = [b.get("type") for b in content]
    assert "text" in block_types
    assert "tool_use" in block_types


def test_safe_round_trips_to_pure_json() -> None:
    """Whatever `_dump` produces, the wrapping `_safe` must run a JSON
    round-trip that completes without error."""
    import json as _json
    from src.gateway.main import _safe
    payload = {"event": "step", "messages": [{"content": "ok"}]}
    out = _safe(payload)
    # If the output isn't pure-JSON, this will raise.
    _json.dumps(out)
    assert out["event"] == "step"


def test_safe_falls_back_on_unserializable_via_default_str() -> None:
    """Outside of langchain messages, we still allow `default=str` as a
    last-resort fallback so arbitrary opaque objects don't crash the
    stream."""
    from src.gateway.main import _safe

    class Opaque:
        def __repr__(self): return "<Opaque>"

    out = _safe({"weird": Opaque()})
    assert out["weird"] == "<Opaque>"
