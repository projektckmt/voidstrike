"""Shared helpers for the middleware guards.

These were copy-pasted across several guard modules; hoisted here so there's one
copy to fix when the message/tool-content shapes shift.
"""

from __future__ import annotations

import json
from typing import Any


def parse_tool_content(result: Any) -> Any:
    """Best-effort decode of a ToolMessage's content into a Python object.

    Returns the decoded JSON, the raw content if it isn't a JSON string, or None
    when it's a string that doesn't parse.
    """
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


def messages_from_state(state: Any) -> list[Any]:
    """Pull the message list off a dict-or-object agent state."""
    if isinstance(state, dict):
        return state.get("messages") or []
    return getattr(state, "messages", None) or []
