"""Tests for the subgraph-streaming visibility layer.

Gateway: `agent.astream(subgraphs=True)` yields `(namespace_tuple, update)`
pairs. The gateway must unpack these and forward the namespace to the SSE
payload so the CLI can label events by subagent.

CLI: events carrying a `namespace` field should display the subagent's
friendly name as a prefix on tool dispatches and prose lines.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Gateway: _unpack_stream_event
# ---------------------------------------------------------------------------


def test_unpack_handles_root_event_without_subgraph_tuple() -> None:
    """Without `subgraphs=True` (or for root-level events with it), langgraph
    yields a plain dict. We normalize that to `((), dict)`."""
    from src.gateway.main import _unpack_stream_event
    ns, update = _unpack_stream_event({"model": {"messages": []}})
    assert ns == ()
    assert update == {"model": {"messages": []}}


def test_unpack_handles_subgraph_tuple() -> None:
    """With `subgraphs=True`, subagent events come back as
    `(namespace_tuple, update_dict)`."""
    from src.gateway.main import _unpack_stream_event
    ns, update = _unpack_stream_event(
        (("task:abc-uuid", "surface"), {"model": {"messages": []}})
    )
    assert ns == ("task:abc-uuid", "surface")
    assert update == {"model": {"messages": []}}


def test_unpack_does_not_misclassify_two_element_dict_tuples() -> None:
    """A non-namespace tuple (e.g. some custom event payload) should not be
    mistaken for the (namespace, update) shape. We key the detection on the
    *first* element being a tuple."""
    from src.gateway.main import _unpack_stream_event
    weird = ({"a": 1}, {"b": 2})  # both elements are dicts, not a namespace
    ns, update = _unpack_stream_event(weird)
    assert ns == ()
    assert update == weird


# ---------------------------------------------------------------------------
# CLI: _subagent_from_namespace
# ---------------------------------------------------------------------------


def test_subagent_from_namespace_empty_returns_none() -> None:
    from src.cli.main import _subagent_from_namespace
    assert _subagent_from_namespace([]) is None


def test_subagent_from_namespace_picks_known_name() -> None:
    from src.cli.main import _subagent_from_namespace
    # The langgraph namespace path can include both a task-id segment and
    # the subagent name. We pick the one matching a known subagent.
    assert _subagent_from_namespace(["task:abc-uuid", "surface"]) == "surface"
    assert _subagent_from_namespace(["agent:exploit"]) == "exploit"


def test_subagent_from_namespace_returns_none_for_unknown_segments() -> None:
    """Random langgraph internals shouldn't be displayed as a 'subagent'."""
    from src.cli.main import _subagent_from_namespace
    assert _subagent_from_namespace(["__internal__", "checkpoint"]) is None


# ---------------------------------------------------------------------------
# CLI: namespace shows up in the rendered output
# ---------------------------------------------------------------------------


def _captured(fn, *args, **kwargs) -> str:
    from src.cli import main as cli
    from rich.console import Console
    from io import StringIO

    buf = StringIO()
    real = cli.console
    cli.console = Console(file=buf, force_terminal=False, width=200)
    try:
        fn(*args, **kwargs)
    finally:
        cli._set_inflight(None)
        cli.console = real
    return buf.getvalue()


def test_render_event_with_subagent_namespace_labels_dispatch() -> None:
    """When a step event carries a `namespace` indicating it came from the
    surface subagent, the dispatch line should reflect that — not just say
    'model calling nmap_quick'."""
    from src.cli.main import _render_event
    event = {
        "event": "step",
        "namespace": ["task:abc", "surface"],
        "data": {
            "model": {
                "messages": [{
                    "content": [
                        {"type": "text", "text": "Scanning the target..."},
                        {"type": "tool_use", "id": "t1",
                         "name": "surface__nmap_quick",
                         "input": {"target": "10.0.0.1"}},
                    ],
                }],
            },
        },
    }
    out = _captured(_render_event, event)
    # The subagent name appears as a prefix on every line it produces.
    assert "surface" in out
    # Well-known tools render via their friendly verb. `surface__nmap_quick`
    # → `surface scans nmap ...`. The raw MCP tool name is not required;
    # the verb + target IP is enough to identify the call.
    assert "scans" in out
    assert "nmap" in out
    assert "10.0.0.1" in out


def test_render_event_root_namespace_uses_node_name() -> None:
    """For root-level events (no namespace), the dispatcher label is the
    friendly 'orchestrator' name — not the raw langgraph `model` node name."""
    from src.cli.main import _render_event
    event = {
        "event": "step",
        "namespace": [],
        "data": {
            "model": {
                "messages": [{
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "task",
                         "input": {"subagent_type": "surface",
                                   "description": "Recon 10.0.0.1"}},
                    ],
                }],
            },
        },
    }
    out = _captured(_render_event, event)
    assert "orchestrator" in out
    # The `task()` dispatch renders with the "delegates to <subagent>" verb.
    assert "delegates to" in out
    assert "surface" in out