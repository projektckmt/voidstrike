"""_extract_interrupt: pull a HITL interrupt payload out of a stream update."""

from __future__ import annotations

from dataclasses import dataclass

from src.gateway.main import _extract_interrupt


@dataclass
class _FakeInterrupt:
    value: object


def test_returns_value_from_interrupt_tuple() -> None:
    payload = {"kind": "stuck_report", "engagement_id": "x"}
    update = {"__interrupt__": (_FakeInterrupt(value=payload),)}
    assert _extract_interrupt(update) == payload


def test_none_for_ordinary_step_update() -> None:
    assert _extract_interrupt({"surface": {"messages": []}}) is None


def test_none_for_non_dict() -> None:
    assert _extract_interrupt(("agent:foo", "surface")) is None


def test_none_for_empty_interrupt() -> None:
    assert _extract_interrupt({"__interrupt__": ()}) is None
