"""Lab-mode breadth-tracking state.

Lab mode: map the network, foothold breadth before depth. The
orchestrator needs to remember which hosts have been owned, which have been
skipped (and why), and which are still pending. Phase 2.

This lives outside the LLM context — the orchestrator calls `mark_host_owned`,
`mark_host_skipped`, `next_target` as ordinary tools, and we keep an index in
the engagement filesystem so reruns from a checkpoint reconstruct state.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class HostStatus(StrEnum):
    PENDING = "pending"
    PROBING = "probing"
    OWNED = "owned"
    SKIPPED = "skipped"
    DEAD = "dead"  # unreachable / no services


def _coerce_status(value: Any) -> HostStatus:
    if isinstance(value, HostStatus):
        return value
    try:
        return HostStatus(str(value))
    except ValueError:
        return HostStatus.PENDING


@dataclass
class HostRecord:
    address: str
    status: HostStatus = HostStatus.PENDING
    reason: str = ""
    services_seen: int = 0
    last_change: str = ""  # ISO timestamp string
    notes: str = ""


@dataclass
class LabState:
    engagement_id: str
    hosts: dict[str, HostRecord] = field(default_factory=dict)

    def upsert(self, address: str, **changes: Any) -> HostRecord:
        record = self.hosts.setdefault(address, HostRecord(address=address))
        if "status" in changes:
            changes["status"] = _coerce_status(changes["status"])
        for key, value in changes.items():
            setattr(record, key, value)
        return record

    def to_json(self) -> str:
        return json.dumps(
            {
                "engagement_id": self.engagement_id,
                "hosts": {a: asdict(r) for a, r in self.hosts.items()},
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, raw: str) -> LabState:
        data = json.loads(raw)
        state = cls(engagement_id=data["engagement_id"])
        for address, record_dict in data["hosts"].items():
            record_dict["status"] = _coerce_status(record_dict.get("status", HostStatus.PENDING))
            state.hosts[address] = HostRecord(**record_dict)
        return state

    def pending(self) -> list[HostRecord]:
        return [r for r in self.hosts.values() if r.status == HostStatus.PENDING]

    def owned(self) -> list[HostRecord]:
        return [r for r in self.hosts.values() if r.status == HostStatus.OWNED]

    def progress(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self.hosts.values():
            status = _coerce_status(record.status).value
            counts[status] = counts.get(status, 0) + 1
        return counts


def state_path(engagement_dir: Path, engagement_id: str) -> Path:
    return engagement_dir / engagement_id / "lab_state.json"


def load(engagement_dir: Path, engagement_id: str) -> LabState:
    path = state_path(engagement_dir, engagement_id)
    if not path.exists():
        return LabState(engagement_id=engagement_id)
    return LabState.from_json(path.read_text())


def save(state: LabState, engagement_dir: Path) -> None:
    path = state_path(engagement_dir, state.engagement_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(state.to_json())
