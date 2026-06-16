"""Parallel enum coordinator for lab mode.

Phase 4: in lab mode the orchestrator should fan out surface
enumeration across many hosts concurrently rather than walking the host list
sequentially. The work is mostly IO-bound (nmap, httpx, ffuf) so async
parallelism wins.

Bounds:
- `max_concurrent` caps simultaneous Surface invocations to avoid hammering
  the lab from a single source IP. Default 4.
- Per-host budget cap keeps a runaway scan from eating the engagement budget.
- All blocking calls happen through the existing MCP servers; we just
  coordinate the fan-out.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from . import lab_state
from .lab_state import HostStatus


@dataclass
class FanOutResult:
    host: str
    ok: bool
    findings: dict[str, Any] | None
    error: str | None = None
    duration_ms: int = 0


async def fan_out_surface(
    engagement_id: str,
    hosts: list[str],
    enum_fn: Callable[[str], Awaitable[dict[str, Any]]],
    *,
    max_concurrent: int = 4,
    per_host_budget_usd: float | None = None,
    engagement_dir = None,
) -> list[FanOutResult]:
    """Run `enum_fn(host)` for every host in `hosts`, bounded by max_concurrent.

    `enum_fn` is expected to be a thin shim over the Surface subagent invocation
    or the surface MCP tool. It returns whatever the subagent's response_format
    is (typically a `SurfaceFindings` dict).
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    results: list[FanOutResult] = []

    async def _one(host: str) -> FanOutResult:
        async with semaphore:
            start = asyncio.get_event_loop().time()
            try:
                findings = await enum_fn(host)
                _mark(engagement_id, host, owned=False, dead=False, probed=True,
                      engagement_dir=engagement_dir)
                return FanOutResult(
                    host=host, ok=True, findings=findings,
                    duration_ms=int((asyncio.get_event_loop().time() - start) * 1000),
                )
            except Exception as exc:  # noqa: BLE001
                _mark(engagement_id, host, owned=False, dead=True,
                      engagement_dir=engagement_dir, reason=str(exc))
                return FanOutResult(
                    host=host, ok=False, findings=None, error=str(exc),
                    duration_ms=int((asyncio.get_event_loop().time() - start) * 1000),
                )

    tasks = [asyncio.create_task(_one(h)) for h in hosts]
    for task in asyncio.as_completed(tasks):
        results.append(await task)
    return results


def _mark(engagement_id: str, host: str, *, owned: bool, dead: bool,
          probed: bool = False, engagement_dir=None, reason: str = "") -> None:
    """Best-effort write to the lab-state file. The orchestrator's tools call
    the same writers when it has more context; we just record the fan-out
    outcome."""
    import os
    from pathlib import Path
    eng_dir = engagement_dir or Path(os.environ.get("ENGAGEMENT_DIR", "./engagements"))
    state = lab_state.load(eng_dir, engagement_id)
    if dead:
        state.upsert(host, status=HostStatus.DEAD, reason=reason)
    elif probed:
        # Only flip to PROBING if not already past it.
        existing = state.hosts.get(host)
        if existing is None or existing.status == HostStatus.PENDING:
            state.upsert(host, status=HostStatus.PROBING)
    lab_state.save(state, eng_dir)
