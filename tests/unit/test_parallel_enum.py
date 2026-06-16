"""Parallel-enum coordinator tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from src.agent.lab_state import HostStatus, LabState
from src.agent.parallel_enum import fan_out_surface


@pytest.mark.asyncio
async def test_fans_out_with_concurrency_bound(tmp_path: Path) -> None:
    in_flight = 0
    peak = 0

    async def enum_fn(host: str):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.02)
        in_flight -= 1
        return {"host": host, "services": []}

    hosts = [f"10.0.0.{i}" for i in range(8)]
    results = await fan_out_surface(
        "e1", hosts, enum_fn,
        max_concurrent=3,
        engagement_dir=tmp_path,
    )
    assert len(results) == 8
    assert peak <= 3


@pytest.mark.asyncio
async def test_dead_host_marked(tmp_path: Path) -> None:
    async def enum_fn(host: str):
        raise RuntimeError("no route to host")

    await fan_out_surface(
        "e1", ["10.0.0.99"], enum_fn,
        max_concurrent=1,
        engagement_dir=tmp_path,
    )
    state = LabState.from_json((tmp_path / "e1" / "lab_state.json").read_text())
    assert state.hosts["10.0.0.99"].status == HostStatus.DEAD


@pytest.mark.asyncio
async def test_successful_host_marked_probing(tmp_path: Path) -> None:
    async def enum_fn(host: str):
        return {"host": host, "services": []}

    await fan_out_surface(
        "e1", ["10.0.0.1"], enum_fn,
        max_concurrent=1,
        engagement_dir=tmp_path,
    )
    state = LabState.from_json((tmp_path / "e1" / "lab_state.json").read_text())
    assert state.hosts["10.0.0.1"].status == HostStatus.PROBING
