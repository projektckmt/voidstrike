"""PR-time benchmark — XBOW easy tier, eco profile.

must not regress more than 2 boxes from main. Per-PR budget cap so a
single PR can't burn $100.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import httpx

from . import xbow

LAB_TARGETS = Path(__file__).parent / "data" / "lab_targets.json"
RESULTS_DIR = Path(__file__).parent / "results"
GATEWAY = os.environ.get("VOIDSTRIKE_GATEWAY", "http://localhost:8000")
PR_BUDGET_USD = float(os.environ.get("PR_BUDGET_USD", "30.0"))
REGRESSION_TOLERANCE = int(os.environ.get("REGRESSION_TOLERANCE", "2"))


async def run_one(box: dict, profile: str = "eco") -> dict:
    """Start one engagement, wait for it to complete, return the outcome."""
    spec = {
        "name": box["name"],
        "mode": "ctf",
        "targets": [box["target"]],
        "objective": box.get("objective", "root flag"),
        "budget_usd": box.get("budget_usd", 1.5),
        "profile": profile,
    }
    async with httpx.AsyncClient(timeout=None) as client:
        resp = await client.post(
            f"{GATEWAY}/engagements",
            files={"spec": ("spec.yaml", json.dumps(spec).encode(), "application/yaml")},
            data={"profile": profile},
        )
        resp.raise_for_status()
        engagement_id = resp.json()["engagement_id"]

        # Stream events until "end", buffering text so we can score the flag.
        flag = (box.get("flag") or "").lower()
        rooted = False
        transcript: list[str] = []
        async with client.stream("GET", f"{GATEWAY}/engagements/{engagement_id}/stream") as stream:
            async for line in stream.aiter_lines():
                if not line.startswith("data:"):
                    continue
                payload = line[5:].strip()
                if not payload:
                    continue
                try:
                    event = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                if event.get("event") == "end":
                    break
                data = json.dumps(event).lower()
                transcript.append(data)
                if flag:
                    # Flag-equality: the exact build-arg flag must surface.
                    if flag in data:
                        rooted = True
                elif "objective_met" in data or "root flag captured" in data:
                    rooted = True

        if flag and not rooted:
            rooted = flag in "".join(transcript)

        cost = await _engagement_cost(client, engagement_id)

    return {
        "name": box["name"],
        "rooted": rooted,
        "cost_usd": cost,
        "engagement_id": engagement_id,
    }


async def _engagement_cost(client: httpx.AsyncClient, engagement_id: str) -> float:
    """Real spend = sum of cost_usd over every episode for this engagement."""
    try:
        resp = await client.get(f"{GATEWAY}/engagements/{engagement_id}/episodes?n=100000")
        eps = resp.json().get("episodes", [])
        return sum(float(e.get("cost_usd") or 0.0) for e in eps)
    except Exception:
        return 0.0


async def run_benchmark(box: dict, profile: str = "eco") -> dict:
    """Run a box, provisioning + tearing down its stack if it's an XBOW target."""
    if box.get("xbow_dir"):
        with xbow.provision(box):
            return await run_one(box, profile)
    return await run_one(box, profile)


async def main() -> int:
    # Lab smoke targets (already on ops-net) + the XBOW level-1 corpus.
    boxes = xbow.load(level=1)
    if LAB_TARGETS.exists():
        boxes = json.loads(LAB_TARGETS.read_text()) + boxes

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"ci_easy_{int(time.time())}.json"

    spent = 0.0
    results: list[dict] = []
    for box in boxes:
        if spent >= PR_BUDGET_USD:
            results.append({"name": box["name"], "rooted": False, "skipped_budget": True})
            continue
        try:
            res = await run_benchmark(box)
        except Exception as exc:  # noqa: BLE001
            res = {"name": box["name"], "rooted": False, "error": str(exc)}
        results.append(res)
        spent += res.get("cost_usd", 0.0)

    rooted = sum(1 for r in results if r.get("rooted"))
    out.write_text(json.dumps({"results": results, "rooted": rooted, "total": len(boxes)}, indent=2))
    print(f"Rooted: {rooted}/{len(boxes)}  spent ${spent:.2f}")

    baseline = _load_baseline()
    if baseline is not None and rooted < baseline - REGRESSION_TOLERANCE:
        print(f"REGRESSION: rooted {rooted} < baseline {baseline} - tolerance {REGRESSION_TOLERANCE}")
        return 1
    return 0


def _load_baseline() -> int | None:
    baseline_path = RESULTS_DIR / "baseline.json"
    if not baseline_path.exists():
        return None
    return json.loads(baseline_path.read_text()).get("rooted")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
