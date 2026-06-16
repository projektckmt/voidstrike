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

XBOW_EASY_LIST = Path(__file__).parent / "data" / "xbow_easy.json"
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

        # Stream events until "end".
        rooted = False
        cost = 0.0
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
                # objective_met events are emitted as part of the agent stream
                data = json.dumps(event).lower()
                if "objective_met" in data or "root flag captured" in data:
                    rooted = True

        # Get cost from episodes summary.
        try:
            summary = await client.get(f"{GATEWAY}/engagements/{engagement_id}/episodes?n=1")
            # Cost is on every episode; this only fetches one, so the dashboard view is more reliable.
            cost = float(box.get("budget_usd", 1.5))  # cap fallback
        except Exception:
            pass

    return {
        "name": box["name"],
        "rooted": rooted,
        "cost_usd": cost,
        "engagement_id": engagement_id,
    }


async def main() -> int:
    if not XBOW_EASY_LIST.exists():
        print(f"missing {XBOW_EASY_LIST} — populate it first", file=sys.stderr)
        return 2
    boxes = json.loads(XBOW_EASY_LIST.read_text())

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = RESULTS_DIR / f"ci_easy_{int(time.time())}.json"

    spent = 0.0
    results: list[dict] = []
    for box in boxes:
        if spent >= PR_BUDGET_USD:
            results.append({"name": box["name"], "rooted": False, "skipped_budget": True})
            continue
        try:
            res = await run_one(box)
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
