"""Lab smoke targets — DVWA / Juice Shop, already up on ops-net.

Kept out of the scored `ci_easy` run because these have no ground-truth flag:
success is the loose `objective_met` substring heuristic, not flag-equality.
Run them on demand to sanity-check the agent against a known-vulnerable box.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from .ci_easy import run_benchmark

LAB_TARGETS = Path(__file__).parent / "data" / "lab_targets.json"


async def main() -> None:
    boxes = json.loads(LAB_TARGETS.read_text()) if LAB_TARGETS.exists() else []
    for box in boxes:
        try:
            res = await run_benchmark(box)
        except Exception as exc:  # noqa: BLE001
            res = {"name": box["name"], "rooted": False, "error": str(exc)}
        mark = "ok " if res.get("rooted") else "MISS"
        why = res.get("error", res.get("engagement_id", ""))
        print(f"[{mark}] {box['name']:16} ${res.get('cost_usd', 0.0):5.2f}  {why}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
