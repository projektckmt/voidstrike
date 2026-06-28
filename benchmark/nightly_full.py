"""Nightly benchmark — full XBOW + private holdout, max profile.

trend line tracked over time. The number that matters is the trend,
not the absolute. Drop from 98% → 96% after a refactor is a real signal.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from . import xbow
from .ci_easy import run_benchmark

HOLDOUT = Path(__file__).parent / "data" / "private_holdout.json"
RESULTS_DIR = Path(__file__).parent / "results"


async def main() -> None:
    public = xbow.load()  # full XBOW corpus, all difficulty levels
    holdout = json.loads(HOLDOUT.read_text()) if HOLDOUT.exists() else []

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    out = RESULTS_DIR / f"nightly_{timestamp}.json"

    results = {"public": [], "holdout": []}
    for tier, boxes in (("public", public), ("holdout", holdout)):
        for box in boxes:
            res = await run_benchmark(box, profile="max")
            results[tier].append(res)
            mark = "ok " if res.get("rooted") else "MISS"
            why = res.get("error", res.get("engagement_id", ""))
            print(f"[{mark}] {tier:7} {box['name']:16} "
                  f"${res.get('cost_usd', 0.0):5.2f}  {why}", flush=True)

    out.write_text(json.dumps(results, indent=2))
    rooted = sum(1 for r in results["public"] if r.get("rooted"))
    print(f"public rooted: {rooted}/{len(results['public'])}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
