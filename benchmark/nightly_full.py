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
    for box in public:
        results["public"].append(await run_benchmark(box, profile="max"))
    for box in holdout:
        results["holdout"].append(await run_benchmark(box, profile="max"))

    out.write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
