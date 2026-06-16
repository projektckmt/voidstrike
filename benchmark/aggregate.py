"""Roll up benchmark results across runs.

Reads every `ci_easy_*.json` and `nightly_*.json` under `results/`, computes
the trend line plan §9 cares about: pass-rate over time, time-to-root
distribution, cost per box, failure-mode clustering.

The number that matters is the trend, not the absolute. A drop from 98% to
96% after a refactor is a real signal even if 96% would look fine in isolation.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

RESULTS_DIR = Path(__file__).parent / "results"


def main() -> None:
    runs = sorted(RESULTS_DIR.glob("*.json"))
    if not runs:
        print("no results yet")
        return

    trend: list[dict] = []
    for path in runs:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        results = _collect_results(data)
        if not results:
            continue
        rooted = sum(1 for r in results if r.get("rooted"))
        total = len(results)
        ts = _parse_run_ts(path)
        trend.append({
            "file": path.name,
            "ts": ts.isoformat() if ts else None,
            "rooted": rooted,
            "total": total,
            "pct": (rooted / total * 100) if total else 0.0,
            "median_cost_usd": _safe_median(r.get("cost_usd", 0.0) for r in results),
            "failure_classes": _classify_failures(results),
        })

    print(f"{len(trend)} runs aggregated")
    print()
    print(f"{'run':40} {'rooted':>10} {'pct':>8} {'med_cost':>10}")
    for entry in trend:
        pct = entry["pct"]
        print(
            f"{entry['file']:40} "
            f"{entry['rooted']}/{entry['total']:<6} "
            f"{pct:7.1f}% "
            f"${entry['median_cost_usd']:9.4f}"
        )

    # Show recent failure-class breakdown if there's a latest run.
    if trend:
        latest = trend[-1]["failure_classes"]
        if latest:
            print()
            print("Latest run — failure clustering:")
            for cls, count in latest.most_common():
                print(f"  {cls}: {count}")

    # Write a summary so the dashboard / CI can pick it up.
    summary_path = RESULTS_DIR / "summary.json"
    summary_path.write_text(json.dumps({"trend": trend}, default=str, indent=2))
    print(f"\nwrote {summary_path}")


def _collect_results(data: dict) -> list[dict]:
    """Both ci_easy.json and nightly_*.json wrap their results differently."""
    if "results" in data:
        return data["results"]
    items: list[dict] = []
    items.extend(data.get("public", []))
    items.extend(data.get("holdout", []))
    return items


def _parse_run_ts(path: Path) -> datetime | None:
    """Filenames look like `ci_easy_1700000000.json` — epoch seconds."""
    parts = path.stem.rsplit("_", 1)
    if len(parts) != 2:
        return None
    try:
        return datetime.fromtimestamp(int(parts[-1]), tz=timezone.utc)
    except ValueError:
        return None


def _safe_median(values) -> float:
    nums = [float(v) for v in values if v not in (None, "")]
    return statistics.median(nums) if nums else 0.0


def _classify_failures(results: list[dict]) -> Counter:
    """Cluster non-rooted results by their error/skip reason."""
    counter: Counter = Counter()
    for r in results:
        if r.get("rooted"):
            continue
        if r.get("skipped_budget"):
            counter["skipped_budget"] += 1
        elif r.get("error"):
            # Truncate so we don't fragment on tracebacks.
            counter[r["error"].splitlines()[0][:80]] += 1
        else:
            counter["unrooted_no_error"] += 1
    return counter


if __name__ == "__main__":
    main()
