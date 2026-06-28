"""PR-time benchmark — XBOW easy tier, eco profile.

must not regress more than 2 boxes from main. Per-PR budget cap so a
single PR can't burn $100.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import httpx

from src.agent.middleware.budget_guard import _price_step

from . import xbow

RESULTS_DIR = Path(__file__).parent / "results"
GATEWAY = os.environ.get("VOIDSTRIKE_GATEWAY", "http://localhost:8000")
PR_BUDGET_USD = float(os.environ.get("PR_BUDGET_USD", "30.0"))
REGRESSION_TOLERANCE = int(os.environ.get("REGRESSION_TOLERANCE", "2"))


def _iter_usage(obj):
    """Yield (model_name, usage_dict, msg_id) for every message carrying token
    usage anywhere in a streamed event. The gateway's per-episode `cost_usd` is
    always 0.0, so real spend is reconstructed from `usage_metadata` here —
    priced with the same `_price_step` the in-engagement budget guard uses."""
    if isinstance(obj, dict):
        usage = obj.get("usage_metadata")
        if usage:
            meta = obj.get("response_metadata") or {}
            model = meta.get("model_name") or meta.get("model") or ""
            yield model, usage, obj.get("id")
        for v in obj.values():
            yield from _iter_usage(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_usage(v)


async def _real_spend(client: httpx.AsyncClient, start_iso: str) -> float | None:
    """Real LiteLLM-billed spend for [start_iso, now], via the gateway's /spend.

    LiteLLM flushes spend logs asynchronously, so we poll until the row count
    stops growing (settled) or a deadline hits. Returns the USD figure, or None
    when LiteLLM isn't logging (table absent, or no rows landed) — the caller
    then falls back to the token-price estimate.
    """
    deadline = time.monotonic() + 15.0
    prev_rows, spend = -1, 0.0
    while time.monotonic() < deadline:
        end_iso = datetime.utcnow().isoformat()
        try:
            body = (await client.get(
                f"{GATEWAY}/spend", params={"start": start_iso, "end": end_iso}
            )).json()
        except Exception:  # noqa: BLE001
            return None
        if not body.get("available"):
            return None
        rows, spend = int(body.get("rows", 0)), float(body.get("spend_usd", 0.0))
        if rows > 0 and rows == prev_rows:
            return spend  # settled
        prev_rows = rows
        await asyncio.sleep(2.0)
    return spend if prev_rows > 0 else None


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
    # UTC window start, captured before the first model call, so the LiteLLM
    # spend-log lookup brackets exactly this engagement's traffic.
    run_start = datetime.utcnow().isoformat()
    async with httpx.AsyncClient(timeout=None) as client:
        resp = await client.post(
            f"{GATEWAY}/engagements",
            files={"spec": ("spec.yaml", json.dumps(spec).encode(), "application/yaml")},
            data={"profile": profile},
        )
        resp.raise_for_status()
        engagement_id = resp.json()["engagement_id"]
        log_dir = RESULTS_DIR / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{box['name']}_{engagement_id}.jsonl"
        print(f"▶ {box['name']:16} engagement {engagement_id}  "
              f"— watch: voidstrike attach {engagement_id}\n"
              f"  log: {log_path}", flush=True)

        # Stream events until "end", buffering text so we can score the flag.
        # Every raw event is appended to the per-box .jsonl (flushed live) so a
        # full transcript survives for post-hoc diagnosis, not just the heartbeat.
        flag = (box.get("flag") or "").lower()
        rooted = False
        transcript: list[str] = []
        cost = 0.0
        priced_msgs: set = set()  # dedup by message id so we don't double-count
        log_f = log_path.open("w")
        try:
            async with client.stream("GET", f"{GATEWAY}/engagements/{engagement_id}/stream") as stream:
                async for line in stream.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    payload = line[5:].strip()
                    if not payload:
                        continue
                    log_f.write(payload + "\n")
                    log_f.flush()
                    try:
                        event = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    if event.get("event") == "end":
                        break
                    for model, usage, mid in _iter_usage(event.get("data")):
                        if mid is not None:
                            if mid in priced_msgs:
                                continue
                            priced_msgs.add(mid)
                        cost += _price_step(model, usage)
                    data = json.dumps(event).lower()
                    transcript.append(data)
                    if flag:
                        # Flag-equality: the exact build-arg flag must surface.
                        if flag in data:
                            rooted = True
                    elif "objective_met" in data or "root flag captured" in data:
                        rooted = True
        except (asyncio.CancelledError, KeyboardInterrupt):
            # Local Ctrl-C only kills this client — the engagement keeps
            # spending on the gateway. Stop it server-side before we exit.
            # shield so the cancel POST survives the propagating cancellation.
            with contextlib.suppress(Exception):
                await asyncio.shield(
                    client.post(f"{GATEWAY}/engagements/{engagement_id}/cancel")
                )
            raise
        finally:
            log_f.close()

        if flag and not rooted:
            rooted = flag in "".join(transcript)

        # Prefer LiteLLM's real billed spend; fall back to the token estimate
        # when the proxy isn't logging (LiteLLM off / no rows).
        real = await _real_spend(client, run_start)
        estimated = real is None
        cost = cost if estimated else real

    return {
        "name": box["name"],
        "rooted": rooted,
        "cost_usd": cost,
        "cost_estimated": estimated,
        "engagement_id": engagement_id,
    }


async def run_benchmark(box: dict, profile: str = "eco") -> dict:
    """Run a box, provisioning + tearing down its stack if it's an XBOW target."""
    if box.get("xbow_dir"):
        with xbow.provision(box):
            return await run_one(box, profile)
    return await run_one(box, profile)


async def main() -> int:
    # The scored corpus: XBOW level-1 (exact flag-equality). Lab smoke targets
    # have no ground-truth flag — run them separately via `python -m benchmark.lab`.
    boxes = xbow.load(level=1)

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
        if res.get("rooted"):
            mark, tail = "ok ", f"FLAG {box.get('flag', '')}"
        else:
            mark, tail = "MISS", res.get("error", res.get("engagement_id", ""))
        # `~$` = token-price estimate (LiteLLM wasn't logging); `$` = real billed.
        cur = "~$" if res.get("cost_estimated") else "$"
        print(f"[{mark}] {box['name']:16} {cur}{res.get('cost_usd', 0.0):5.2f}  "
              f"(${spent:.2f} spent)  {tail}", flush=True)

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
