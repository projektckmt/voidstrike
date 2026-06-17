"""Challenge lifecycle runner: spawn → engage → verify → teardown.

Wraps an engagement with HTB target provisioning so a run (or a benchmark
sweep) is unattended end-to-end. The HTB calls and the actual "run the
engagement" step are both **injected**, so this module is pure orchestration and
unit-testable without a token or a running gateway:

    result = await run_challenge(
        spec.htb,
        client=HtbClient(),                  # or a fake in tests
        engage=lambda ip: _run_engagement(ip),  # returns EngageOutcome
    )

Teardown runs in a `finally`, so a crashed or cancelled run never leaves a
machine occupying your HTB slot.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from ..integrations.htb import HtbClient, HtbError, Machine
from ..schemas.engagement import HtbConfig

log = logging.getLogger("voidstrike.challenge")


@dataclass
class EngageOutcome:
    """What the injected `engage` callable returns."""
    flags: list[str] = field(default_factory=list)
    success: bool = False          # rooted / all objectives met
    detail: str = ""


@dataclass
class ChallengeResult:
    machine: str
    status: str                    # solved | failed | error
    ip: str | None = None
    flags_submitted: list[str] = field(default_factory=list)
    flag_errors: list[str] = field(default_factory=list)
    teardown_done: bool = False
    error: str | None = None


# engage callable: given the resolved target IP, run the engagement and report.
EngageFn = Callable[[str], Awaitable[EngageOutcome]]


async def run_challenge(
    cfg: HtbConfig,
    *,
    client: HtbClient,
    engage: EngageFn,
    force_terminate_other: bool = False,
    on_event: Callable[[str, str], None] | None = None,
) -> ChallengeResult:
    """Provision the HTB machine in `cfg`, run `engage(ip)`, submit flags, and
    tear down per `cfg.teardown`.

    `force_terminate_other`: if a *different* machine is already spawned on the
    account, terminate it first (off by default — we don't nuke an in-progress
    box without being told to).
    """
    def _ev(stage: str, msg: str) -> None:
        log.info("challenge %s [%s] %s", cfg.machine, stage, msg)
        if on_event:
            on_event(stage, msg)

    result = ChallengeResult(machine=cfg.machine, status="error")
    machine: Machine | None = None
    provisioned = False  # did WE bring our target up (spawn/reuse)? gates teardown

    try:
        # 1. Resolve.
        machine = await client.resolve_machine(cfg.machine)
        result.ip = machine.ip
        _ev("resolve", f"id={machine.id} kind={machine.kind}")

        # 2. Pre-flight: reconcile against whatever is already spawned.
        active = await client.active_machine()
        if active and active.id != machine.id:
            if not force_terminate_other:
                raise HtbError(
                    f"a different machine ({active.name!r}, id={active.id}) is already "
                    "spawned — terminate it or pass force_terminate_other=True"
                )
            _ev("preflight", f"terminating other active machine {active.name!r}")
            await client.terminate(active)
            active = None

        # 3. Spawn (or reuse) + wait for the IP.
        if active and active.id == machine.id:
            machine.ip = active.ip
            if cfg.reset_before:
                _ev("reset", "resetting already-spawned target to clean state")
                await client.reset(machine)
            _ev("spawn", "target already spawned; reusing")
            provisioned = True
        else:
            _ev("spawn", "requesting spawn")
            await client.spawn(machine)
            provisioned = True

        ip = machine.ip or await client.wait_for_ip(
            machine, timeout_s=cfg.spawn_timeout_s
        )
        result.ip = ip
        _ev("ready", f"target IP {ip}")

        # 4. Run the engagement.
        outcome = await engage(ip)
        result.status = "solved" if outcome.success else "failed"
        _ev("engaged", f"{result.status}; {len(outcome.flags)} flag(s) captured")

        # 5. Submit captured flags (best-effort; a dup/late submit isn't fatal).
        if cfg.submit_flags:
            for flag in outcome.flags:
                try:
                    await client.submit_flag(machine, flag, difficulty=cfg.difficulty)
                    result.flags_submitted.append(flag)
                except HtbError as exc:
                    result.flag_errors.append(f"{flag[:8]}…: {exc}")
                    _ev("flag", f"submit failed: {exc}")

        return result

    except Exception as exc:  # noqa: BLE001 — record, still run teardown below
        result.status = "error"
        result.error = str(exc)
        _ev("error", str(exc))
        return result

    finally:
        # Teardown ALWAYS runs (success, failure, or crash) so we never strand a
        # machine WE provisioned — but never touch a box we didn't bring up (e.g.
        # we errored out on a conflict). Best-effort; a teardown failure doesn't
        # mask the run result.
        if machine is not None and provisioned and _should_teardown(cfg.teardown, result.status):
            try:
                await client.terminate(machine)
                result.teardown_done = True
                _ev("teardown", "machine terminated")
            except HtbError as exc:
                _ev("teardown", f"failed (leaving machine up): {exc}")


def _should_teardown(policy: str, status: str) -> bool:
    """`never` → no; `on_success` → only when solved; `on_complete` → always."""
    if policy == "never":
        return False
    if policy == "on_success":
        return status == "solved"
    return True  # on_complete (default)
