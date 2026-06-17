"""Tests for the challenge lifecycle runner (spawn → engage → teardown).

The HTB client and the engage step are both injected, so these exercise the
orchestration directly: teardown always runs, the teardown policy, flag
submission, the already-spawned reconciliation, and engage-failure handling.
"""

from __future__ import annotations

import asyncio

from src.agent.challenge import EngageOutcome, run_challenge
from src.integrations.htb import HtbError, Machine
from src.schemas.engagement import HtbConfig


def _run(coro):
    return asyncio.run(coro)


class FakeHtb:
    """Duck-typed stand-in for HtbClient. Records calls; configurable active box."""

    def __init__(self, *, active: Machine | None = None, resolved: Machine | None = None,
                 flag_fails: bool = False):
        self._active = active
        self._resolved = resolved or Machine(id=10, name="Support", kind="retired")
        self.calls: list[str] = []
        self.flag_fails = flag_fails
        self.submitted: list[str] = []

    async def resolve_machine(self, name_or_id):
        self.calls.append("resolve")
        return self._resolved

    async def active_machine(self):
        self.calls.append("active")
        return self._active

    async def spawn(self, machine):
        self.calls.append("spawn")
        self._active = machine  # now it's the active box

    async def reset(self, machine):
        self.calls.append("reset")

    async def terminate(self, machine):
        self.calls.append("terminate")
        self._active = None

    async def wait_for_ip(self, machine, *, timeout_s=180.0, interval_s=6.0):
        self.calls.append("wait_for_ip")
        machine.ip = "10.10.10.5"
        return "10.10.10.5"

    async def submit_flag(self, machine, flag, *, difficulty=5):
        self.calls.append("submit_flag")
        if self.flag_fails:
            raise HtbError("already owned")
        self.submitted.append(flag)


def _cfg(**kw) -> HtbConfig:
    return HtbConfig(machine="Support", **kw)


async def _engage_ok(ip):
    return EngageOutcome(flags=["userflag", "rootflag"], success=True)


async def _engage_fail(ip):
    return EngageOutcome(flags=["userflag"], success=False)


# --- happy path -------------------------------------------------------------

def test_spawn_engage_submit_teardown():
    htb = FakeHtb()
    res = _run(run_challenge(_cfg(), client=htb, engage=_engage_ok))
    assert res.status == "solved"
    assert res.ip == "10.10.10.5"
    assert res.flags_submitted == ["userflag", "rootflag"]
    assert res.teardown_done is True
    assert htb.calls == ["resolve", "active", "spawn", "wait_for_ip",
                         "submit_flag", "submit_flag", "terminate"]


def test_engage_receives_resolved_ip():
    htb = FakeHtb()
    seen = {}

    async def engage(ip):
        seen["ip"] = ip
        return EngageOutcome(flags=[], success=True)

    _run(run_challenge(_cfg(submit_flags=False), client=htb, engage=engage))
    assert seen["ip"] == "10.10.10.5"


# --- teardown policy --------------------------------------------------------

def test_teardown_never_leaves_box_up():
    htb = FakeHtb()
    res = _run(run_challenge(_cfg(teardown="never"), client=htb, engage=_engage_ok))
    assert res.teardown_done is False
    assert "terminate" not in htb.calls


def test_teardown_on_success_skips_on_failure():
    htb = FakeHtb()
    res = _run(run_challenge(_cfg(teardown="on_success"), client=htb, engage=_engage_fail))
    assert res.status == "failed"
    assert res.teardown_done is False
    assert "terminate" not in htb.calls


def test_teardown_on_success_terminates_on_success():
    htb = FakeHtb()
    res = _run(run_challenge(_cfg(teardown="on_success"), client=htb, engage=_engage_ok))
    assert res.teardown_done is True


def test_teardown_runs_even_when_engage_raises():
    htb = FakeHtb()

    async def boom(ip):
        raise RuntimeError("agent crashed")

    res = _run(run_challenge(_cfg(), client=htb, engage=boom))
    assert res.status == "error"
    assert "agent crashed" in res.error
    assert res.teardown_done is True            # box still torn down
    assert "terminate" in htb.calls


# --- reconciliation with an already-spawned machine -------------------------

def test_reuses_already_spawned_target():
    target = Machine(id=10, name="Support", kind="retired", ip="10.10.10.9")
    htb = FakeHtb(active=target, resolved=Machine(id=10, name="Support", kind="retired"))
    res = _run(run_challenge(_cfg(), client=htb, engage=_engage_ok))
    assert "spawn" not in htb.calls             # reused, didn't re-spawn
    assert res.status == "solved"


def test_reset_before_on_reused_target():
    target = Machine(id=10, name="Support", ip="10.10.10.9")
    htb = FakeHtb(active=target, resolved=Machine(id=10, name="Support"))
    _run(run_challenge(_cfg(reset_before=True), client=htb, engage=_engage_ok))
    assert "reset" in htb.calls


def test_other_active_machine_blocks_without_force():
    other = Machine(id=999, name="OtherBox")
    htb = FakeHtb(active=other, resolved=Machine(id=10, name="Support"))
    res = _run(run_challenge(_cfg(), client=htb, engage=_engage_ok))
    assert res.status == "error"
    assert "already spawned" in res.error
    assert "spawn" not in htb.calls             # didn't touch ours
    assert "terminate" not in htb.calls         # didn't nuke theirs


def test_force_terminate_other_then_spawns():
    other = Machine(id=999, name="OtherBox")
    htb = FakeHtb(active=other, resolved=Machine(id=10, name="Support"))
    res = _run(run_challenge(_cfg(), client=htb, engage=_engage_ok,
                            force_terminate_other=True))
    assert res.status == "solved"
    assert htb.calls.count("terminate") == 2    # the other one, then our own teardown
    assert "spawn" in htb.calls


# --- flag submission resilience ---------------------------------------------

def test_flag_submit_error_recorded_not_fatal():
    htb = FakeHtb(flag_fails=True)
    res = _run(run_challenge(_cfg(), client=htb, engage=_engage_ok))
    assert res.status == "solved"               # run still counts as solved
    assert res.flags_submitted == []
    assert len(res.flag_errors) == 2
    assert res.teardown_done is True


def test_on_event_callback_fires():
    htb = FakeHtb()
    events = []
    _run(run_challenge(_cfg(), client=htb, engage=_engage_ok,
                      on_event=lambda stage, msg: events.append(stage)))
    assert "resolve" in events and "ready" in events and "teardown" in events
