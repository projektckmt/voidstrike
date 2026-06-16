"""Surface nuclei wrapper behavior.

nuclei exits non-zero both for genuine failures *and* when its tag/severity
filter selects zero templates (e.g. an invented tag like `nextjs`). The wrapper
must distinguish those: a zero-template-match is a clean empty result with
guidance, a real failure surfaces stderr in the error message.
"""

from __future__ import annotations

import json

import pytest


def _exec_returning(rc, stdout="", stderr=""):
    async def _fake(cmd, timeout_s=600):
        _fake.cmd = cmd
        return {
            "ok": rc == 0,
            "rc": rc,
            "stdout": stdout,
            "stderr": stderr,
            **({} if rc == 0 else {"error": "timeout" if rc == -1 else "nonzero"}),
        }
    return _fake


@pytest.mark.asyncio
async def test_nuclei_parses_and_sorts_matches(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    stdout = "\n".join([
        json.dumps({"template-id": "apache-detect", "info": {"name": "Apache", "severity": "info"}, "type": "http", "matched-at": "http://t/"}),
        json.dumps({"template-id": "CVE-2025-1", "info": {"name": "RCE", "severity": "critical", "classification": {"cve-id": "CVE-2025-1"}}, "type": "http", "matched-at": "http://t/x"}),
        "garbage-non-json",
    ])
    monkeypatch.setattr(server, "_exec", _exec_returning(0, stdout=stdout))
    out = await server.nuclei("http://t", severity="")
    assert out["ok"] is True
    assert out["finding_count"] == 2  # garbage line skipped
    assert out["findings"][0]["severity"] == "critical"  # worst first
    assert out["findings"][0]["cve"] == "CVE-2025-1"


@pytest.mark.asyncio
async def test_nuclei_severity_flag_omitted_when_blank(monkeypatch) -> None:
    from src.mcp_servers.surface import server
    fake = _exec_returning(0, stdout="")
    monkeypatch.setattr(server, "_exec", fake)
    await server.nuclei("http://t", severity="")
    assert "-severity" not in fake.cmd
    # and present when provided
    fake2 = _exec_returning(0, stdout="")
    monkeypatch.setattr(server, "_exec", fake2)
    await server.nuclei("http://t", severity="high", tags="cve")
    assert "-severity" in fake2.cmd and "-tags" in fake2.cmd


@pytest.mark.asyncio
async def test_nuclei_zero_template_match_is_benign_when_templates_present(monkeypatch) -> None:
    """tags='nextjs' selects no templates (but templates ARE installed) → nuclei
    exits 1 with 'no templates provided for scan'. That's a bad-filter, so it's a
    clean empty result with guidance, not a hard error."""
    from src.mcp_servers.surface import server
    monkeypatch.setattr(server, "_nuclei_templates_present", lambda: True)
    monkeypatch.setattr(
        server, "_exec",
        _exec_returning(1, stderr="[FTL] Could not run nuclei: no templates provided for scan"),
    )
    out = await server.nuclei("http://t", tags="nextjs,next")
    assert out["ok"] is True
    assert out["finding_count"] == 0
    assert "note" in out and "0 templates" in out["note"]


@pytest.mark.asyncio
async def test_nuclei_no_templates_installed_is_a_hard_error(monkeypatch) -> None:
    """Same 'no templates provided' stderr, but the template store is MISSING —
    that's an environment failure, so it must be ok:False with the real remedy,
    not a benign empty that makes the agent re-tune its tags forever."""
    from src.mcp_servers.surface import server
    monkeypatch.setattr(server, "_nuclei_templates_present", lambda: False)
    monkeypatch.setattr(
        server, "_exec",
        _exec_returning(1, stderr="[FTL] no templates provided for scan"),
    )
    out = await server.nuclei("http://t", tags="cve,exposure")
    assert out["ok"] is False
    assert "templates are NOT installed" in out["error"]
    assert "update-templates" in out["error"]


@pytest.mark.asyncio
async def test_nuclei_uses_no_mhe_so_flaky_hosts_arent_abandoned(monkeypatch) -> None:
    """A flaky HTB box trips nuclei's max-host-error skip (30 errors → drop the
    rest of the templates), so it exits 0 with only the fast early detections and
    misses later CVE templates. `-no-mhe` disables that."""
    from src.mcp_servers.surface import server
    fake = _exec_returning(0, stdout="")
    monkeypatch.setattr(server, "_exec", fake)
    await server.nuclei("http://t")
    assert "-no-mhe" in fake.cmd


@pytest.mark.asyncio
async def test_nuclei_raises_request_timeout_for_vpn_latency(monkeypatch) -> None:
    """Heavyweight RCE templates (React2Shell's POST) and VPN latency need more
    than nuclei's default 10s per-request timeout, or they i/o-timeout and the
    vuln is missed. We pass a generous -timeout and -retries."""
    from src.mcp_servers.surface import server
    fake = _exec_returning(0, stdout="")
    monkeypatch.setattr(server, "_exec", fake)
    await server.nuclei("http://t")
    assert "-timeout" in fake.cmd
    assert int(fake.cmd[fake.cmd.index("-timeout") + 1]) >= 20
    assert "-retries" in fake.cmd


@pytest.mark.asyncio
async def test_nuclei_excludes_code_protocol_templates(monkeypatch) -> None:
    """`code`-protocol templates need a local go/python engine (and `-code`),
    don't apply to remote scanning, and emit 'no valid engine found' warnings —
    exclude the type so they neither run nor spam the log."""
    from src.mcp_servers.surface import server
    fake = _exec_returning(0, stdout="")
    monkeypatch.setattr(server, "_exec", fake)
    await server.nuclei("http://t")
    assert "-exclude-type" in fake.cmd
    assert fake.cmd[fake.cmd.index("-exclude-type") + 1] == "code"


@pytest.mark.asyncio
async def test_nuclei_defaults_to_run_to_completion(monkeypatch) -> None:
    """By default there's no wall-clock cap — the scan runs to completion, since
    a short cap returns only the fast early detections and misses the CVE
    templates that run after them."""
    from src.mcp_servers.surface import server

    seen = {}

    async def fake_exec(cmd, timeout_s=600):
        seen["timeout_s"] = timeout_s
        return {"ok": True, "rc": 0, "stdout": ""}

    monkeypatch.setattr(server, "_exec", fake_exec)
    await server.nuclei("http://t")
    assert seen["timeout_s"] is None  # no cap unless the caller asks for one


@pytest.mark.asyncio
async def test_nuclei_agent_can_cap_runtime(monkeypatch) -> None:
    """The agent may pass `max_runtime_s` to bound a slow/flapping host; it
    propagates to the subprocess wall-clock cap."""
    from src.mcp_servers.surface import server

    seen = {}

    async def fake_exec(cmd, timeout_s=600):
        seen["timeout_s"] = timeout_s
        return {"ok": True, "rc": 0, "stdout": ""}

    monkeypatch.setattr(server, "_exec", fake_exec)
    await server.nuclei("http://t", max_runtime_s=900)
    assert seen["timeout_s"] == 900


@pytest.mark.asyncio
async def test_nuclei_real_failure_surfaces_stderr(monkeypatch) -> None:
    from src.mcp_servers.surface import server
    monkeypatch.setattr(
        server, "_exec",
        _exec_returning(1, stderr="could not resolve host: bogus.invalid"),
    )
    out = await server.nuclei("http://bogus.invalid")
    assert out["ok"] is False
    # the cause is in the error message, not just a buried field
    assert "could not resolve host" in out["error"]
