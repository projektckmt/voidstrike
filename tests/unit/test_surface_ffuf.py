"""Surface ffuf wrapper behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.mark.asyncio
async def test_ffuf_rejects_missing_wordlist_without_running(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    async def _should_not_run(*args, **kwargs):  # pragma: no cover - should not execute
        raise AssertionError("_exec should not run for a missing wordlist")

    monkeypatch.setattr(server, "_exec", _should_not_run)

    result = await server.ffuf(
        url="http://target/FUZZ",
        wordlist="/does/not/exist.txt",
    )

    assert result["ok"] is False
    assert result["error"] == "wordlist not found"
    assert "ffuf" not in result.get("stdout", "")


@pytest.mark.asyncio
async def test_ffuf_missing_fuzz_points_to_vhost_enum(monkeypatch) -> None:
    # The reported case: agent ran ffuf with a subdomains wordlist and no FUZZ,
    # meaning to fuzz vhosts. The error must redirect to vhost_enum, not just
    # say "url must contain FUZZ", and must not execute ffuf.
    from src.mcp_servers.surface import server

    async def _should_not_run(*args, **kwargs):  # pragma: no cover
        raise AssertionError("ffuf must not run when FUZZ is missing")

    monkeypatch.setattr(server, "_exec", _should_not_run)

    result = await server.ffuf(
        url="http://10.129.245.103/",
        wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
    )
    assert result["ok"] is False
    assert "FUZZ" in result["error"]
    assert "vhost_enum" in result["error"]
    # The subdomain wordlist triggers the stronger wrong-tool hint.
    assert "hint" in result and "vhost_enum" in result["hint"]


@pytest.mark.asyncio
async def test_ffuf_uses_default_wordlist_when_unset(monkeypatch, tmp_path: Path) -> None:
    """First pass (no `wordlist=`) uses whatever `_default_ffuf_wordlist` returns."""
    from src.mcp_servers.surface import server

    default_wl = tmp_path / "raft-medium-directories.txt"
    default_wl.write_text("admin\nlogin\n")
    monkeypatch.setattr(server, "_default_ffuf_wordlist", lambda: str(default_wl))

    calls: list[list[str]] = []

    async def fake_exec(cmd, timeout_s=600):
        calls.append(cmd)
        return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(server, "_exec", fake_exec)
    await server.ffuf(url="http://target/FUZZ")  # no wordlist arg
    assert calls, "ffuf should have run with the default wordlist"
    assert calls[0][calls[0].index("-w") + 1] == str(default_wl)


def test_default_ffuf_wordlist_prefers_big() -> None:
    """The default sweep is SecLists' big.txt (~20k); the common lists are only
    fallbacks if it isn't installed."""
    from src.mcp_servers.surface import server

    assert server._FFUF_DEFAULT_WORDLISTS[0].endswith("/Web-Content/big.txt")
    assert any("common.txt" in wl for wl in server._FFUF_DEFAULT_WORDLISTS[1:])


@pytest.mark.asyncio
async def test_ffuf_uses_resolved_wordlist_and_parses_json(monkeypatch, tmp_path: Path) -> None:
    from src.mcp_servers.surface import server

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n")
    calls: list[list[str]] = []

    async def _fake_exec(cmd, timeout_s=0):
        calls.append(cmd)
        # ffuf writes its JSON to the file named after `-o`; the wrapper
        # reads it back. Stdout may contain plaintext discovery lines from
        # silent mode — emulate that to pin the "stdout is not JSON" case.
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump({
                "results": [{"url": "http://target/admin", "status": 200}],
                "config": {"wordlists": [str(wordlist)]},
            }, fh)
        return {
            "ok": True,
            "rc": 0,
            "stdout": "admin\n",  # ffuf silent-mode plaintext discoveries
            "stderr": "",
        }

    monkeypatch.setattr(server, "_exec", _fake_exec)

    result = await server.ffuf(url="http://target/FUZZ", wordlist=str(wordlist))

    assert result["ok"] is True, result
    # Results are compacted to actionable fields; raw verbose ffuf objects and
    # the bulky `config` are dropped so the result stays inline-able.
    assert result["results"] == [
        {"fuzz": None, "url": "http://target/admin", "status": 200,
         "length": None, "words": None, "lines": None},
    ]
    assert result["total_matches"] == 1
    assert result["truncated"] is False
    assert "config" not in result
    assert calls
    assert calls[0][calls[0].index("-w") + 1] == str(wordlist)
    # Auto-calibration must be on so wildcard/catch-all servers don't return the
    # whole wordlist (the /large_tool_results blow-up).
    assert "-ac" in calls[0]
    # The wrapper must write JSON to a tempfile, NOT to /dev/stdout — that's
    # the entire point of the fix.
    out_path = calls[0][calls[0].index("-o") + 1]
    assert out_path != "/dev/stdout", f"ffuf must not write JSON to stdout (got {out_path!r})"


@pytest.mark.asyncio
async def test_ffuf_handles_silent_mode_stdout_pollution(
    monkeypatch, tmp_path: Path,
) -> None:
    """Regression: ffuf with `-s -of json -o /dev/stdout` mixes plaintext
    discovery lines and JSON, breaking `json.loads(stdout)`. We now write
    JSON to a tempfile and read it back so stdout pollution can't drop
    matches. This test exercises that exact scenario."""
    from src.mcp_servers.surface import server

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nlogin\nrobots.txt\n")

    async def _fake_exec(cmd, timeout_s=0):
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump({
                "results": [
                    {"url": "http://target/admin", "status": 200},
                    {"url": "http://target/robots.txt", "status": 200},
                ],
            }, fh)
        # Simulate ffuf's silent-mode discovery dumps BEFORE the JSON would
        # appear (when -o was /dev/stdout). Stdout is plaintext-only here.
        return {
            "ok": True, "rc": 0,
            "stdout": "admin\nrobots.txt\nlogin\n",
            "stderr": "",
        }

    monkeypatch.setattr(server, "_exec", _fake_exec)
    result = await server.ffuf(url="http://t/FUZZ", wordlist=str(wordlist))
    assert result["ok"] is True
    assert len(result["results"]) == 2


def test_shape_ffuf_compacts_and_keeps_fuzz_and_redirect() -> None:
    from src.mcp_servers.surface import server

    raw = [{
        "input": {"FUZZ": "admin"},
        "url": "http://t/admin",
        "status": 301,
        "length": 12,
        "words": 3,
        "lines": 1,
        "redirectlocation": "/admin/",
        "content-type": "text/html",  # dropped
        "duration": 12345,            # dropped
    }]
    out = server._shape_ffuf_results(raw)
    assert out["results"] == [{
        "fuzz": "admin", "url": "http://t/admin", "status": 301,
        "length": 12, "words": 3, "lines": 1, "redirect": "/admin/",
    }]
    assert out["total_matches"] == 1
    assert out["truncated"] is False


def test_shape_ffuf_caps_and_flags_truncation() -> None:
    from src.mcp_servers.surface import server

    raw = [{"input": {"FUZZ": f"p{i}"}, "url": f"http://t/p{i}", "status": 403}
           for i in range(server._FFUF_RESULT_CAP + 50)]
    out = server._shape_ffuf_results(raw)
    assert len(out["results"]) == server._FFUF_RESULT_CAP
    assert out["total_matches"] == server._FFUF_RESULT_CAP + 50
    assert out["truncated"] is True
    assert "hint" in out  # tells the model it's likely a wildcard/catch-all


def test_ffuf_error_suppresses_usage_dump() -> None:
    from src.mcp_servers.surface import server

    result = server._ffuf_error({
        "ok": False,
        "rc": 1,
        "stdout": "Fuzz Faster U Fool - v2.1.0-dev\n\nHTTP OPTIONS:\n...",
        "stderr": "Encountered error(s): missing wordlist",
    })

    assert result == {
        "ok": False,
        "rc": 1,
        "error": "Encountered error(s): missing wordlist",
        "stderr": "Encountered error(s): missing wordlist",
    }


@pytest.mark.asyncio
async def test_vhost_enum_follows_redirects_and_autocalibrates(monkeypatch, tmp_path) -> None:
    # Regression: same-size redirects (nginx 178-byte 301) for every Host defeat
    # size filtering, so a real vhost gets masked. We follow redirects (-r) and
    # auto-calibrate (-ac) so distinct vhost CONTENT stands out.
    from src.mcp_servers.surface import server

    wl = tmp_path / "subs.txt"
    wl.write_text("staging\ndev\n")
    calls = []

    async def _fake_exec(cmd, timeout_s=0):
        calls.append(cmd)
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w") as fh:
            json.dump({"results": [
                {"input": {"FUZZ": "staging"}, "url": "http://x", "status": 200, "length": 8000},
            ]}, fh)
        return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(server, "_exec", _fake_exec)
    res = await server.vhost_enum(base_url="http://silentium.htb", wordlist=str(wl))
    assert res["ok"] is True
    assert res["results"][0]["fuzz"] == "staging"
    cmd = calls[0]
    assert "-r" in cmd          # follow redirects
    assert "-ac" in cmd         # auto-calibrate
    assert "Host: FUZZ.silentium.htb" in cmd


@pytest.mark.asyncio
async def test_vhost_enum_rejects_ip_base_url() -> None:
    from src.mcp_servers.surface import server

    async def _should_not_run(*a, **k):  # pragma: no cover
        raise AssertionError("must not run ffuf for an IP base_url")

    res = await server.vhost_enum(base_url="http://10.129.9.91")
    assert res["ok"] is False
    assert "IP" in res["error"]
    assert "add_hosts_entry" in res["hint"]


@pytest.mark.asyncio
async def test_vhost_enum_empty_result_explains_itself(monkeypatch, tmp_path) -> None:
    from src.mcp_servers.surface import server

    wl = tmp_path / "subs.txt"
    wl.write_text("nope\n")

    async def _fake_exec(cmd, timeout_s=0):
        out_path = cmd[cmd.index("-o") + 1]
        with open(out_path, "w") as fh:
            json.dump({"results": []}, fh)
        return {"ok": True, "rc": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(server, "_exec", _fake_exec)
    res = await server.vhost_enum(base_url="http://silentium.htb", wordlist=str(wl))
    assert res["ok"] is True
    assert res["results"] == []
    assert "hint" in res and "wordlist" in res["hint"].lower()
