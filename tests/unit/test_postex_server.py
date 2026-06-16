"""PostEx MCP server tests.

The recipes (`linpeas`, `suid_enum`, …) all funnel through `_send_and_read`,
which drives the shell server over the MCP client protocol. An earlier version
POSTed to a REST path the shell server never exposed (`<url>/tools/tmux_send`),
so every recipe 404'd with "tmux_send failed: Not Found". These tests pin the
result-parsing and the fail-soft error path.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import src.mcp_servers.postex.server as server


class _Block:
    def __init__(self, text: str) -> None:
        self.text = text


class TestParseToolResult:
    def test_structured_dict_passthrough(self) -> None:
        r = SimpleNamespace(structuredContent={"ok": True, "output": "hi"}, content=[])
        assert server._parse_tool_result(r) == {"ok": True, "output": "hi"}

    def test_sole_result_key_unwrapped(self) -> None:
        r = SimpleNamespace(structuredContent={"result": {"output": "x"}}, content=[])
        assert server._parse_tool_result(r) == {"output": "x"}

    def test_text_content_json_decoded(self) -> None:
        r = SimpleNamespace(structuredContent=None, content=[_Block('{"output": "ok"}')])
        assert server._parse_tool_result(r) == {"output": "ok"}

    def test_text_content_non_json_falls_back_to_output(self) -> None:
        r = SimpleNamespace(structuredContent=None, content=[_Block("plain text")])
        assert server._parse_tool_result(r) == {"output": "plain text"}

    def test_empty_result(self) -> None:
        r = SimpleNamespace(structuredContent=None, content=[])
        assert server._parse_tool_result(r) == {}


class TestLinpeasCommand:
    """`_linpeas_command` is the fix for two real bugs: `-a` went to bash (a
    no-op shell flag) instead of linpeas, and delivery assumed target internet
    egress that isolated CTF boxes don't have."""

    def test_fast_mode_does_not_pass_dash_a_to_linpeas(self) -> None:
        cmd = server._linpeas_command("fast")
        assert "sh /tmp/.lp.sh >" in cmd  # no -a in fast mode
        assert "sh /tmp/.lp.sh -a" not in cmd

    def test_thorough_passes_dash_a_to_linpeas_not_bash(self) -> None:
        cmd = server._linpeas_command("thorough")
        # -a is an argument to the linpeas script, never `bash -a`
        assert "sh /tmp/.lp.sh -a >" in cmd
        assert "bash -a" not in cmd

    def test_kali_url_is_tried_first(self) -> None:
        cmd = server._linpeas_command("fast", url="http://10.10.16.91:8000/linpeas.sh")
        # the staged Kali URL precedes the public release fallback
        assert cmd.index("10.10.16.91") < cmd.index("github.com")

    def test_fetch_failure_sentinel_present(self) -> None:
        assert "LINPEAS_FETCH_FAILED" in server._linpeas_command("fast")

    def test_saves_full_output_and_greps_highlights(self) -> None:
        cmd = server._linpeas_command("fast")
        assert "/tmp/linpeas.out" in cmd
        assert "LINPEAS HIGHLIGHTS" in cmd
        assert "grep -aiE" in cmd

    def test_url_is_shell_quoted(self) -> None:
        # a hostile/space-bearing url must not break out of the for-loop list
        cmd = server._linpeas_command("fast", url="http://x/ ; rm -rf /")
        assert "; rm -rf /" not in cmd.split("for U in", 1)[1].split(";")[0]


class TestMarkerIsolation:
    """Reading a command's output from a pane the exploited app is flooding."""

    def _wrap(self, command):
        wrapped, begin, end = server._isolate_wrap(command)
        return wrapped, begin, end

    def test_wrap_brackets_and_folds_stderr(self) -> None:
        wrapped, begin, end = self._wrap("id")
        assert begin in wrapped and end in wrapped
        assert "2>&1" in wrapped
        # end marker after the command, separated by `;` so it runs regardless
        assert wrapped.index("{ id; }") < wrapped.index(end)
        assert "&&" not in wrapped

    def test_markers_are_unique_per_call(self) -> None:
        _, b1, _ = self._wrap("id")
        _, b2, _ = self._wrap("id")
        assert b1 != b2

    def test_clean_extraction(self) -> None:
        _, b, e = self._wrap("id")
        pane = f"$ printf ...{b}...{e}\n{b}\nuid=0(root) gid=0(root)\n{e}\n$ "
        out = server._isolate_extract(pane, b, e)
        assert out["polluted"] is False
        assert out["output"] == "uid=0(root) gid=0(root)"

    def test_ignores_marker_in_echoed_command(self) -> None:
        """The echoed command line contains the marker literals too; extraction
        must key off the *printed* markers (the later occurrence)."""
        _, b, e = self._wrap("id")
        pane = f"noise before\n$ cmd with {b} and {e} in it\n{b}\nREAL OUTPUT\n{e}\n"
        assert server._isolate_extract(pane, b, e)["output"] == "REAL OUTPUT"

    def test_flood_drops_begin_marker_flagged_polluted(self) -> None:
        _, b, e = self._wrap("id")
        # begin marker scrolled out of the window; only JS noise remains
        pane = 'function(){let{styles:e}=this.props}//...minified bundle...' * 5
        out = server._isolate_extract(pane, b, e)
        assert out["polluted"] is True
        assert out["output"] == ""
        assert "tail" in out

    def test_begin_without_end_is_partial_and_polluted(self) -> None:
        _, b, e = self._wrap("id")
        pane = f"{b}\nuid=0 then the app starts spewing JS forever..."
        out = server._isolate_extract(pane, b, e)
        assert out["polluted"] is True
        assert out["output"].startswith("uid=0")

    def test_output_capped(self) -> None:
        _, b, e = self._wrap("cat /etc/passwd")
        big = "x" * (server._ISOLATE_CAP + 500)
        out = server._isolate_extract(f"{b}\n{big}\n{e}\n", b, e)
        assert len(out["output"]) <= server._ISOLATE_CAP + 40
        assert "truncated" in out["output"]


class TestSendAndRead:
    def test_transport_failure_returns_error_dict(self, monkeypatch) -> None:
        """A connection failure must come back as `{ok: False, error: ...}` so
        the recipe degrades instead of raising out of the tool."""
        def _boom(*_a, **_kw):
            raise ConnectionError("shell-mcp unreachable")

        monkeypatch.setattr(server, "streamablehttp_client", _boom)
        out = asyncio.run(server._send_and_read("lsn", "id"))
        assert out["ok"] is False
        assert "shell MCP call failed" in out["error"]
        assert "unreachable" in out["error"]
