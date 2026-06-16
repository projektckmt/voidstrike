"""Surface `curl` MCP tool — parses curl -i output into structured response."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_curl_parses_status_headers_and_body(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Server: Apache/2.4.29\r\n"
        "\r\n"
        "<html><body>hi</body></html>"
        "\n__VS_CURL_META__\n"
        "http://target/index.php\n"
        "0.123\n"
    )

    async def _fake_exec(cmd, timeout_s=0):
        return {"ok": True, "rc": 0, "stdout": raw, "stderr": ""}

    monkeypatch.setattr(server, "_exec", _fake_exec)
    result = await server.curl(url="http://target/index.php")

    assert result["ok"] is True
    assert result["status"] == 200
    assert result["reason"] == "OK"
    assert result["headers"]["Content-Type"] == "text/html"
    assert result["headers"]["Server"] == "Apache/2.4.29"
    assert "<html>" in result["body"]
    assert result["final_url"] == "http://target/index.php"
    assert result["redirected"] is False
    assert result["time_total_ms"] == 123
    assert result["hop_count"] == 1


@pytest.mark.asyncio
async def test_curl_accepts_json_dict_data(monkeypatch) -> None:
    # Regression: the model passes a JSON object for `data` (the natural way to
    # POST JSON). It must be accepted, JSON-encoded, and sent application/json —
    # not rejected with a pydantic string-type error.
    from src.mcp_servers.surface import server

    captured = {}

    async def _fake_exec(cmd, timeout_s=0):
        captured["cmd"] = cmd
        return {"ok": True, "rc": 0, "stdout": "HTTP/1.1 200 OK\r\n\r\nok", "stderr": ""}

    monkeypatch.setattr(server, "_exec", _fake_exec)
    result = await server.curl(
        url="http://staging.silentium.htb/api/v1/account/forgot-password",
        method="POST",
        data={"user": {"email": "admin@silentium.htb"}},
    )
    assert result["ok"] is True
    cmd = captured["cmd"]
    # Body was JSON-encoded (compact) and passed to curl -d.
    di = cmd.index("-d")
    assert cmd[di + 1] == '{"user": {"email": "admin@silentium.htb"}}'
    # Content-Type defaulted to application/json.
    joined = " ".join(cmd)
    assert "Content-Type: application/json" in joined


@pytest.mark.asyncio
async def test_curl_dict_data_respects_explicit_content_type(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    captured = {}

    async def _fake_exec(cmd, timeout_s=0):
        captured["cmd"] = cmd
        return {"ok": True, "rc": 0, "stdout": "HTTP/1.1 200 OK\r\n\r\nok", "stderr": ""}

    monkeypatch.setattr(server, "_exec", _fake_exec)
    await server.curl(
        url="http://t/x", method="POST",
        data={"a": 1},
        headers={"Content-Type": "application/vnd.api+json"},
    )
    joined = " ".join(captured["cmd"])
    assert "application/vnd.api+json" in joined
    assert "application/json " not in joined + " "  # didn't also add the default


@pytest.mark.asyncio
async def test_curl_keeps_only_final_block_after_redirects(monkeypatch) -> None:
    """`-L` follows redirects; curl `-i` prints each hop's headers+body. We
    return the FINAL response, not the redirect chain dump."""
    from src.mcp_servers.surface import server

    raw = (
        "HTTP/1.1 302 Found\r\n"
        "Location: /login.php\r\n"
        "\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<form action='/login.php' method='POST'>...</form>"
        "\n__VS_CURL_META__\n"
        "http://target/login.php\n"
        "0.456\n"
    )

    async def _fake_exec(cmd, timeout_s=0):
        return {"ok": True, "rc": 0, "stdout": raw, "stderr": ""}

    monkeypatch.setattr(server, "_exec", _fake_exec)
    result = await server.curl(url="http://target/index.php")

    assert result["status"] == 200
    assert result["headers"]["Content-Type"] == "text/html"
    # Should NOT have the Location header from the 302 hop.
    assert "Location" not in result["headers"]
    assert "<form" in result["body"]
    assert result["redirected"] is True
    assert result["hop_count"] == 2
    assert result["final_url"] == "http://target/login.php"


@pytest.mark.asyncio
async def test_curl_method_and_headers_passed_through(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    captured: list[list[str]] = []

    async def _fake_exec(cmd, timeout_s=0):
        captured.append(cmd)
        return {
            "ok": True, "rc": 0,
            "stdout": "HTTP/1.1 200 OK\r\n\r\n\n__VS_CURL_META__\nhttp://t/\n0.01\n",
            "stderr": "",
        }

    monkeypatch.setattr(server, "_exec", _fake_exec)
    await server.curl(
        url="http://t/",
        method="POST",
        headers={"Authorization": "Bearer abc", "X-Custom": "y"},
        data="key=val",
        follow_redirects=False,
        insecure=False,
    )

    cmd = captured[0]
    assert "-X" in cmd and cmd[cmd.index("-X") + 1] == "POST"
    assert "-d" in cmd and cmd[cmd.index("-d") + 1] == "key=val"
    # Custom headers should appear as -H key/value pairs.
    h_positions = [i for i, v in enumerate(cmd) if v == "-H"]
    h_values = [cmd[i + 1] for i in h_positions]
    assert "Authorization: Bearer abc" in h_values
    assert "X-Custom: y" in h_values
    # follow_redirects=False → no -L; insecure=False → no -k
    assert "-L" not in cmd
    assert "-k" not in cmd


@pytest.mark.asyncio
async def test_curl_body_truncation(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    big_body = "A" * (server._CURL_BODY_MAX_CHARS + 100)
    raw = (
        f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n{big_body}"
        "\n__VS_CURL_META__\nhttp://t/\n0.01\n"
    )

    async def _fake_exec(cmd, timeout_s=0):
        return {"ok": True, "rc": 0, "stdout": raw, "stderr": ""}

    monkeypatch.setattr(server, "_exec", _fake_exec)
    result = await server.curl(url="http://t/")
    assert result["body_truncated"] is True
    assert result["body"].endswith("[truncated]")
    assert len(result["body"]) < len(big_body)


@pytest.mark.asyncio
async def test_curl_propagates_exec_failure(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    async def _fake_exec(cmd, timeout_s=0):
        return {"ok": False, "rc": 6, "stdout": "", "stderr": "Could not resolve host: nope"}

    monkeypatch.setattr(server, "_exec", _fake_exec)
    result = await server.curl(url="http://nope/")
    assert result["ok"] is False
    assert "Could not resolve host" in result["error"]
