"""Surface compound recon tools."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_web_intake_extracts_page_and_probe_signals(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    html = """
    <html>
      <head>
        <title>Admin Login</title>
        <meta name="generator" content="Next.js">
        <script src="/_next/static/app.js"></script>
      </head>
      <body>
        <form method="post" action="/login">
          <input name="username">
          <input name="password" type="password">
        </form>
        <a href="/api/v1/users">users</a>
        <a href="/upload">upload</a>
      </body>
    </html>
    """

    async def fake_curl(url: str, **kwargs):
        if url.endswith("/robots.txt"):
            return {"ok": True, "status": 200, "body": "Disallow: /admin\nSitemap: /sitemap.xml"}
        if url.endswith("/sitemap.xml"):
            return {
                "ok": True,
                "status": 200,
                "body": "<urlset><url><loc>http://target/admin</loc></url></urlset>",
            }
        if url.endswith("/favicon.ico"):
            return {"ok": True, "status": 200, "body": "ico"}
        return {
            "ok": True,
            "status": 200,
            "headers": {
                "Server": "nginx",
                "Content-Type": "text/html",
                "Set-Cookie": "sid=abc; Path=/; HttpOnly",
            },
            "body": html,
            "final_url": "http://target/",
            "redirected": False,
            "hop_count": 1,
        }

    monkeypatch.setattr(server, "curl", fake_curl)
    result = await server.web_intake("http://target/")

    assert result["ok"] is True
    assert result["title"] == "Admin Login"
    assert result["server"] == "nginx"
    assert "sid" in result["cookie_names"]
    assert "Next.js" in result["technologies"]
    assert "/login" in result["interesting_paths"]
    assert "/api/v1/users" in result["interesting_paths"]
    assert result["body_hints"]["has_login"] is True
    assert result["body_hints"]["has_upload"] is True
    assert result["probes"]["robots"]["entries"] == ["Disallow: /admin", "Sitemap: /sitemap.xml"]
    assert result["probes"]["sitemap"]["locs"] == ["http://target/admin"]
    assert result["probes"]["favicon"]["sha256_16"]


@pytest.mark.asyncio
async def test_service_triage_summarizes_safe_exposures(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    async def fake_exec(cmd, timeout_s=0):
        binary = cmd[0]
        if binary == "curl":
            return {"ok": True, "rc": 0, "stdout": "drwxr-xr-x pub\n", "stderr": ""}
        if binary == "smbclient":
            return {"ok": True, "rc": 0, "stdout": "Disk|public|Public share\nIPC|IPC$|\n", "stderr": ""}
        if binary == "showmount":
            return {"ok": True, "rc": 0, "stdout": "Export list for target:\n/share *\n", "stderr": ""}
        if binary == "redis-cli":
            return {"ok": True, "rc": 0, "stdout": "# Server\nredis_version:7.0.0\n", "stderr": ""}
        if binary == "rsync":
            return {"ok": True, "rc": 0, "stdout": "public          Public files\n", "stderr": ""}
        raise AssertionError(cmd)

    async def fake_curl(url: str, **kwargs):
        return {
            "ok": True,
            "status": 200,
            "body": '{"cluster_name":"es","tagline":"You Know, for Search"}',
        }

    monkeypatch.setattr(server, "_exec", fake_exec)
    monkeypatch.setattr(server, "curl", fake_curl)

    result = await server.service_triage(
        "target",
        services=[
            {"port": 21, "service": "ftp"},
            {"port": 445, "service": "microsoft-ds"},
            {"port": 2049, "service": "nfs"},
            {"port": 6379, "service": "redis"},
            {"port": 873, "service": "rsync"},
            {"port": 9200, "service": "elasticsearch"},
        ],
    )

    assert result["ok"] is True
    assert result["exposure_count"] == 6
    kinds = {item["kind"] for item in result["exposures"]}
    assert kinds == {
        "ftp_anonymous",
        "smb_anonymous",
        "nfs_exports",
        "redis_unauthenticated_info",
        "rsync_modules",
        "elasticsearch_root",
    }


@pytest.mark.asyncio
async def test_service_triage_marks_missing_optional_binaries_as_skipped(monkeypatch) -> None:
    from src.mcp_servers.surface import server

    async def fake_exec(cmd, timeout_s=0):
        return {"ok": False, "rc": 127, "error": f"command failed to start: {cmd[0]}"}

    monkeypatch.setattr(server, "_exec", fake_exec)
    result = await server.service_triage("target", services=[{"port": 445, "service": "smb"}])

    assert result["ok"] is True
    assert result["exposure_count"] == 0
    assert result["checks"][0]["skipped"] is True
