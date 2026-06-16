"""surface__add_hosts_entry — map a discovered vhost into /etc/hosts.

The tool is append-only and idempotent so it can never corrupt the sandbox's
hosts file (which Docker seeds with localhost/container entries).
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def hosts_file(monkeypatch, tmp_path: Path) -> Path:
    from src.mcp_servers.surface import server

    path = tmp_path / "hosts"
    path.write_text("127.0.0.1\tlocalhost\n")
    monkeypatch.setattr(server, "_ETC_HOSTS", str(path))
    return path


@pytest.mark.asyncio
async def test_adds_mapping(hosts_file: Path) -> None:
    from src.mcp_servers.surface import server

    res = await server.add_hosts_entry(ip="10.129.245.103", hostnames=["silentium.htb"])
    assert res["ok"] is True
    assert res["added"] == ["silentium.htb"]
    text = hosts_file.read_text()
    assert "127.0.0.1\tlocalhost" in text  # existing line preserved
    assert "10.129.245.103\tsilentium.htb" in text


@pytest.mark.asyncio
async def test_idempotent(hosts_file: Path) -> None:
    from src.mcp_servers.surface import server

    await server.add_hosts_entry(ip="10.129.245.103", hostnames=["silentium.htb"])
    res = await server.add_hosts_entry(ip="10.129.245.103", hostnames=["silentium.htb"])
    assert res["added"] == []
    assert res["already_present"] == ["silentium.htb"]
    # Only one entry line — not appended twice.
    assert hosts_file.read_text().count("silentium.htb") == 1


@pytest.mark.asyncio
async def test_multiple_hostnames_and_partial_dedupe(hosts_file: Path) -> None:
    from src.mcp_servers.surface import server

    await server.add_hosts_entry(ip="10.10.10.5", hostnames=["a.htb"])
    res = await server.add_hosts_entry(ip="10.10.10.5", hostnames=["a.htb", "b.htb"])
    assert res["added"] == ["b.htb"]
    assert res["already_present"] == ["a.htb"]


@pytest.mark.asyncio
async def test_rejects_bad_ip(hosts_file: Path) -> None:
    from src.mcp_servers.surface import server

    res = await server.add_hosts_entry(ip="not-an-ip", hostnames=["x.htb"])
    assert res["ok"] is False
    assert "invalid IP" in res["error"]
    assert hosts_file.read_text() == "127.0.0.1\tlocalhost\n"  # untouched


@pytest.mark.asyncio
async def test_rejects_bad_hostname(hosts_file: Path) -> None:
    from src.mcp_servers.surface import server

    res = await server.add_hosts_entry(ip="10.0.0.1", hostnames=["bad host!"])
    assert res["ok"] is False
    assert "invalid hostname" in res["error"]
    assert hosts_file.read_text() == "127.0.0.1\tlocalhost\n"


@pytest.mark.asyncio
async def test_appends_newline_when_file_lacks_trailing(monkeypatch, tmp_path: Path) -> None:
    from src.mcp_servers.surface import server

    path = tmp_path / "hosts"
    path.write_text("127.0.0.1\tlocalhost")  # no trailing newline
    monkeypatch.setattr(server, "_ETC_HOSTS", str(path))

    await server.add_hosts_entry(ip="10.0.0.9", hostnames=["x.htb"])
    lines = path.read_text().splitlines()
    assert lines == ["127.0.0.1\tlocalhost", "10.0.0.9\tx.htb"]
