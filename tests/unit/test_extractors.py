"""ETL extractor tests."""

from __future__ import annotations

import json

from src.etl.extractors import extract


def test_nmap_json_summary_extraction() -> None:
    payload = json.dumps({
        "ok": True,
        "hosts": [{
            "address": "10.10.10.5",
            "ports": [
                {"port": 22, "protocol": "tcp", "service": "ssh",
                 "product": "OpenSSH", "version": "7.6p1"},
                {"port": 80, "protocol": "tcp", "service": "http",
                 "product": "Apache", "version": "2.4.49"},
            ],
            "scripts": [],
        }],
    })
    facts = extract({"action": "surface__nmap_quick", "tool_output": payload})
    assert "10.10.10.5" in facts.hosts
    ports = sorted(s["port"] for s in facts.services)
    assert ports == [22, 80]


def test_nmap_xml_extraction() -> None:
    xml = """<nmaprun>
      <host>
        <address addr="10.10.10.5" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="7.6p1"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="Apache" version="2.4.49"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="closed"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    facts = extract({"action": "surface__nmap_quick", "tool_output": xml})
    assert "10.10.10.5" in facts.hosts
    services = sorted(facts.services, key=lambda s: s["port"])
    assert [s["port"] for s in services] == [22, 80]
    assert services[1]["version"] == "2.4.49"


def test_httpx_jsonlines_extraction() -> None:
    output = "\n".join([
        json.dumps({"url": "http://10.0.0.1/", "status_code": 200, "title": "App", "tech": ["WordPress"]}),
        json.dumps({"url": "http://10.0.0.1/admin", "status_code": 401, "title": "Login"}),
    ])
    facts = extract({"action": "surface__httpx_fingerprint", "tool_output": output})
    urls = sorted(p["url"] for p in facts.web_paths)
    assert urls == ["http://10.0.0.1/", "http://10.0.0.1/admin"]


def test_ffuf_json_extraction() -> None:
    output = json.dumps({
        "results": [
            {"url": "http://t/admin", "status": 200, "length": 1024},
            {"url": "http://t/api", "status": 401, "length": 0},
        ],
    })
    facts = extract({"action": "surface__ffuf", "tool_output": output})
    urls = sorted(p["url"] for p in facts.web_paths)
    assert urls == ["http://t/admin", "http://t/api"]


def test_suid_enum_extraction() -> None:
    output = "/usr/bin/sudo\n/usr/bin/passwd\n/bin/su\n"
    facts = extract({"action": "postex__suid_enum", "tool_output": output})
    assert "/usr/bin/sudo" in facts.suid_paths
    assert len(facts.suid_paths) == 3


def test_cve_pickup_anywhere() -> None:
    facts = extract({
        "action": "exploit__poc_search",
        "tool_output": "Found CVE-2021-41773 in this writeup.",
    })
    assert "CVE-2021-41773" in facts.cves


def test_credential_signal_extraction() -> None:
    facts = extract({
        "action": "postex__loot_credentials",
        "tool_output": "found id_rsa: -----BEGIN OPENSSH PRIVATE KEY-----\n...",
        "tool_input": {"host": "10.0.0.5"},
    })
    types = {c["type"] for c in facts.credentials}
    assert "ssh_key" in types


def test_subfinder_subdomain_extraction() -> None:
    output = "shop.example.com\nadmin.example.com\nnot a domain\n"
    facts = extract({"action": "surface__subfinder", "tool_output": output})
    assert "shop.example.com" in facts.hosts
    assert "admin.example.com" in facts.hosts
