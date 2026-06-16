"""browser__read_dom — returns bounded visible text by default, raw HTML on demand.

Raw 100KB+ HTML blew past the tool-result size limit, got offloaded to
/large_tool_results, and triggered a blind-grep spiral. Default text + a cap
keeps the result inline and readable.
"""

from __future__ import annotations

import asyncio


class _FakePage:
    def __init__(self, html: str, text: str):
        self.url = "http://staging.silentium.htb/advisory"
        self._html = html
        self._text = text

    async def content(self):
        return self._html

    async def inner_text(self, selector):  # noqa: ARG002
        return self._text


def _patch_page(monkeypatch, page):
    from src.mcp_servers.browser import server

    async def _fake_get_page(engagement_id, page_name="default"):  # noqa: ARG001
        return page

    monkeypatch.setattr(server, "_get_page", _fake_get_page)
    return server


def _run(coro):
    return asyncio.run(coro)


def test_default_returns_visible_text_not_html(monkeypatch):
    page = _FakePage(html="<html><script>x</script><body>Flowise CVE-2025-58434</body></html>",
                     text="Flowise CVE-2025-58434")
    server = _patch_page(monkeypatch, page)
    res = _run(server.read_dom(engagement_id="e1"))
    assert res["ok"] is True
    assert res["text"] == "Flowise CVE-2025-58434"
    assert "html" not in res  # no raw markup by default
    assert "<script>" not in res["text"]


def test_raw_returns_html(monkeypatch):
    page = _FakePage(html="<html><body>hi</body></html>", text="hi")
    server = _patch_page(monkeypatch, page)
    res = _run(server.read_dom(engagement_id="e1", raw=True))
    assert res["html"] == "<html><body>hi</body></html>"
    assert "text" not in res


def test_text_is_capped_with_hint(monkeypatch):
    big = "A" * 50000
    page = _FakePage(html="<html>", text=big)
    server = _patch_page(monkeypatch, page)
    res = _run(server.read_dom(engagement_id="e1", max_chars=15000))
    assert len(res["text"]) == 15000
    assert res["truncated"] is True
    assert "hint" in res


def test_falls_back_to_html_when_no_body(monkeypatch):
    class _NoBody(_FakePage):
        async def inner_text(self, selector):  # noqa: ARG002
            raise RuntimeError("no body yet")

    page = _NoBody(html="<html>partial", text="")
    server = _patch_page(monkeypatch, page)
    res = _run(server.read_dom(engagement_id="e1"))
    assert res["ok"] is True
    assert res["text"] == "<html>partial"  # fell back to content()
