"""Browser MCP server — Playwright-backed.

First-class capability, used by both `Surface` and `Exploit`. Phase 1
required (not phase 2) because JS-heavy targets are common on HTB easy boxes.

Sessions are keyed by `engagement_id` to preserve cookies/state.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP, Image

try:  # Playwright is heavy; we import lazily so the module loads in tests.
    from playwright.async_api import (
        Browser,
        BrowserContext,
        Page,
        Playwright,
        async_playwright,
    )
except ImportError:  # pragma: no cover
    Browser = BrowserContext = Page = Playwright = async_playwright = None  # type: ignore

app = FastMCP(
    "browser",
    host=os.environ.get("HOST", "0.0.0.0"),
    port=int(os.environ.get("PORT", "8080")),
)


@dataclass
class _Session:
    context: Any  # BrowserContext
    pages: dict[str, Any] = field(default_factory=dict)


_playwright: Any = None
_browser: Any = None
_sessions: dict[str, _Session] = {}
_lock = asyncio.Lock()


async def _ensure_browser() -> None:
    global _playwright, _browser
    async with _lock:
        if _browser is None:
            _playwright = await async_playwright().start()
            _browser = await _playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )


async def _get_session(engagement_id: str) -> _Session:
    await _ensure_browser()
    if engagement_id not in _sessions:
        ctx = await _browser.new_context(
            ignore_https_errors=True,
            user_agent="voidstrike/0.1",
        )
        _sessions[engagement_id] = _Session(context=ctx)
    return _sessions[engagement_id]


async def _get_page(engagement_id: str, page_name: str = "default") -> Any:
    session = await _get_session(engagement_id)
    if page_name not in session.pages:
        session.pages[page_name] = await session.context.new_page()
    return session.pages[page_name]


@app.tool()
async def goto(engagement_id: str, url: str, page_name: str = "default", wait_until: str = "load") -> dict[str, Any]:
    """Navigate the named page to the URL."""
    page = await _get_page(engagement_id, page_name)
    try:
        resp = await page.goto(url, wait_until=wait_until, timeout=30000)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {
        "ok": True,
        "url": page.url,
        "status": resp.status if resp else None,
        "title": await page.title(),
    }


@app.tool()
async def read_dom(
    engagement_id: str,
    page_name: str = "default",
    raw: bool = False,
    max_chars: int = 15000,
) -> dict[str, Any]:
    """Read the current page's content.

    Returns the page's **visible text** by default (`raw=False`) — markup,
    scripts, and styles stripped — which is what you actually want for reading
    advisories, writeups, exploit-db, and docs. Raw HTML is enormous (a single
    page is often 100KB+), which blows past the tool-result size limit and gets
    offloaded to `/large_tool_results`, forcing you to blind-`grep` a noisy blob.
    Bounded text keeps the result inline and readable.

    Pass `raw=True` only when you specifically need markup/attributes (hidden
    inputs, form actions, CSRF tokens, comments). `max_chars` caps the output.
    """
    page = await _get_page(engagement_id, page_name)
    if raw:
        content = await page.content()
        kind = "html"
    else:
        # Visible text only — far smaller and higher-signal than raw HTML.
        try:
            content = await page.inner_text("body")
        except Exception:  # noqa: BLE001  # no <body> yet / detached — fall back to HTML
            content = await page.content()
        kind = "text"
    truncated = len(content) > max_chars
    return {
        "ok": True,
        "url": page.url,
        kind: content[:max_chars],
        "truncated": truncated,
        **({"hint": "output truncated; narrow with a more specific page or use surface__curl on a known endpoint"} if truncated else {}),
    }


@app.tool()
async def fill_form(
    engagement_id: str,
    fields: dict[str, str],
    page_name: str = "default",
) -> dict[str, Any]:
    """Fill form fields by CSS selector → value."""
    page = await _get_page(engagement_id, page_name)
    filled: list[str] = []
    for selector, value in fields.items():
        try:
            await page.fill(selector, value)
            filled.append(selector)
        except Exception as exc:
            return {"ok": False, "filled_so_far": filled, "error": str(exc), "failed_selector": selector}
    return {"ok": True, "filled": filled}


@app.tool()
async def submit(engagement_id: str, selector: str = "button[type=submit]", page_name: str = "default") -> dict[str, Any]:
    """Submit a form by clicking the named selector."""
    page = await _get_page(engagement_id, page_name)
    try:
        async with page.expect_navigation(wait_until="load", timeout=15000):
            await page.click(selector)
    except Exception:
        # Some flows don't navigate — try a plain click.
        try:
            await page.click(selector)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
    return {"ok": True, "url": page.url, "title": await page.title()}


@app.tool()
async def click(engagement_id: str, selector: str, page_name: str = "default") -> dict[str, Any]:
    page = await _get_page(engagement_id, page_name)
    try:
        await page.click(selector)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "url": page.url}


@app.tool()
async def screenshot(engagement_id: str, page_name: str = "default", path: str | None = None):
    """Capture a full-page PNG screenshot of the current browser page.

    With no `path`, the image is returned inline as a vision block so the model
    can *see* the page (e.g. read a captcha, inspect rendered state) alongside a
    small text metadata block. With `path`, the PNG is written to that file on
    the server host and only metadata is returned.

    The return type is intentionally left un-annotated: a `-> dict` annotation
    makes FastMCP build a structured-output schema that rejects the mixed
    image+metadata list, which would silently downgrade the image to base64 text.
    """
    page = await _get_page(engagement_id, page_name)
    img_bytes = await page.screenshot(full_page=True)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(img_bytes)
        return {"ok": True, "path": path, "bytes": len(img_bytes)}
    return [Image(data=img_bytes, format="png"), {"ok": True, "bytes": len(img_bytes)}]


@app.tool()
async def get_cookies(engagement_id: str, url: str | None = None) -> dict[str, Any]:
    session = await _get_session(engagement_id)
    cookies = await session.context.cookies([url] if url else None)
    return {"ok": True, "cookies": cookies}


@app.tool()
async def eval_js(engagement_id: str, expression: str, page_name: str = "default") -> dict[str, Any]:
    """Run a JavaScript expression in the page; return its JSON-serializable result."""
    page = await _get_page(engagement_id, page_name)
    try:
        result = await page.evaluate(expression)
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "result": result}


@app.tool()
async def close_session(engagement_id: str) -> dict[str, Any]:
    if engagement_id in _sessions:
        await _sessions[engagement_id].context.close()
        _sessions.pop(engagement_id)
    return {"ok": True}


def main() -> None:
    app.run(transport="streamable-http")


if __name__ == "__main__":
    main()
