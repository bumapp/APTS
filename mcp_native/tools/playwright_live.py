"""Native Playwright primitives as MCP tools — a browser the AGENT drives.

Unlike ``crawl`` / ``crawl_v2`` (which encapsulate fill+click+submit in one
mechanical call), this exposes the raw browser actions — navigate, snapshot,
fill, click, press, read-requests — so an agent loop orchestrates the
interaction itself, step by step, the way the public Playwright-MCP server works.

The session is a process singleton: one browser + one current page that persists
across tool calls, so the agent can goto -> snapshot -> fill -> click on the same
page. It is NOT concurrency-safe (one page, shared) — drive it from a single
sequential loop, one action per turn. Intended for a disposable lab target.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from playwright.async_api import async_playwright

_SHELL = {
    "/rest/admin/application-configuration", "/rest/admin/application-version",
    "/rest/languages", "/api/Challenges/", "/socket.io/", "/api/Quantitys/",
    "/rest/products/search", "/assets/i18n/en.json",
}
_STATIC = (".js", ".css", ".png", ".jpg", ".jpeg", ".ico", ".woff2", ".svg", ".map", ".json")

_S: dict[str, Any] = {"pw": None, "browser": None, "ctx": None, "page": None, "reqs": []}


async def _ensure():
    if _S["page"] is None:
        pw = await async_playwright().start()
        browser = await pw.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()

        def on_request(r):
            try:
                _S["reqs"].append({"method": r.method, "url": r.url,
                                   "rt": r.resource_type, "post": r.post_data})
            except Exception:  # noqa: BLE001
                pass
        page.on("request", on_request)
        page.on("dialog", lambda d: asyncio.create_task(d.accept()))
        _S.update(pw=pw, browser=browser, ctx=ctx, page=page)
    return _S["page"]


async def _snapshot(page) -> dict:
    """The interactive elements the page currently shows, with a usable selector."""
    try:
        inputs = await page.eval_on_selector_all(
            "input,textarea,select",
            "els=>els.filter(e=>e.offsetParent!==null).map(e=>({"
            "sel:(e.id?('#'+e.id):(e.name?('[name=\"'+e.name+'\"]'):e.tagName.toLowerCase())),"
            "type:(e.type||e.tagName).toLowerCase(), name:(e.name||e.id||'')}))")
    except Exception:  # noqa: BLE001
        inputs = []
    try:
        buttons = await page.eval_on_selector_all(
            "button,input[type=submit]",
            "els=>els.filter(e=>e.offsetParent!==null).map(e=>({"
            "sel:(e.id?('#'+e.id):''), text:(e.innerText||e.value||'').trim().slice(0,30)}))")
    except Exception:  # noqa: BLE001
        buttons = []
    try:
        text = (await page.inner_text("body"))[:300].replace("\n", " ")
    except Exception:  # noqa: BLE001
        text = ""
    return {"url": page.url, "inputs": inputs[:20], "buttons": buttons[:20],
            "page_text": text}


async def pw_goto(url: str) -> dict[str, Any]:
    """Navigate the browser to a URL and return a snapshot of the page's interactive
    elements (inputs with selector+type+name, buttons with selector+text, page text).
    Clears the request log so pw_requests() afterwards shows only this page's traffic."""
    page = await _ensure()
    _S["reqs"].clear()
    try:
        resp = await page.goto(url, wait_until="load")
        await page.wait_for_timeout(1800)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"goto failed: {str(exc).splitlines()[0][:150]}"}
    snap = await _snapshot(page)
    snap["status"] = resp.status if resp else None
    return snap


async def pw_snapshot() -> dict[str, Any]:
    """Re-read the current page's interactive elements (after a click changed the DOM)."""
    if _S["page"] is None:
        return {"error": "no page open; call pw_goto first"}
    return await _snapshot(_S["page"])


async def pw_fill(selector: str, value: str) -> dict[str, Any]:
    """Fill a form field. selector is a CSS selector from a snapshot (e.g. '#email')."""
    if _S["page"] is None:
        return {"error": "no page open; call pw_goto first"}
    try:
        await _S["page"].fill(selector, value, timeout=4000)
        return {"ok": True, "filled": selector}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc).splitlines()[0][:140]}


async def pw_click(selector: str) -> dict[str, Any]:
    """Click an element (e.g. a submit button) by CSS selector, then settle 1.2s."""
    if _S["page"] is None:
        return {"error": "no page open; call pw_goto first"}
    try:
        await _S["page"].click(selector, timeout=5000)
        await _S["page"].wait_for_timeout(1200)
        return {"ok": True, "clicked": selector}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc).splitlines()[0][:140]}


async def pw_press(selector: str, key: str = "Enter") -> dict[str, Any]:
    """Press a key (default Enter) while focused on a field, to submit a form."""
    if _S["page"] is None:
        return {"error": "no page open; call pw_goto first"}
    try:
        await _S["page"].press(selector, key, timeout=4000)
        await _S["page"].wait_for_timeout(1200)
        return {"ok": True, "pressed": key, "on": selector}
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc).splitlines()[0][:140]}


async def pw_requests() -> dict[str, Any]:
    """Return the notable HTTP requests the page has fired since the last pw_goto
    (method, path, body) — the request map the downstream agents need. Static
    assets and app-shell polling are filtered out."""
    out: list[dict] = []
    seen: set = set()
    for r in _S["reqs"]:
        p = urlparse(r["url"]).path
        if p in _SHELL or p.endswith(_STATIC):
            continue
        if r["rt"] not in ("xhr", "fetch") and r["method"] == "GET":
            continue
        k = (r["method"], p, (r["post"] or "")[:100])
        if k in seen:
            continue
        seen.add(k)
        out.append({"method": r["method"], "path": p, "body": (r["post"] or "")[:160]})
    return {"requests": out[:25], "count": len(out)}


async def peek(urls: list[str]) -> dict[str, Any]:
    """Phase-0.5 peek: render each URL (no interaction) and return what each page
    IS and DOES — title, headings, visible inputs (type+name+selector), buttons, and
    the XHR/fetch calls it fires on load. Its own throwaway browser (does not touch
    the live pw_* session). Cheap scout that turns a URI list into a meaning map so a
    downstream agent decides which pages to interact with by behaviour, not by name."""
    import os
    conc = int(os.environ.get("APTS_PEEK_CONCURRENCY", "8"))
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = await browser.new_context(ignore_https_errors=True)
        sem = asyncio.Semaphore(conc)

        async def _one(url: str) -> dict:
            async with sem:  # render up to `conc` routes CONCURRENTLY (was serial)
                xhr: list[str] = []
                page = await ctx.new_page()
                page.on("request", lambda r: xhr.append(f"{r.method} {urlparse(r.url).path}")
                        if r.resource_type in ("xhr", "fetch") and not urlparse(r.url).path.endswith(_STATIC)
                        else None)
                page.on("dialog", lambda d: asyncio.create_task(d.accept()))
                try:
                    await page.goto(url, wait_until="load")
                    await page.wait_for_timeout(1500)
                except Exception as exc:  # noqa: BLE001
                    await page.close()
                    return {"url": url, "requested": url, "error": str(exc).splitlines()[0][:100]}
                snap = await _snapshot(page)
                seen: set = set()
                snap["xhr_on_load"] = [x for x in xhr if not (x in seen or seen.add(x))][:15]
                snap["requested"] = url
                await page.close()
                return snap

        out = await asyncio.gather(*(_one(u) for u in urls[:80]))
        await browser.close()
    return {"peeked": len(out), "pages": list(out)}


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Phase-0.5 peek: render a list of URLs (no interaction) and return per page "
        "its title, headings, visible inputs (type+name+selector), buttons and on-load "
        "XHRs — a cheap behaviour map to decide which pages are worth interacting with."
    ))(peek)
    mcp.tool(description=(
        "Navigate the live browser to a URL; returns the page's interactive elements "
        "(inputs/buttons with selectors) + page text. Call this first for a route."
    ))(pw_goto)
    mcp.tool(description=(
        "Re-read the current page's interactive elements (use after a click reveals "
        "new fields, e.g. a multi-step form)."
    ))(pw_snapshot)
    mcp.tool(description=(
        "Fill a form field by CSS selector (from a snapshot), e.g. selector='#email'."
    ))(pw_fill)
    mcp.tool(description=(
        "Click an element by CSS selector (e.g. a submit button '#loginButton')."
    ))(pw_click)
    mcp.tool(description=(
        "Press a key (default Enter) on a field to submit a form."
    ))(pw_press)
    mcp.tool(description=(
        "Read the notable HTTP requests the page fired since the last pw_goto "
        "(method/path/body) — call after submitting to capture the real request."
    ))(pw_requests)
    return ["peek", "pw_goto", "pw_snapshot", "pw_fill", "pw_click", "pw_press", "pw_requests"]
