"""Crawler v2 — generic, Playwright-MCP-style. No heuristics.

v1 (``crawler.py``) reaches menu-gated/unlinked routes with a stack of hardcoded
guesses — an ARIA/English menu selector, a ``path:"..."`` route regex, an
English submit-id list, English field-name value guessing. Every one of those is
a fixed assumption that breaks on a different site, framework, or language.

v2 throws all of that out and keeps ONE generic mechanism: **locate the clickable
elements the browser itself reports, and click them.** Menus open, JS-only routes
fire, forms submit — because we interact with the live UI the way a user would,
not because we recognised an app's specific markup. Inputs are filled by their
HTML ``type`` (email/password/number/date…), never by matching English names.

What it reuses from v1 is only the generic spine, imported unchanged:
* scope enforcement — every request the browser makes is scope-checked and
  aborted if out of bounds (``_in_scope``);
* observation — every in-scope request the browser fires is recorded in full
  (same ``observed_requests`` shape v1 and the recon worker already consume).

Bounded like v1 (pages, depth, clicks-per-page, wall-clock). Like v1 it submits
forms, so it is NOT read-only — only point it at a disposable target.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import deque
from typing import Any
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright

from .config import (
    CRAWL_BODY_LIMIT, CRAWL_MAX_DEPTH, CRAWL_MAX_PAGES, CRAWL_MAX_SECONDS,
    TARGET_TIMEOUT_SECONDS,
)
from .context import ToolContext
# Reuse ONLY v1's generic helpers — scope, URL canonicalisation, cookie shaping,
# the binary-suffix skip list. None of these are heuristics; they are the spine.
from .crawler import _SKIP_SUFFIXES, _canonical, _in_scope, _normalise_cookies

log = logging.getLogger("mcp.services.tools.crawl_v2")

_MAX_OBSERVED = int(os.environ.get("APTS_CRAWL_MAX_OBSERVED", "2000"))
_MAX_CLICKS_PER_PAGE = int(os.environ.get("APTS_CRAWL_V2_MAX_CLICKS", "25"))

# Generic clickable set — interactive roles/elements present on ANY site, in any
# language. Crucially includes bare onclick handlers and menu/tab roles, which
# v1's narrow "<button>/[role=button]" selector silently missed.
_CLICKABLE_SEL = ("a[href], button, [role=button], [role=link], [role=menuitem], "
                  "[role=tab], [role=menuitemcheckbox], [onclick], summary, "
                  "input[type=submit], input[type=button]")


def _fill_value(ftype: str) -> str:
    """A value for an input chosen by its HTML ``type`` — generic, not by name."""
    return {
        "email": "test@example.com", "password": "Test1234!", "tel": "1234567890",
        "number": "1", "range": "1", "url": "http://example.com",
        "search": "test", "date": "2024-01-01", "time": "12:00",
        "month": "2024-01", "week": "2024-W01", "color": "#000000",
    }.get(ftype, "test")


class CrawlToolV2:
    """Breadth-first crawl that discovers purely by clicking what the page shows."""

    async def __call__(self, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
        seed = str(args.get("url") or "")
        max_pages = min(int(args.get("max_pages", CRAWL_MAX_PAGES)), CRAWL_MAX_PAGES)
        max_depth = min(int(args.get("max_depth", CRAWL_MAX_DEPTH)), CRAWL_MAX_DEPTH)

        skip = {_canonical(str(u)) for u in (args.get("skip_urls") or [])}
        queue: deque[tuple[str, int]] = deque([(seed, 0)])
        seen: set[str] = {_canonical(seed)} | skip
        pages: list[dict] = []
        observed: list[dict] = []
        observed_seen: set[tuple] = set()
        api_paths: set[str] = set()
        current = seed
        deadline = time.monotonic() + CRAWL_MAX_SECONDS
        truncated = False

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            ctx_kwargs: dict[str, Any] = {"ignore_https_errors": True}
            basic = args.get("basic_auth")
            if isinstance(basic, dict) and basic.get("username"):
                ctx_kwargs["http_credentials"] = {
                    "username": str(basic["username"]), "password": str(basic.get("password", ""))}
            context = await browser.new_context(**ctx_kwargs)
            context.set_default_navigation_timeout(TARGET_TIMEOUT_SECONDS * 1000)
            context.set_default_timeout(TARGET_TIMEOUT_SECONDS * 1000)
            hdrs = args.get("headers")
            if isinstance(hdrs, dict) and hdrs:
                await context.set_extra_http_headers({str(k): str(v) for k, v in hdrs.items()})
            cookies = _normalise_cookies(args.get("cookies"), seed)
            if cookies:
                await context.add_cookies(cookies)

            # --- the generic spine, unchanged from v1 ---
            async def route_handler(route, request):
                if _in_scope(request.url, ctx):
                    await route.continue_()
                else:
                    await route.abort()

            await context.route("**/*", route_handler)

            def on_request(request):
                url = request.url
                if not _in_scope(url, ctx):
                    return
                if request.resource_type in ("xhr", "fetch"):
                    api_paths.add(urlparse(url).path or "/")
                try:
                    pd = request.post_data
                except Exception:
                    pd = None
                k = (request.method, url, pd)
                if k in observed_seen or len(observed) >= _MAX_OBSERVED:
                    return
                observed_seen.add(k)
                try:
                    hdr = dict(request.headers)
                except Exception:
                    hdr = {}
                observed.append({
                    "method": request.method, "url": url,
                    "resource_type": request.resource_type,
                    "content_type": hdr.get("content-type", ""),
                    "post_data": pd, "headers": hdr, "source_page": current})

            context.on("request", on_request)

            try:
                while queue:
                    if len(pages) >= max_pages or time.monotonic() > deadline:
                        truncated = True
                        break
                    url, depth = queue.popleft()
                    if not _in_scope(url, ctx):
                        continue
                    current = url
                    page = await context.new_page()
                    page.on("dialog", lambda d: asyncio.create_task(d.accept()))
                    page.on("popup", lambda p: asyncio.create_task(p.close()))
                    try:
                        resp = await page.goto(url, wait_until="load")
                        await page.wait_for_timeout(1200)
                    except Exception as exc:  # noqa: BLE001
                        await page.close()
                        log.warning("crawl_v2 goto failed %s: %s", url, exc)
                        continue

                    status = resp.status if resp else None
                    headers = resp.headers if resp else {}
                    ct = (headers.get("content-type", "") or "").split(";")[0].strip()
                    if not _in_scope(page.url, ctx):
                        await page.close()
                        continue
                    pages.append({"url": page.url, "status": status, "content_type": ct,
                                  "response_headers": dict(headers)})

                    if "html" in ct and depth < max_depth:
                        try:
                            # Wait for the SPA to actually render its inputs before filling.
                            # Without this, on a cold render _fill_all finds no fields (esp.
                            # the password field) and never submits — the real cause of the
                            # flaky login capture, not click ordering.
                            try:
                                await page.wait_for_selector(
                                    "input:visible, textarea:visible", timeout=4000)
                            except Exception:
                                pass
                            last = await self._fill_all(page)   # generic, by type
                            if last is not None:                # generic submit: Enter
                                try:
                                    await last.press("Enter")
                                    # wait for the submit's request to settle (networkidle),
                                    # so the POST is observed before we move on; bounded.
                                    try:
                                        await page.wait_for_load_state("networkidle", timeout=3000)
                                    except Exception:
                                        await page.wait_for_timeout(1200)
                                except Exception:
                                    pass
                                if page.url != url:
                                    t = _canonical(page.url)
                                    if t not in seen and _in_scope(t, ctx):
                                        seen.add(t)
                                        queue.append((t, depth + 1))
                                    try:
                                        await page.goto(url, wait_until="load")
                                        await page.wait_for_timeout(400)
                                    except Exception:
                                        pass
                            await self._click_all(page, url, ctx, seen, queue, depth)
                            for href in await self._links(page):  # follow real links too
                                t = _canonical(urljoin(url, href))
                                if (t not in seen and not t.lower().endswith(_SKIP_SUFFIXES)):
                                    seen.add(t)
                                    if _in_scope(t, ctx):
                                        queue.append((t, depth + 1))
                        except Exception as exc:  # noqa: BLE001 — one page must not end the crawl
                            log.warning("crawl_v2 discovery error %s: %s", url, exc)
                    await page.close()
            finally:
                await context.close()
                await browser.close()

        log.info("crawl_v2 of %s: %d pages, %d requests%s", seed, len(pages),
                 len(observed), " (truncated)" if truncated else "")
        return {
            "seed": seed, "pages": pages, "observed_requests": observed,
            "js_api_paths": sorted(api_paths), "forms": [], "technologies": [],
            "third_party_hosts": [], "mined_routes": [],
            "pages_crawled": len(pages), "truncated": truncated,
        }

    # --- generic interaction: fill by type, click what the page shows -------- #
    @staticmethod
    async def _fill_all(page):
        """Fill every visible input (value chosen by its HTML ``type``) and return the
        field to press Enter on to SUBMIT.

        Prefer the last PASSWORD field when present — a generic signal that this is a
        credential/submit form, and Enter on it reliably submits. Only if there is no
        password field do we fall back to the last text/email field. (Returning "the
        last field filled" was unreliable: the last field is often a checkbox/toggle —
        e.g. rememberMe — and Enter there never submits, so logins silently didn't fire.)
        No English field-name matching — purely by HTML type."""
        try:
            fields = await page.query_selector_all("input, textarea, select")
        except Exception:
            return None
        last_text = None
        last_password = None
        for f in fields:
            try:
                if not await f.is_visible():
                    continue
                tag = await f.evaluate("e => e.tagName.toLowerCase()")
                ftype = (await f.get_attribute("type") or "text").lower()
                if ftype in ("submit", "button", "hidden", "file", "image", "reset"):
                    continue
                if ftype in ("checkbox", "radio"):
                    await f.check(timeout=1000)
                elif tag == "select":
                    await f.select_option(index=0)
                else:
                    await f.fill(_fill_value(ftype), timeout=1000)
                    last_text = f
                    if ftype == "password":
                        last_password = f
            except Exception:
                continue
        return last_password or last_text

    async def _click_all(self, page, base: str, ctx: ToolContext,
                         seen: set, queue: deque, depth: int) -> None:
        """Locate the clickables the browser reports and click each one.

        This single generic move replaces v1's menu-expansion, button-clicking and
        route-mining: opening a menu, firing a JS-only route, and submitting a form
        are all just "click a thing the page shows". After a click that navigates,
        the new URL is queued and the page is reset to ``base`` and re-filled, so
        the next click (e.g. a form's submit) still acts on a filled, clean page.
        """
        try:
            count = len(await page.query_selector_all(_CLICKABLE_SEL))
        except Exception:
            return
        for i in range(min(count, _MAX_CLICKS_PER_PAGE)):
            try:
                els = await page.query_selector_all(_CLICKABLE_SEL)  # fresh: avoid stale handles
                if i >= len(els):
                    break
                el = els[i]
                if not await el.is_visible():
                    continue
                await el.click(timeout=1500)
                await page.wait_for_timeout(250)
                if page.url != base:
                    t = _canonical(page.url)
                    if t not in seen and _in_scope(t, ctx):
                        seen.add(t)
                        queue.append((t, depth + 1))
                    # reset to a clean, filled base so later clicks still work
                    await page.goto(base, wait_until="load")
                    await page.wait_for_timeout(300)
                    await self._fill_all(page)
            except Exception:
                # a click that errored may have left the page dirty — reset + refill
                try:
                    await page.goto(base, wait_until="load")
                    await page.wait_for_timeout(200)
                    await self._fill_all(page)
                except Exception:
                    pass
                continue

    @staticmethod
    async def _links(page) -> list[str]:
        try:
            return await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
        except Exception:
            return []
