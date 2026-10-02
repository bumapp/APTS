#!/usr/bin/env python3
"""APTS lab crawler — a standalone copy of the APTS recon crawler's capabilities.

Run it against a target in YOUR OWN offline lab to see what the crawler can map:
pages, forms, every observed request (full headers + body), technologies, and the
client-side routes it mines from JS bundles.

    pip install playwright
    playwright install chromium
    python lab_crawler.py http://target.local/ --domain target.local

    # authenticated:
    python lab_crawler.py http://target.local/ --domain target.local \
        --token "<JWT>"            # sent as Authorization: Bearer + cookie 'token'
    python lab_crawler.py http://target.local/ --domain target.local \
        --header "Authorization: Bearer <JWT>" --cookie "session=abc"

    # save the full map as JSON:
    python lab_crawler.py http://target.local/ --domain target.local --json out.json

⚠️  SAFETY: like the real APTS crawler, this is NOT read-only by default — it
fills in and submits every form/input it finds (login, search, "delete", …),
firing real state-changing requests. Only point it at a disposable target you
own. Use --no-forms for a passive, read-only crawl.

This file has no APTS dependencies on purpose, so you can drop it into any lab.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from collections import deque
from urllib.parse import urldefrag, urljoin, urlparse

from playwright.async_api import async_playwright, Page, Request as PWRequest

# --------------------------------------------------------------------------- #
# Tunables (CLI overrides most of these)
# --------------------------------------------------------------------------- #
SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
                 ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".css")
API_RESOURCE_TYPES = frozenset({"xhr", "fetch"})
ROUTE_RE = re.compile(r"""path\s*:\s*["']([^"']*)["']""")
MENU_TRIGGER_SEL = (
    "[aria-haspopup], [aria-label*='menu' i], [aria-label*='nav' i], "
    "[aria-label*='open' i], [class*='hamburger' i], [class*='menu-toggle' i], "
    "[class*='menu-button' i]")
MAX_JS_FILES = 25
MAX_JS_BYTES = 5_000_000
MAX_MINED_ROUTES = 150

HEURISTICS: list[tuple[list[str], str]] = [
    (["email"], "test@example.com"),
    (["confirm"], "Test1234!"),
    (["password", "pass", "pwd"], "Test1234!"),
    (["username", "user", "login"], "testuser"),
    (["search", "query", "q"], "test"),
    (["phone", "tel"], "1234567890"),
    (["zip", "postal"], "12345"),
    (["url", "website"], "http://example.com"),
    (["comment", "message", "feedback", "review"], "This is a test."),
    (["name"], "Test Name"),
]


# --------------------------------------------------------------------------- #
# Scope
# --------------------------------------------------------------------------- #
def host_matches(host: str, domains: list[str]) -> bool:
    host = (host or "").lower()
    for d in domains:
        d = d.lstrip("*.").lower()
        if d and (host == d or host.endswith("." + d)):
            return True
    return False


def in_scope(url: str, domains, allow_paths, deny_paths) -> bool:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return False
    if not host_matches(p.hostname or "", domains):
        return False
    path = p.path or "/"
    if any(path.startswith(d) for d in deny_paths):
        return False
    return not allow_paths or any(path.startswith(a) for a in allow_paths)


def canonical(url: str) -> str:
    frag = urldefrag(url)
    return url if frag.fragment.startswith("/") else frag.url


def origin_of(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def clean_route(path: str) -> str | None:
    p = (path or "").strip()
    if not p or p in ("*", "**", "/"):
        return None
    if p.startswith(("http://", "https://", "//", "#")):
        return None
    if any(ch in p for ch in (" ", "<", ">", "\\", ":", "*", "?", "=", "{", "}")):
        return None
    if len(p) > 120:
        return None
    return p.strip("/") or None


def guess_value(name: str, fid: str, placeholder: str, ftype: str) -> str:
    hay = f"{name} {fid} {placeholder}".lower()
    if ftype == "email":
        return "test@example.com"
    if ftype == "password":
        return "Test1234!"
    if ftype in ("number", "range"):
        return "1"
    if ftype == "date":
        return "2024-01-01"
    for keys, val in HEURISTICS:
        if any(k in hay for k in keys):
            return val
    return "test"


# --------------------------------------------------------------------------- #
# Crawler
# --------------------------------------------------------------------------- #
class LabCrawler:
    def __init__(self, args):
        self.a = args
        self.domains = args.domain or [urlparse(args.url).hostname]
        self.allow = args.allow_path or []
        self.deny = args.deny_path or []
        self.pages: list[dict] = []
        self.forms: list[dict] = []
        self.observed: list[dict] = []
        self.observed_seen: set = set()
        self.scripts: set[str] = set()
        self.third_party: set[str] = set()
        self.api_paths: set[str] = set()
        self.mined_routes: list[str] = []
        self.tech: dict[str, str] = {}
        self.current_page = args.url

    def _scope(self, url):
        return in_scope(url, self.domains, self.allow, self.deny)

    async def run(self) -> dict:
        a = self.a
        seed = a.url
        queue: deque = deque([(seed, 0)])
        seen = {seed}
        routes_mined = False
        menus_expanded = False
        import time
        deadline = time.monotonic() + a.max_seconds

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            headers = dict(h.split(":", 1) for h in a.header) if a.header else {}
            headers = {k.strip(): v.strip() for k, v in headers.items()}
            if a.token:
                headers.setdefault("Authorization", f"Bearer {a.token}")
            context = await browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=headers or None)
            cookies = []
            for c in (a.cookie or []):
                if "=" in c:
                    k, v = c.split("=", 1)
                    cookies.append({"name": k.strip(), "value": v.strip(), "url": seed})
            if a.token:
                cookies.append({"name": "token", "value": a.token, "url": seed})
            if cookies:
                await context.add_cookies(cookies)

            async def route_handler(route, request: PWRequest):
                await (route.continue_() if self._scope(request.url) else route.abort())
            await context.route("**/*", route_handler)
            context.on("request", self._on_request)

            try:
                while queue:
                    if len(self.pages) >= a.max_pages or time.monotonic() > deadline:
                        break
                    url, depth = queue.popleft()
                    if not self._scope(url):
                        continue
                    self.current_page = url
                    page = await context.new_page()
                    page.on("dialog", lambda d: asyncio.create_task(d.accept()))
                    page.on("popup", lambda p: asyncio.create_task(p.close()))
                    try:
                        html = await self._visit(page, url)
                    except Exception as exc:
                        print(f"  ! visit failed {url}: {exc}", file=sys.stderr)
                        await page.close()
                        continue

                    try:
                        if html and depth < a.max_depth:
                            await self._collect_scripts(page, url)
                            if not routes_mined and self.scripts:
                                routes_mined = True
                                landing = await self._links(page)
                                hash_router = any("#/" in h for h in landing)
                                self.mined_routes = await self._mine_routes(
                                    context, seed, hash_router)
                                self._enqueue(self.mined_routes, seed, seen, queue, 0)
                            if not a.no_forms:
                                await self._fill_and_submit(page, url)
                            self._enqueue(await self._links(page), url, seen, queue, depth)
                            if not menus_expanded:  # nav menu is the same site-wide
                                menus_expanded = True
                                self._enqueue(await self._expand_menus(page), url, seen, queue, depth)
                            if depth == 0:  # button-clicking is slow; entry page only
                                self._enqueue(await self._click_buttons(page, url), url, seen, queue, depth)
                    except Exception as exc:
                        print(f"  ! discovery error on {url}: {exc}", file=sys.stderr)
                    finally:
                        await page.close()
            finally:
                await context.close()
                await browser.close()
        return self._result()

    def _on_request(self, request: PWRequest):
        url = request.url
        if not self._scope(url):
            return
        rtype, method = request.resource_type, request.method
        if rtype in API_RESOURCE_TYPES:
            self.api_paths.add(urlparse(url).path or "/")
        try:
            post = request.post_data
        except Exception:
            post = None
        key = (method, url, post)
        if key in self.observed_seen:
            return
        self.observed_seen.add(key)
        try:
            hdrs = dict(request.headers)
        except Exception:
            hdrs = {}
        self.observed.append({
            "method": method, "url": url, "resource_type": rtype,
            "content_type": hdrs.get("content-type", ""),
            "post_data": post, "headers": hdrs, "source_page": self.current_page})

    async def _visit(self, page: Page, url: str) -> str:
        async def _go():
            # "load" + settle, not "networkidle" — a long-polling app (socket.io,
            # live chat) never goes idle, which would stall every page load.
            r = await page.goto(url, wait_until="load", timeout=30000)
            await page.wait_for_timeout(1200)
            return r
        try:
            resp = await _go()
        except Exception as exc:
            conn = any(m in str(exc) for m in
                       ("ERR_CONNECTION", "ECONNREFUSED", "net::ERR"))
            resp = None
            if conn:  # target down/restarting — wait for it, then retry once
                print(f"  ~ target unreachable at {url}; waiting for recovery…",
                      file=sys.stderr)
                for _ in range(12):
                    await page.wait_for_timeout(3000)
                    try:
                        r = await page.context.request.get(self.a.url, timeout=5000)
                        await r.dispose()
                        break
                    except Exception:
                        continue
                try:
                    resp = await _go()
                except Exception:
                    resp = None
            if resp is None:
                self.pages.append({"url": url, "status": None, "content_type": "",
                                   "response_headers": {}})
                return ""
        headers = resp.headers if resp else {}
        ctype = (headers.get("content-type", "") or "").split(";")[0].strip()
        self.pages.append({"url": page.url, "status": resp.status if resp else None,
                           "content_type": ctype, "response_headers": dict(headers)})
        for name, key in (("server", "Server"), ("x-powered-by", "X-Powered-By")):
            if headers.get(name):
                self.tech[headers[name]] = key
        if "html" in ctype:
            return await page.content()
        return ""

    async def _collect_scripts(self, page: Page, base: str):
        try:
            srcs = await page.eval_on_selector_all("script[src]", "els=>els.map(e=>e.src)")
        except Exception:
            srcs = []
        for s in srcs:
            absu = urljoin(base, s)
            self.scripts.add(absu)
            host = urlparse(absu).hostname
            if host and not host_matches(host, self.domains):
                self.third_party.add(host)

    @staticmethod
    async def _links(page: Page) -> list[str]:
        try:
            return await page.eval_on_selector_all("a[href]", "els=>els.map(e=>e.href)")
        except Exception:
            return []

    async def _mine_routes(self, context, seed, hash_router) -> list[str]:
        origin, routes, fetched = origin_of(seed), set(), 0
        for su in list(self.scripts):
            if fetched >= MAX_JS_FILES:
                break
            host = urlparse(su).hostname
            if host and not host_matches(host, self.domains):
                continue
            try:
                resp = await context.request.get(su, timeout=self.a.max_seconds * 1000)
                body = await resp.text()
                await resp.dispose()
            except Exception:
                continue
            fetched += 1
            for m in ROUTE_RE.finditer(body[:MAX_JS_BYTES]):
                r = clean_route(m.group(1))
                if r:
                    routes.add(r)
                if len(routes) >= MAX_MINED_ROUTES:
                    break
        return [f"{origin}/#/{r}" if hash_router else f"{origin}/{r}"
                for r in sorted(routes)]

    async def _expand_menus(self, page: Page) -> list[str]:
        revealed = []
        try:
            triggers = await page.query_selector_all(MENU_TRIGGER_SEL)
        except Exception:
            return revealed
        before = set(await self._links(page))
        for t in triggers[:10]:
            try:
                if not await t.is_visible():
                    continue
                await t.click(timeout=1500)
                await page.wait_for_timeout(350)
                for h in await self._links(page):
                    if h not in before:
                        revealed.append(h)
                        before.add(h)
                await page.keyboard.press("Escape")
                await page.wait_for_timeout(120)
            except Exception:
                continue
        return revealed

    async def _click_buttons(self, page: Page, base: str) -> list[str]:
        found = []
        try:
            els = await page.query_selector_all(
                ":not(form) > button, [role=button]:not(form [role=button])")
        except Exception:
            return found
        for el in els:
            try:
                await el.click(timeout=2000)
                await page.wait_for_timeout(300)
                if page.url != base:
                    found.append(page.url)
                    await page.go_back(timeout=3000)
            except Exception:
                continue
        return found

    async def _fill_and_submit(self, page: Page, url: str):
        try:
            fields = await page.query_selector_all("input, textarea, select")
        except Exception:
            return
        filled = False
        for f in fields:
            try:
                if not await f.is_visible():
                    continue
                tag = await f.evaluate("el=>el.tagName.toLowerCase()")
                ftype = (await f.get_attribute("type") or "text").lower()
                if ftype in ("submit", "button", "hidden", "file", "image", "reset"):
                    continue
                if ftype in ("checkbox", "radio"):
                    await f.check(timeout=1500)
                    filled = True
                    continue
                name = await f.get_attribute("name") or ""
                fid = await f.get_attribute("id") or ""
                ph = await f.get_attribute("placeholder") or ""
                if tag == "select":
                    await f.select_option(index=0)
                else:
                    await f.fill(guess_value(name, fid, ph, ftype), timeout=1500)
                filled = True
            except Exception:
                continue
        # record the form shape for the report
        try:
            for form in await page.query_selector_all("form"):
                method = (await form.get_attribute("method") or "GET").upper()
                action = await form.get_attribute("action") or ""
                names = await form.eval_on_selector_all(
                    "input[name],textarea[name],select[name]",
                    "els=>els.map(e=>e.getAttribute('name'))")
                self.forms.append({"page": url, "method": method,
                                   "action": action, "fields": names})
        except Exception:
            pass
        if not filled:
            return
        for sel in ("button[type=submit]", "input[type=submit]",
                    "button[id*='login' i]", "button[id*='submit' i]", "button"):
            try:
                b = await page.query_selector(sel)
                if b and await b.is_visible() and await b.is_enabled():
                    await b.click(timeout=2000)
                    break
            except Exception:
                continue
        await page.wait_for_timeout(800)
        if page.url != url:
            try:
                await page.goto(url, wait_until="networkidle")
            except Exception:
                pass

    def _enqueue(self, hrefs, base, seen, queue, depth):
        for href in hrefs:
            target = canonical(urljoin(base, href))
            if target in seen or target.lower().endswith(SKIP_SUFFIXES):
                continue
            seen.add(target)
            if self._scope(target):
                queue.append((target, depth + 1))

    def _result(self) -> dict:
        return {
            "seed": self.a.url,
            "pages_crawled": len(self.pages),
            "pages": self.pages,
            "forms": self.forms,
            "observed_requests": self.observed,
            "js_api_paths": sorted(self.api_paths),
            "mined_routes": self.mined_routes,
            "technologies": [{"name": k, "source": v} for k, v in self.tech.items()],
            "third_party_hosts": sorted(self.third_party),
        }


# --------------------------------------------------------------------------- #
def _report(r: dict) -> None:
    print(f"\n=== crawl of {r['seed']} ===")
    print(f"pages crawled: {r['pages_crawled']}")
    print(f"routes mined from JS: {len(r['mined_routes'])}")
    print(f"forms: {len(r['forms'])} | observed requests: {len(r['observed_requests'])}")
    print("\n-- PAGES --")
    for p in r["pages"]:
        print(f"  [{p.get('status')}] {p['url']}")
    if r["forms"]:
        print("\n-- FORMS --")
        for f in r["forms"]:
            print(f"  {f['method']} {f['action']}  fields={f['fields']}")
    by_type: dict[str, int] = {}
    for o in r["observed_requests"]:
        by_type[o["resource_type"]] = by_type.get(o["resource_type"], 0) + 1
    print("\n-- OBSERVED REQUESTS by type --")
    for t, n in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"  {t}: {n}")
    print("\n-- TECHNOLOGIES --")
    for t in r["technologies"]:
        print(f"  {t['name']}  ({t['source']})")
    if r["mined_routes"]:
        print("\n-- MINED ROUTES (sample) --")
        for u in r["mined_routes"][:30]:
            print(f"  {u}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Standalone APTS lab crawler (Playwright). Disposable targets only.")
    ap.add_argument("url", help="Seed URL, e.g. http://target.local/")
    ap.add_argument("--domain", action="append", default=[],
                    help="In-scope domain (repeatable; default: the seed host).")
    ap.add_argument("--allow-path", action="append", default=[])
    ap.add_argument("--deny-path", action="append", default=[])
    ap.add_argument("--max-pages", type=int, default=40)
    ap.add_argument("--max-depth", type=int, default=3)
    ap.add_argument("--max-seconds", type=float, default=120)
    ap.add_argument("--header", action="append", default=[],
                    help="Extra request header 'Name: value' (repeatable).")
    ap.add_argument("--cookie", action="append", default=[],
                    help="Cookie 'name=value' (repeatable).")
    ap.add_argument("--token", default=None,
                    help="Bearer token: sent as Authorization header + 'token' cookie.")
    ap.add_argument("--no-forms", action="store_true",
                    help="Passive/read-only: do not fill or submit anything.")
    ap.add_argument("--json", default=None, help="Write the full map to this JSON file.")
    args = ap.parse_args(argv)

    result = asyncio.run(LabCrawler(args).run())
    _report(result)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)
        print(f"\nfull map written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
