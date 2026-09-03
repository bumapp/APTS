"""Browser-driven crawler — maps the target's attack surface with a real browser.

Replaces the previous `httpx`-based crawler. The output contract is unchanged
(same dict shape consumed by :class:`agent.services.workers.recon_worker.ReconWorker`)
but the fetch mechanism is not: this drives headless Chromium through
Playwright, so it executes page JavaScript, follows client-side-rendered links
a static `<a href>` scan would never see, fills in and submits every `<form>`
it finds, and clicks through non-form buttons to reach routes with no link at
all. On a single-page app this finds real pages instead of one empty shell.

It also records every HTTP request the browser actually fires while it works
(``page.on("request", ...)``), and reports the XHR/fetch ones as
``js_api_paths`` — these are *confirmed, observed* calls, not the regex-mined
guesses over bundle text the old crawler produced. Confirmed and reachable via
a real request, exactly like everything else this stage reports.

**Two invariants inherited unchanged from the previous implementation, because
neither is optional:**

* **Every derived URL is re-checked against scope with :func:`_in_scope`.**
  The guardrails checkpoint upstream only ever vets the seed URL; everything a
  running browser discovers or fires a request to afterwards — a link, a form
  action, an XHR triggered by page JS — is a URL guardrails never saw.
* **Everything is bounded** — page count, depth, and total wall-clock. A real
  browser is far slower per page than a bare GET, so these ceilings matter more
  here, not less.

**One invariant deliberately NOT inherited: recon here is no longer read-only.**
Every prior stage in this codebase runs as passive discovery — recon has never
had a model, never had shell access, and the tool-policy table's own comment
for `agent-recon` reads "Discovery: read the target, never execute against
it." Filling in and submitting forms breaks that: it sends real, state-changing
requests (whatever the form actually does — login, search, "delete my
account," checkout) with no guardrail beyond the scope check above; nothing
here inspects a form's action or button text before submitting it. This is a
deliberate, known scope decision for use against a disposable practice target,
not an oversight — if this ever points at something that is not disposable,
that gap needs closing first.
"""
from __future__ import annotations

import asyncio
import logging
import hashlib
import json
import os
import time
import warnings
from collections import deque
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

from playwright.async_api import (
    Page,
    Request as PWRequest,
    TimeoutError as PWTimeoutError,
    async_playwright,
)

from shared.scope_match import host_matches, matching_deny_path, path_allowed

from mcp_tools.config import (
    CRAWL_BODY_LIMIT,
    CRAWL_CACHE_DIR,
    CRAWL_CACHE_ENABLED,
    CRAWL_MAX_DEPTH,
    CRAWL_MAX_PAGES,
    CRAWL_MAX_SECONDS,
    TARGET_TIMEOUT_SECONDS,
)
from mcp_tools.services.tools.base import ToolContext
from mcp_tools.utils.html import parse_page

log = logging.getLogger("mcp.services.tools.crawl")

# python-Wappalyzer 0.3.1 still imports the deprecated pkg_resources and ships a
# fingerprint DB with a handful of invalid regexes it warns about on every
# analyze. Neither is actionable here, so silence both rather than let them
# spam the container log.
warnings.filterwarnings("ignore", message=".*pkg_resources.*")
warnings.filterwarnings("ignore", message=".*compiling regex.*")
logging.getLogger("python-Wappalyzer").setLevel(logging.ERROR)

# One Wappalyzer instance, built lazily and reused across every crawl. `latest()`
# parses ~2500 fingerprints from a *bundled* JSON file — no network call — which
# costs ~300ms once and would be wasteful per crawl. If the library is missing or
# fails to build, tech fingerprinting is skipped, never fatal: recon's job is the
# asset map, and a missing technology list is a smaller loss than a failed crawl.
_WAPPALYZER: Any = None
_WAPPALYZER_UNAVAILABLE = False


def _wappalyze(url: str, html: str, headers: dict) -> dict:
    """Run Wappalyzer over one already-fetched page. Synchronous and CPU-bound
    (regex over the DOM), so callers run it in a worker thread.

    Uses the *rendered* DOM the browser produced, not a raw HTTP body: on a
    single-page app the shell HTML names only a couple of libraries, while the
    hydrated DOM reveals the actual framework — verified against this project's
    practice target, where the raw body misses Angular and the rendered DOM
    finds it with its version.
    """
    global _WAPPALYZER, _WAPPALYZER_UNAVAILABLE
    if _WAPPALYZER_UNAVAILABLE:
        return {}
    try:
        if _WAPPALYZER is None:
            from Wappalyzer import Wappalyzer
            _WAPPALYZER = Wappalyzer.latest()
        from Wappalyzer import WebPage
        page = WebPage(url, html=html, headers=dict(headers))
        return _WAPPALYZER.analyze_with_versions_and_categories(page)
    except Exception as exc:
        _WAPPALYZER_UNAVAILABLE = True
        log.warning("Wappalyzer unavailable; skipping tech fingerprinting: %s", exc)
        return {}

# Extensions worth discovering but not worth loading in a browser.
_SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
                  ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".css")


# --------------------------------------------------------------------------- #
# Development crawl cache (see mcp_tools.config.CRAWL_CACHE_ENABLED). A no-op
# unless the switch is on. Keyed on everything that changes what a crawl would
# return — target, limits, and the full scope — so a different scope or target
# never replays another one's result.
# --------------------------------------------------------------------------- #

def _cache_key(seed: str, max_pages: int, max_depth: int,
               scope: Any) -> str:
    material = json.dumps({
        "seed": seed,
        "max_pages": max_pages,
        "max_depth": max_depth,
        "domains": sorted(scope.domains),
        "allow_paths": sorted(scope.allow_paths),
        "deny_paths": sorted(scope.deny_paths),
    }, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()


def _cache_load(key: str) -> dict | None:
    path = os.path.join(CRAWL_CACHE_DIR, f"{key}.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log.warning("crawl cache unreadable at %s: %s", path, exc)
        return None


def _cache_store(key: str, result: dict) -> None:
    try:
        os.makedirs(CRAWL_CACHE_DIR, exist_ok=True)
        path = os.path.join(CRAWL_CACHE_DIR, f"{key}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(result, fh)
    except OSError as exc:
        # A cache is a convenience; failing to write one must never fail a crawl.
        log.warning("could not write crawl cache: %s", exc)

# Requests the browser fires that look like API calls rather than page loads.
_API_RESOURCE_TYPES = frozenset({"xhr", "fetch"})

# Bounds on the observed-request log. A busy SPA can fire hundreds of calls; an
# unbounded list would flow straight into the next stage's context window and
# the flow file. A POST body is captured but capped for the same reason.
_MAX_OBSERVED_REQUESTS = 200
_POST_DATA_LIMIT = 4000

# Same field-guessing heuristics as the POC browser agent this replaces —
# first match wins, "test" is the fallback. No model call: guessing a
# plausible value is exactly the kind of fuzzy, judgement-y work the rest of
# this codebase keeps out of code, but recon has no LLM wired in and every
# other stage's "AI suggests, code decides" boundary assumes recon's artifact
# is deterministic input. A model-backed guesser belongs in a later stage, not
# folded into this one.
_HEURISTICS: list[tuple[list[str], str]] = [
    (["email"], "test@example.com"),
    (["confirm"], "Test1234!"),
    (["password", "pass", "pwd"], "Test1234!"),
    (["username", "user", "login"], "testuser"),
    (["search", "query", "q"], "test"),
    (["phone", "tel"], "1234567890"),
    (["zip", "postal"], "12345"),
    (["url", "website"], "http://example.com"),
    (["address"], "123 Test St"),
    (["city"], "Testville"),
    (["comment", "message", "feedback", "review"], "This is a test."),
    (["name"], "Test Name"),
]


def _canonical(url: str) -> str:
    """Drop a same-page anchor fragment, but keep a hash-router route.

    A real, JS-executing browser turns up links a static `httpx` crawl never
    would, and a lot of single-page apps (this project's own practice target
    included) route entirely through the URL fragment — `#/login`, `#/about`.
    Blindly stripping fragments the way a classic crawler does collapses every
    one of those distinct pages down to the bare origin, which then looks
    identical to a page already seen and gets silently deduplicated away.
    `#/...` is the near-universal hash-router convention (Angular's default
    strategy among others); a bare `#section`-style anchor still collapses to
    its page, same as before.
    """
    fragment = urldefrag(url)
    if fragment.fragment.startswith("/"):
        return url
    return fragment.url


def _in_scope(url: str, ctx: ToolContext) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    if not host_matches(host, ctx.scope.domains):
        return False
    if matching_deny_path(path, ctx.scope.deny_paths):
        return False
    return path_allowed(path, ctx.scope.allow_paths)


def _guess_value(name: str, fid: str, placeholder: str, ftype: str) -> str:
    haystack = f"{name} {fid} {placeholder}".lower()
    if ftype == "email":
        return "test@example.com"
    if ftype == "password":
        return "Test1234!"
    if ftype in ("number", "range"):
        return "1"
    if ftype == "date":
        return "2024-01-01"
    for keywords, val in _HEURISTICS:
        if any(k in haystack for k in keywords):
            return val
    return "test"


class CrawlTool:
    """Breadth-first crawl of a target, driven by a real browser."""

    async def __call__(self, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
        seed = str(args.get("url") or "")
        max_pages = min(int(args.get("max_pages", CRAWL_MAX_PAGES)), CRAWL_MAX_PAGES)
        max_depth = min(int(args.get("max_depth", CRAWL_MAX_DEPTH)), CRAWL_MAX_DEPTH)

        # Development cache (off by default — see mcp_tools.config). On a hit we
        # never launch the browser at all; the result is whatever the last real
        # crawl of this exact target+scope produced.
        cache_key = ""
        if CRAWL_CACHE_ENABLED:
            cache_key = _cache_key(seed, max_pages, max_depth, ctx.scope)
            cached = _cache_load(cache_key)
            if cached is not None:
                log.warning("crawl cache HIT for %s (key %s) — REPLAYING a cached "
                            "result, not crawling; disable APTS_CRAWL_CACHE for a "
                            "live crawl", seed, cache_key[:12])
                return cached

        queue: deque[tuple[str, int]] = deque([(seed, 0)])
        seen: set[str] = {seed}
        pages: list[dict] = []
        forms: list[dict] = []
        scripts: set[str] = set()
        third_party: set[str] = set()
        # name -> {"source": ..., "version": ...}
        technologies: dict[str, dict[str, str]] = {}
        tech_detected = False
        api_paths: set[str] = set()
        observed: list[dict] = []
        observed_seen: set[tuple[str, str, str | None]] = set()
        current_page_url = seed  # page being loaded; tags each observed request
        out_of_scope_skipped = 0
        deadline = time.monotonic() + CRAWL_MAX_SECONDS
        truncated = False

        async with async_playwright() as pw:
            # --no-sandbox: this container already runs as a non-root user with
            # no added capabilities (see docker-compose.yml), which is where
            # Chromium's own sandbox usually falls over. --disable-dev-shm-usage
            # avoids crashes against Docker's small default /dev/shm.
            browser = await pw.chromium.launch(
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            context = await browser.new_context(ignore_https_errors=True)
            context.set_default_navigation_timeout(TARGET_TIMEOUT_SECONDS * 1000)
            context.set_default_timeout(TARGET_TIMEOUT_SECONDS * 1000)

            # Blocks every out-of-scope request at the network layer — not
            # just links this tool chose to follow, but anything the browser
            # tries to fetch on its own: a redirect chain, an XHR page JS
            # fires, a third-party script/font/image. This is the property
            # the old httpx crawler got from a one-line `follow_redirects=
            # False`; a full browser has no such switch, since following
            # redirects is normal navigation to it, so the boundary has to be
            # enforced per-request instead. Route interception runs before
            # the request ever leaves the process — `context.on("request",
            # ...)` (used below only to observe, not block) fires too late to
            # stop anything.
            async def route_handler(route, request: PWRequest) -> None:
                if _in_scope(request.url, ctx):
                    await route.continue_()
                else:
                    await route.abort()

            await context.route("**/*", route_handler)

            def on_request(request: PWRequest) -> None:
                # Observe-only. The route handler above already decides what
                # actually leaves the process; this just records what the
                # browser fired, and only the calls worth keeping: the app's
                # own API traffic (XHR/fetch) and anything state-changing (a
                # login POST, a form submit), never the flood of static
                # image/script/style GETs.
                url = request.url
                if not _in_scope(url, ctx):
                    return
                rtype = request.resource_type
                method = request.method
                if rtype not in _API_RESOURCE_TYPES and method == "GET":
                    return

                api_paths.add(urlparse(url).path or "/")

                try:
                    post_data = request.post_data
                except Exception:
                    post_data = None
                key = (method, url, post_data)
                if key in observed_seen:
                    return
                observed_seen.add(key)
                if len(observed) >= _MAX_OBSERVED_REQUESTS:
                    return
                try:
                    headers = dict(request.headers)
                except Exception:
                    headers = {}
                observed.append({
                    "method": method,
                    "url": url,
                    "resource_type": rtype,
                    "content_type": headers.get("content-type", ""),
                    "post_data": post_data[:_POST_DATA_LIMIT] if post_data else None,
                    "headers": headers,
                    # The page the browser was on when this request fired. Set
                    # from the crawl loop before each navigation (best-effort:
                    # requests are observed context-wide, tagged to the page
                    # currently being loaded).
                    "source_page": current_page_url,
                })

            context.on("request", on_request)

            try:
                while queue:
                    if len(pages) >= max_pages or time.monotonic() > deadline:
                        truncated = True
                        break

                    url, depth = queue.popleft()

                    # Verified by hand against this project's own practice
                    # target: Juice Shop's `/redirect?to=` endpoint is
                    # in-scope itself (host matches), but 302s straight to
                    # github.com — and Chromium follows that redirect to
                    # completion, fully loading the out-of-scope page, before
                    # `context.route()` above ever sees a request for the
                    # redirected URL. The route block is real defense in
                    # depth for in-page JS firing a fresh request, but it does
                    # not catch a same-navigation redirect chain, so every
                    # redirect hop is resolved and scope-checked by hand,
                    # here, before Chromium is ever pointed at the URL at all.
                    resolved = await self._resolve_safe(context, url, ctx)
                    if resolved is None:
                        out_of_scope_skipped += 1
                        continue
                    url = resolved
                    current_page_url = url  # tag requests fired while loading it

                    page = await context.new_page()
                    page.on("dialog", lambda d: asyncio.create_task(d.accept()))
                    # "popup" fires only when *this* page opens another one
                    # (target="_blank", window.open()) — unlike the
                    # context-wide "page" event, it never fires for pages we
                    # create ourselves, so there is no race with the goto()
                    # below.
                    page.on("popup", lambda popup: asyncio.create_task(popup.close()))

                    try:
                        record, html, resp_headers = await self._visit(page, url)
                    except Exception as exc:
                        log.warning("crawl visit failed %s: %s", url, exc)
                        await page.close()
                        continue

                    # Belt and suspenders: if the page still ended up
                    # somewhere out of scope despite the pre-check above (an
                    # in-page JS redirect after load, say), the content is
                    # never parsed or reported — only the fact that it
                    # happened is counted.
                    if not _in_scope(record["url"], ctx):
                        log.warning("crawl landed out of scope: %s -> %s",
                                   url, record["url"])
                        out_of_scope_skipped += 1
                        await page.close()
                        continue

                    pages.append(record)

                    # Fingerprint technologies once, on the first page that
                    # renders HTML. One page is enough for the framework stack —
                    # it is the same bundle on every route — and analysing every
                    # page would repeat the identical answer for no gain. Runs
                    # off the rendered DOM and response headers already in hand,
                    # so it costs no extra request.
                    if html:
                        self._note_technologies(record, technologies)
                    if html and not tech_detected:
                        tech_detected = True
                        await self._detect_technologies(
                            record["url"], html, resp_headers, technologies)

                    if html and depth < max_depth:
                        parsed = parse_page(html)
                        if parsed.generator:
                            technologies.setdefault(
                                parsed.generator,
                                {"source": "meta generator", "version": ""})
                        for form in parsed.forms:
                            form["page"] = url
                            forms.append(form)
                        for src in parsed.scripts:
                            absolute = urljoin(url, src)
                            scripts.add(absolute)
                            host = urlparse(absolute).hostname
                            if host and not host_matches(host, ctx.scope.domains):
                                third_party.add(host)

                        await self._fill_and_submit(page, url)

                        hrefs = await self._collect_links(page)
                        out_of_scope_skipped += self._enqueue(
                            hrefs, url, ctx, seen, queue, depth)

                        clicked_hrefs = await self._click_clickables(page, url)
                        out_of_scope_skipped += self._enqueue(
                            clicked_hrefs, url, ctx, seen, queue, depth)

                    await page.close()
            finally:
                await context.close()
                await browser.close()

        if truncated:
            log.info("crawl of %s stopped at a limit (%d pages)", seed, len(pages))
        if out_of_scope_skipped:
            log.info("crawl skipped %d out-of-scope links", out_of_scope_skipped)
        if api_paths:
            log.info("observed %d distinct API paths across the crawl", len(api_paths))
        if observed:
            log.info("captured %d in-scope requests (%d with a body)",
                     len(observed), sum(1 for r in observed if r["post_data"]))

        result = {
            "seed": seed,
            "pages": pages,
            "forms": forms,
            "scripts": sorted(scripts),
            "js_api_paths": sorted(api_paths),
            "observed_requests": observed,
            "third_party_hosts": sorted(third_party),
            "technologies": [
                {"name": k, "source": v["source"], "version": v.get("version", "")}
                for k, v in technologies.items()
            ],
            "pages_crawled": len(pages),
            "out_of_scope_skipped": out_of_scope_skipped,
            "truncated": truncated,
        }

        if CRAWL_CACHE_ENABLED and cache_key:
            _cache_store(cache_key, result)
            log.info("crawl cache stored for %s (key %s)", seed, cache_key[:12])

        return result

    # ----------------------------------------------------------------- #
    # Redirects
    # ----------------------------------------------------------------- #

    @staticmethod
    async def _resolve_safe(context, url: str, ctx: ToolContext) -> str | None:
        """Follow ``url``'s redirect chain by hand, scope-checking every hop.

        Uses Playwright's own request API (``max_redirects=0``) rather than a
        separate HTTP client, so it shares the context's cookies and TLS
        settings with whatever the browser would actually see. Bounded to a
        handful of hops — a redirect loop is a target bug, not something to
        spin on.
        """
        current = url
        for _ in range(5):
            if not _in_scope(current, ctx):
                return None
            try:
                response = await context.request.get(
                    current, max_redirects=0, timeout=TARGET_TIMEOUT_SECONDS * 1000)
            except Exception as exc:
                log.debug("redirect probe failed %s: %s", current, exc)
                return current  # let the real navigation surface the error
            status = response.status
            location = response.headers.get("location")
            await response.dispose()
            if status not in (301, 302, 303, 307, 308) or not location:
                return current
            current = urljoin(current, location)
        return None

    # ----------------------------------------------------------------- #
    # One page
    # ----------------------------------------------------------------- #

    @staticmethod
    async def _visit(page: Page, url: str) -> tuple[dict, str, dict]:
        """Navigate to ``url``. Returns the page record, rendered HTML, and the
        full response headers.

        HTML is `""` (and so nothing downstream is parsed) whenever the
        response was not actually HTML, or the load timed out — the same
        `content_type` gate the previous `httpx`-based crawler used, plus a
        timeout tolerance a real browser needs and a bare GET never did. The
        headers come back separately (not folded into the record, which is
        reported) so tech fingerprinting can see Server/Set-Cookie without
        bloating every page entry in the artifact.
        """
        try:
            response = await page.goto(url, wait_until="networkidle")
        except PWTimeoutError:
            log.debug("crawl navigation timeout %s", url)
            return ({"url": url, "status": None, "content_type": "",
                     "server": "", "powered_by": ""}, "", {})

        status = response.status if response else None
        headers = response.headers if response else {}
        content_type = (headers.get("content-type", "") or "").split(";")[0].strip()
        record = {
            "url": page.url,
            "status": status,
            "content_type": content_type,
            "server": headers.get("server", ""),
            "powered_by": headers.get("x-powered-by", ""),
        }
        html = ""
        if "html" in content_type:
            html = (await page.content())[:CRAWL_BODY_LIMIT]
        return record, html, headers

    @staticmethod
    def _note_technologies(page: dict, into: dict[str, dict[str, str]]) -> None:
        if page.get("server"):
            into.setdefault(page["server"], {"source": "Server header", "version": ""})
        if page.get("powered_by"):
            into.setdefault(page["powered_by"],
                            {"source": "X-Powered-By header", "version": ""})

    @staticmethod
    async def _detect_technologies(url: str, html: str, headers: dict,
                                   into: dict[str, dict[str, str]]) -> None:
        """Fingerprint the page's technology stack with Wappalyzer and merge the
        result in. Runs the synchronous, CPU-bound match in a worker thread so
        it does not stall the crawl's event loop.

        Merge, not overwrite: a name already noted from a header keeps its entry
        but gains a version if Wappalyzer found one. Header-derived hits and
        fingerprint hits are complementary, and neither should clobber the
        other.
        """
        results = await asyncio.to_thread(_wappalyze, url, html, headers)
        for name, info in results.items():
            versions = info.get("versions") or []
            version = versions[0] if versions else ""
            existing = into.get(name)
            if existing is None:
                into[name] = {"source": "Wappalyzer", "version": version}
            elif version and not existing.get("version"):
                existing["version"] = version

    # ----------------------------------------------------------------- #
    # Discovery: links, clicks, forms
    # ----------------------------------------------------------------- #

    @staticmethod
    async def _collect_links(page: Page) -> list[str]:
        try:
            return await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)")
        except Exception:
            return []

    @staticmethod
    def _enqueue(hrefs: list[str], base_url: str, ctx: ToolContext,
                 seen: set[str], queue: deque[tuple[str, int]], depth: int) -> int:
        skipped = 0
        for href in hrefs:
            target = _canonical(urljoin(base_url, href))
            if target in seen or target.lower().endswith(_SKIP_SUFFIXES):
                continue
            seen.add(target)
            if not _in_scope(target, ctx):
                skipped += 1
                continue
            queue.append((target, depth + 1))
        return skipped

    async def _click_clickables(self, page: Page, base_url: str) -> list[str]:
        """Click non-form buttons and role="button" elements to surface
        JavaScript-only routes a static `<a href>` scan can't see.

        Returns whatever URL the click landed on (or nothing, if it didn't
        navigate) — actual link-following is `_collect_links`' job, this only
        exists for the routes that have no `<a href>` at all.
        """
        found: list[str] = []
        try:
            clickables = await page.query_selector_all(
                ":not(form) > button, [role=button]:not(form [role=button])")
        except Exception:
            return found

        for element in clickables:
            try:
                await element.click(timeout=2000)
                await page.wait_for_timeout(300)
                if page.url != base_url:
                    found.append(page.url)
                    await page.go_back(timeout=3000)
            except Exception:
                continue
        return found

    async def _fill_and_submit(self, page: Page, url: str) -> None:
        """Fill every fillable input on the page and click submit.

        Deliberately *not* scoped to ``<form>`` elements. Modern SPA auth,
        search, and feedback screens — this project's own practice target
        included — bind their inputs directly with no ``<form>`` wrapper at
        all, so a form-scoped fill sends nothing and the app's most
        interesting request (a login POST, a search) never fires. Filling
        page-wide by ``id``/``name``/``placeholder`` heuristics and then
        clicking the submit control is what actually puts that request on the
        wire, where ``on_request`` records it.

        This is the one place the crawl sends state-changing traffic. See the
        module docstring: the request's target is not vetted before it is
        sent, which is a deliberate scope decision for a disposable target.
        """
        try:
            fields = await page.query_selector_all("input, textarea, select")
        except Exception:
            return

        filled_any = False
        for field in fields:
            try:
                if not await field.is_visible():
                    continue
                tag = await field.evaluate("el => el.tagName.toLowerCase()")
                ftype = (await field.get_attribute("type") or "text").lower()
                if ftype in ("submit", "button", "hidden", "file", "image", "reset"):
                    continue
                if ftype in ("checkbox", "radio"):
                    await field.check(timeout=1500)
                    filled_any = True
                    continue
                name = await field.get_attribute("name") or ""
                fid = await field.get_attribute("id") or ""
                placeholder = await field.get_attribute("placeholder") or ""
                if tag == "select":
                    await field.select_option(index=0)
                else:
                    await field.fill(_guess_value(name, fid, placeholder, ftype),
                                     timeout=1500)
                filled_any = True
            except Exception:
                continue

        if not filled_any:
            return

        await self._click_submit(page)
        # Give the resulting XHR time to fire so on_request captures it.
        await page.wait_for_timeout(800)
        if page.url != url:
            try:
                await page.goto(url, wait_until="networkidle")
            except Exception:
                pass

    @staticmethod
    async def _click_submit(page: Page) -> None:
        """Click the first visible, enabled submit-like control on the page.

        Ordered most-specific first: a real submit control, then common id
        conventions, then any button as a last resort. A single click is
        enough — the goal is to fire the page's primary action, not to
        exhaustively press every button (that is `_click_clickables`' job, for
        navigation).
        """
        selectors = (
            "button[type=submit]",
            "input[type=submit]",
            "[id*='login' i] button",
            "button[id*='login' i]",
            "button[id*='submit' i]",
            "button[id*='send' i]",
            "button",
        )
        for selector in selectors:
            try:
                button = await page.query_selector(selector)
                if button is None:
                    continue
                if await button.is_visible() and await button.is_enabled():
                    await button.click(timeout=2000)
                    return
            except Exception:
                continue
