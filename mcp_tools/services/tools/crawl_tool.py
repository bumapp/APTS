"""Bounded crawler — maps a target's reachable surface.

This is the first tool that generates requests nobody explicitly asked for, and
that makes it the first one that could take the deployment out of scope on its
own. Two properties matter more than coverage:

**Every derived URL is re-checked against the engagement scope.** The guardrails
checkpoint validated the seed URL only; every link discovered afterwards is a
URL it never saw. A link to ``https://evil.test/`` on a page of an in-scope
target is not hypothetical — it is what an external ``<a href>`` looks like, and
an unchecked crawler would happily fetch it. Links failing the check are counted
and discarded, never followed.

**Everything is bounded.** Page count, depth, per-page body size, and total
wall-clock all have ceilings. An unbounded crawl on a large app is how an agent
pipeline exhausts its context window and how a "scan" turns into something the
target's owner would reasonably call a denial-of-service attempt. When a limit
stops the sweep the result says so, so a coverage figure derived from it cannot
silently read as complete.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse

import httpx

from shared.scope_match import host_matches, matching_deny_path, path_allowed

from mcp_tools.config import (
    CRAWL_BODY_LIMIT,
    CRAWL_MAX_SCRIPTS,
    CRAWL_SCRIPT_LIMIT,
    CRAWL_MAX_DEPTH,
    CRAWL_MAX_PAGES,
    CRAWL_MAX_SECONDS,
    TARGET_TIMEOUT_SECONDS,
)
from mcp_tools.services.tools.base import ToolContext
from mcp_tools.utils.html import parse_page
from mcp_tools.utils.js_endpoints import extract_api_paths

log = logging.getLogger("mcp.services.tools.crawl")

# Extensions worth discovering but not worth downloading and parsing.
_SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
                  ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".css")


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


class CrawlTool:
    """Breadth-first crawl of a target, bounded on every axis."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def __call__(self, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
        seed = str(args.get("url") or "")
        max_pages = min(int(args.get("max_pages", CRAWL_MAX_PAGES)), CRAWL_MAX_PAGES)
        max_depth = min(int(args.get("max_depth", CRAWL_MAX_DEPTH)), CRAWL_MAX_DEPTH)

        queue: deque[tuple[str, int]] = deque([(seed, 0)])
        seen: set[str] = {seed}
        pages: list[dict] = []
        forms: list[dict] = []
        scripts: set[str] = set()
        third_party: set[str] = set()
        technologies: dict[str, str] = {}
        out_of_scope_skipped = 0
        deadline = time.monotonic() + CRAWL_MAX_SECONDS
        truncated = False

        while queue:
            if len(pages) >= max_pages or time.monotonic() > deadline:
                truncated = True
                break

            url, depth = queue.popleft()
            page = await self._fetch(url)
            if page is None:
                continue
            pages.append(page)

            self._note_technologies(page, technologies)
            if depth >= max_depth or not page.get("html"):
                continue

            parsed = parse_page(page.pop("html"))
            if parsed.generator:
                technologies.setdefault(parsed.generator, "meta generator")

            for form in parsed.forms:
                form["page"] = url
                forms.append(form)

            for src in parsed.scripts:
                absolute = urljoin(url, src)
                scripts.add(absolute)
                host = urlparse(absolute).hostname
                if host and not host_matches(host, ctx.scope.domains):
                    third_party.add(host)

            for href in parsed.links:
                target = urldefrag(urljoin(url, href)).url
                if target in seen or target.lower().endswith(_SKIP_SUFFIXES):
                    continue
                seen.add(target)
                if not _in_scope(target, ctx):
                    out_of_scope_skipped += 1
                    continue
                queue.append((target, depth + 1))

        # Mine in-scope JS bundles for API routes. On a single-page app this is
        # the only thing that finds any surface at all: the HTML shell has no
        # links, and every route the app calls lives as a literal in its bundle.
        js_paths = await self._mine_scripts(scripts, ctx)

        for page in pages:
            page.pop("html", None)

        if truncated:
            log.info("crawl of %s stopped at a limit (%d pages)", seed, len(pages))
        if out_of_scope_skipped:
            log.info("crawl skipped %d out-of-scope links", out_of_scope_skipped)

        return {
            "seed": seed,
            "pages": pages,
            "forms": forms,
            "scripts": sorted(scripts),
            "js_api_paths": js_paths,
            "third_party_hosts": sorted(third_party),
            "technologies": [{"name": k, "source": v} for k, v in technologies.items()],
            "pages_crawled": len(pages),
            "out_of_scope_skipped": out_of_scope_skipped,
            "truncated": truncated,
        }

    # ----------------------------------------------------------------- #

    async def _mine_scripts(self, scripts: set[str], ctx: ToolContext) -> list[str]:
        """Fetch in-scope script bundles and extract candidate API paths.

        Scope applies here exactly as it does to page links. A third-party CDN
        script is out of scope, and fetching it would be an unapproved request
        to a host the engagement never authorised — so those are skipped, and
        their host is already recorded as third-party surface instead.
        """
        paths: set[str] = set()
        fetched = 0
        for src in sorted(scripts):
            if fetched >= CRAWL_MAX_SCRIPTS:
                break
            if not _in_scope(src, ctx):
                continue
            try:
                response = await self._client.get(
                    src, follow_redirects=False, timeout=TARGET_TIMEOUT_SECONDS)
            except httpx.HTTPError as exc:
                log.debug("script fetch failed %s: %s", src, exc)
                continue
            fetched += 1
            paths.update(extract_api_paths(response.text[:CRAWL_SCRIPT_LIMIT]))

        if paths:
            log.info("extracted %d candidate API paths from %d bundles",
                     len(paths), fetched)
        return sorted(paths)

    async def _fetch(self, url: str) -> dict | None:
        try:
            response = await self._client.get(
                url, follow_redirects=False, timeout=TARGET_TIMEOUT_SECONDS)
        except httpx.HTTPError as exc:
            log.debug("crawl fetch failed %s: %s", url, exc)
            return None

        content_type = response.headers.get("content-type", "")
        record = {
            "url": url,
            "status": response.status_code,
            "content_type": content_type.split(";")[0].strip(),
            "server": response.headers.get("server", ""),
            "powered_by": response.headers.get("x-powered-by", ""),
        }
        if "html" in content_type:
            record["html"] = response.text[:CRAWL_BODY_LIMIT]
        return record

    @staticmethod
    def _note_technologies(page: dict, into: dict[str, str]) -> None:
        """Fingerprint from response headers — cheap, deterministic, no guessing."""
        if page.get("server"):
            into.setdefault(page["server"], "Server header")
        if page.get("powered_by"):
            into.setdefault(page["powered_by"], "X-Powered-By header")
