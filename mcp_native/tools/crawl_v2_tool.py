"""crawl_v2 — generic browser crawler (no heuristics), as a native MCP tool.

Wraps :class:`mcp_native.crawler.crawler_v2.CrawlToolV2`. Same output shape as
``crawl`` (so the recon worker consumes it unchanged), but discovery is purely
"locate the clickables the page shows and click them" — no menu selectors, no
route-mining regex, no English field/submit guessing. v1's ``crawl`` is left
completely untouched; this is a separate tool you can A/B against it.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from uuid import uuid4


async def crawl_v2(
    url: str,
    allow_domains: list[str] | None = None,
    allow_paths: list[str] | None = None,
    deny_paths: list[str] | None = None,
    max_pages: int = 40,
    max_depth: int = 3,
    skip_urls: list[str] | None = None,
    headers: dict[str, str] | None = None,
    cookies: list[dict] | None = None,
    basic_auth: dict | None = None,
) -> dict[str, Any]:
    """Crawl a target by clicking through its live UI with a real headless browser.

    Discovers pages the generic way — it fills inputs by their HTML type and
    clicks the interactive elements the browser reports (links, buttons, menu
    items, onclick handlers) — so menus open, JS-only routes fire and forms submit
    without any site-, framework- or language-specific rules. Records every
    in-scope request the browser fires. Enforces the engagement scope on every URL.

    Args mirror ``crawl``: url (seed), allow_domains/allow_paths/deny_paths (scope),
    max_pages, max_depth, skip_urls (pages to skip), and optional auth
    (headers / cookies / basic_auth) — secrets reach in-scope hosts only.
    """
    from shared.models import Scope
    from mcp_native.crawler.context import ToolContext
    from mcp_native.crawler.crawler_v2 import CrawlToolV2

    domains = [d for d in (allow_domains or [urlparse(url).hostname or ""]) if d]
    scope = Scope(domains=domains, allow_paths=allow_paths or [],
                  deny_paths=deny_paths or [])
    ctx = ToolContext(engagement_id=uuid4(), caller="mcp-native", scope=scope)
    return await CrawlToolV2()(
        {"url": url, "max_pages": max_pages, "max_depth": max_depth,
         "skip_urls": skip_urls or [], "headers": headers, "cookies": cookies,
         "basic_auth": basic_auth}, ctx)


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Crawl a target with a real headless browser, discovering purely by "
        "clicking the interactive elements the page shows (links, buttons, menu "
        "items, onclick handlers) and filling inputs by their HTML type — no "
        "site/framework/language-specific rules. Menus open, JS-only routes fire, "
        "forms submit. Returns pages, observed_requests (every in-scope request "
        "fired, with full bodies) and candidate api paths. Enforces scope. Like "
        "'crawl' but heuristic-free; submits forms, so use a disposable target."
    ))(crawl_v2)
    return ["crawl_v2"]
