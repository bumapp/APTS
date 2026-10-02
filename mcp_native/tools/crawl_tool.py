"""crawl — browser-driven reconnaissance crawler, as a native MCP tool.

Wraps the Playwright crawler (``mcp_native.crawler.crawler.CrawlTool``) so the
recon agent can drive it over native MCP like every other tool. The crawler
enforces the engagement scope on every URL it derives; this tool builds that
scope from the arguments the recon loop passes.

Returns the crawler's dict: pages, forms, technologies, js_api_paths,
observed_requests (each tagged with the source_page that fired it),
third_party_hosts, pages_crawled, truncated.
"""
from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

# Default to the crawler's full ceilings so a plain crawl (recon passes no override)
# maps the WHOLE surface. The crawler still clamps to CRAWL_MAX_* as a hard cap.
_DEFAULT_MAX_PAGES = int(os.environ.get("APTS_CRAWL_MAX_PAGES", "150"))
_DEFAULT_MAX_DEPTH = int(os.environ.get("APTS_CRAWL_MAX_DEPTH", "4"))


async def crawl(
    url: str,
    allow_domains: list[str] | None = None,
    allow_paths: list[str] | None = None,
    deny_paths: list[str] | None = None,
    max_pages: int = _DEFAULT_MAX_PAGES,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    headers: dict[str, str] | None = None,
    cookies: list[dict] | None = None,
    basic_auth: dict | None = None,
) -> dict[str, Any]:
    """Crawl a target with a real headless browser and map its attack surface.

    Supply credentials to crawl authenticated areas — any secret is only ever sent
    to in-scope hosts (out-of-scope requests are aborted before they leave).

    Args:
        url: The seed URL to start from.
        allow_domains: In-scope host patterns (defaults to the seed's own host).
        allow_paths: Optional path allowlist (empty means all paths on allowed hosts).
        deny_paths: Optional path denylist.
        max_pages: Crawl page ceiling.
        max_depth: Link-follow depth ceiling.
        headers: Extra HTTP headers sent on every in-scope request — use for a
            bearer/access token or API key, e.g. {"Authorization": "Bearer <token>"}
            or {"X-API-Key": "<key>"}.
        cookies: Session cookies, each {"name","value"} plus optionally "url" or
            "domain"/"path" (defaults to the seed's URL if neither given).
        basic_auth: HTTP Basic credentials, {"username","password"}.
    """
    # Imported here (not at module load) so the server still starts if Playwright
    # is unavailable in a given image; only calling crawl then fails.
    from shared.models import Scope
    from mcp_native.crawler.context import ToolContext
    from mcp_native.crawler.crawler import CrawlTool

    domains = [d for d in (allow_domains or [urlparse(url).hostname or ""]) if d]
    scope = Scope(domains=domains, allow_paths=allow_paths or [],
                  deny_paths=deny_paths or [])
    ctx = ToolContext(engagement_id=uuid4(), caller="mcp-native", scope=scope)
    return await CrawlTool()(
        {"url": url, "max_pages": max_pages, "max_depth": max_depth,
         "headers": headers, "cookies": cookies, "basic_auth": basic_auth}, ctx)


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Crawl a target with a real headless browser (Playwright/Chromium): "
        "executes page JavaScript, follows client-side links, submits forms, and "
        "records every in-scope request the browser fires — each tagged with the "
        "page that fired it. Returns pages, forms, technologies, observed_requests "
        "and candidate API paths. Enforces the engagement scope on every derived URL. "
        "Optional auth to crawl behind a login: headers (e.g. an Authorization "
        "bearer token or API key), cookies (session cookies), or basic_auth "
        "(username/password) — secrets reach in-scope hosts only."
    ))(crawl)
    return ["crawl"]
