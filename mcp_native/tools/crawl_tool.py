"""crawl — browser-driven reconnaissance crawler, as a native MCP tool.

Wraps the tested Playwright crawler (``mcp_tools...crawl_tool.CrawlTool``) so the
recon agent can drive it over native MCP like every other tool. The crawler
enforces the engagement scope on every URL it derives; this tool builds that
scope from the arguments the recon loop passes.

Returns the crawler's dict: pages, forms, technologies, js_api_paths,
observed_requests (each tagged with the source_page that fired it),
third_party_hosts, pages_crawled, truncated.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from uuid import uuid4


async def crawl(
    url: str,
    allow_domains: list[str] | None = None,
    allow_paths: list[str] | None = None,
    deny_paths: list[str] | None = None,
    max_pages: int = 40,
    max_depth: int = 3,
) -> dict[str, Any]:
    """Crawl a target with a real headless browser and map its attack surface.

    Args:
        url: The seed URL to start from, e.g. "http://juice-shop:3000/".
        allow_domains: In-scope host patterns, e.g. ["juice-shop", "*.example.com"].
            Defaults to the seed's own host.
        allow_paths: Optional path allowlist (empty means all paths on allowed hosts).
        deny_paths: Optional path denylist.
        max_pages: Crawl page ceiling.
        max_depth: Link-follow depth ceiling.
    """
    # Imported here (not at module load) so the server still starts if Playwright
    # is unavailable in a given image; only calling crawl then fails.
    from shared.models import Scope
    from mcp_tools.services.tools.base import ToolContext
    from mcp_tools.services.tools.crawl_tool import CrawlTool

    domains = [d for d in (allow_domains or [urlparse(url).hostname or ""]) if d]
    scope = Scope(domains=domains, allow_paths=allow_paths or [],
                  deny_paths=deny_paths or [])
    ctx = ToolContext(engagement_id=uuid4(), caller="mcp-native", scope=scope)
    return await CrawlTool()(
        {"url": url, "max_pages": max_pages, "max_depth": max_depth}, ctx)


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Crawl a target with a real headless browser (Playwright/Chromium): "
        "executes page JavaScript, follows client-side links, submits forms, and "
        "records every in-scope request the browser fires — each tagged with the "
        "page that fired it. Returns pages, forms, technologies, observed_requests "
        "and candidate API paths. Enforces the engagement scope on every derived URL."
    ))(crawl)
    return ["crawl"]
