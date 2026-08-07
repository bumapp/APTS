"""Crawler tests, centred on the scope boundary.

The crawler is the first tool that issues requests nobody asked for. The
guardrails checkpoint vetted the seed URL and nothing else, so every link the
crawler discovers is a URL that has never been checked. If it followed those
blindly, one ``<a href="https://evil.test/">`` on an in-scope page would take
the whole deployment out of scope — silently, and while reporting success.

So the tests that matter here are the ones asserting what the crawler *did not*
fetch. A fake target serves the pages; the request log is the evidence.
"""
from __future__ import annotations

from uuid import uuid4

import httpx

from shared.models import Scope

from mcp_tools.services.tools.base import ToolContext
from mcp_tools.services.tools.crawl_tool import CrawlTool

SCOPE = Scope(domains=["*.target.test"], deny_paths=["/admin/"])


def ctx(scope: Scope = SCOPE) -> ToolContext:
    return ToolContext(engagement_id=uuid4(), caller="agent-recon", scope=scope)


class FakeSite:
    """Serves canned pages and records every URL actually requested."""

    def __init__(self, pages: dict[str, str]) -> None:
        self.pages = pages
        self.requested: list[str] = []

    def client(self) -> httpx.AsyncClient:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            self.requested.append(url)
            body = self.pages.get(url)
            if body is None:
                return httpx.Response(404, text="not found",
                                      headers={"content-type": "text/html"})
            return httpx.Response(200, text=body, headers={
                "content-type": "text/html", "server": "nginx/1.25"})

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def page(*links: str, forms: str = "") -> str:
    body = "".join(f'<a href="{href}">x</a>' for href in links)
    return f"<html><head><title>t</title></head><body>{body}{forms}</body></html>"


# --------------------------------------------------------------------------- #
# Scope enforcement on discovered links
# --------------------------------------------------------------------------- #

async def test_offsite_links_are_never_fetched():
    site = FakeSite({
        "https://target.test/": page("https://evil.test/steal", "/about"),
        "https://target.test/about": page(),
    })
    result = await CrawlTool(site.client())({"url": "https://target.test/"}, ctx())

    assert "https://evil.test/steal" not in site.requested
    assert result["out_of_scope_skipped"] == 1
    assert {p["url"] for p in result["pages"]} == {
        "https://target.test/", "https://target.test/about"}


async def test_denied_paths_are_never_fetched():
    site = FakeSite({
        "https://target.test/": page("/admin/panel", "/public"),
        "https://target.test/public": page(),
    })
    await CrawlTool(site.client())({"url": "https://target.test/"}, ctx())

    assert "https://target.test/admin/panel" not in site.requested


async def test_allow_paths_confine_the_crawl():
    scope = Scope(domains=["target.test"], allow_paths=["/app/"])
    site = FakeSite({
        "https://target.test/app/": page("/app/next", "/elsewhere"),
        "https://target.test/app/next": page(),
    })
    await CrawlTool(site.client())({"url": "https://target.test/app/"}, ctx(scope))

    assert "https://target.test/elsewhere" not in site.requested


async def test_subdomain_within_wildcard_is_followed():
    site = FakeSite({
        "https://target.test/": page("https://api.target.test/v1"),
        "https://api.target.test/v1": page(),
    })
    await CrawlTool(site.client())({"url": "https://target.test/"}, ctx())

    assert "https://api.target.test/v1" in site.requested


async def test_non_http_schemes_ignored():
    site = FakeSite({"https://target.test/": page(
        "mailto:a@b.test", "javascript:alert(1)", "tel:+123")})
    await CrawlTool(site.client())({"url": "https://target.test/"}, ctx())

    assert site.requested == ["https://target.test/"]


# --------------------------------------------------------------------------- #
# Bounds
# --------------------------------------------------------------------------- #

def fan_out(count: int) -> dict[str, str]:
    """A hub linking to `count` leaf pages — wide, not deep.

    Deliberately shallow so the depth limit cannot be what stops the crawl;
    otherwise this would pass while testing the wrong ceiling.
    """
    pages = {"https://target.test/": page(*[f"/p{i}" for i in range(count)])}
    pages.update({f"https://target.test/p{i}": page() for i in range(count)})
    return pages


async def test_page_limit_is_enforced_and_reported():
    result = await CrawlTool(FakeSite(fan_out(30)).client())(
        {"url": "https://target.test/", "max_pages": 5}, ctx())

    assert result["pages_crawled"] == 5
    assert result["truncated"] is True


async def test_argument_cannot_raise_the_configured_ceiling():
    """A caller may lower a limit; it must not be able to raise one."""
    result = await CrawlTool(FakeSite(fan_out(200)).client())(
        {"url": "https://target.test/", "max_pages": 10_000}, ctx())

    assert result["pages_crawled"] <= 40          # CRAWL_MAX_PAGES
    assert result["truncated"] is True


async def test_depth_limit_respected():
    site = FakeSite({
        "https://target.test/": page("/a"),
        "https://target.test/a": page("/b"),
        "https://target.test/b": page("/c"),
        "https://target.test/c": page(),
    })
    await CrawlTool(site.client())(
        {"url": "https://target.test/", "max_depth": 1}, ctx())

    assert "https://target.test/b" not in site.requested


async def test_a_page_is_never_fetched_twice():
    site = FakeSite({
        "https://target.test/": page("/a", "/a", "/a#frag"),
        "https://target.test/a": page("/"),
    })
    await CrawlTool(site.client())({"url": "https://target.test/"}, ctx())

    assert site.requested.count("https://target.test/a") == 1


# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #

async def test_forms_and_technologies_extracted():
    login = ('<form action="/login" method="post">'
             '<input name="email" type="email">'
             '<input name="password" type="password"></form>')
    site = FakeSite({"https://target.test/": page(forms=login)})
    result = await CrawlTool(site.client())({"url": "https://target.test/"}, ctx())

    form = result["forms"][0]
    assert form["method"] == "POST"
    assert [f["name"] for f in form["fields"]] == ["email", "password"]
    assert any(t["name"] == "nginx/1.25" for t in result["technologies"])


async def test_third_party_script_hosts_recorded():
    html = ('<html><body><script src="https://cdn.evil-analytics.test/t.js">'
            '</script></body></html>')
    site = FakeSite({"https://target.test/": html})
    result = await CrawlTool(site.client())({"url": "https://target.test/"}, ctx())

    assert result["third_party_hosts"] == ["cdn.evil-analytics.test"]
    assert "https://cdn.evil-analytics.test/t.js" not in site.requested


async def test_unreachable_target_is_data_not_a_crash():
    def dead(request):
        raise httpx.ConnectError("connection refused")

    client = httpx.AsyncClient(transport=httpx.MockTransport(dead))
    result = await CrawlTool(client)({"url": "https://target.test/"}, ctx())

    assert result["pages_crawled"] == 0
