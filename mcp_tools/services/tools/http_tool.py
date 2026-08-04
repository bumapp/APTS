"""Real HTTP fetch against the engagement target.

The first tool that puts packets on the wire, so the properties that matter are
as much about restraint as capability.

*Redirects are not followed.* A redirect is a new URL the guardrails checkpoint
never saw, and following it silently is the same scope bypass a crawler would
commit. The redirect target is returned as data; if an agent wants it fetched,
it asks again and the checkpoint runs again.

*Bodies are truncated.* An uncapped response is the most common way an agent
pipeline exhausts its context window mid-engagement. The cap is reported so a
consumer can tell a short page from a clipped one.

*Responses are sanitised.* Everything here is attacker-controlled by
definition — that is the point of the engagement — so the body passes through
the injection filter before an agent ever reads it.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from mcp_tools.config import HTTP_BODY_LIMIT, TARGET_TIMEOUT_SECONDS
from mcp_tools.services.tools.base import ToolContext
from mcp_tools.utils.sanitise import strip_injection

log = logging.getLogger("mcp.services.tools.http")

# Methods an agent may issue. Deliberately excludes nothing dangerous-by-name —
# a pentest legitimately needs PUT and DELETE against a sandboxed target — but
# does exclude CONNECT, which would turn this tool into a proxy.
ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


class HttpTool:
    """Issues one HTTP request and returns the response as structured data."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def __call__(self, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
        url = str(args.get("url") or "")
        method = str(args.get("method", "GET")).upper()
        if method not in ALLOWED_METHODS:
            return {"error": f"method {method!r} is not permitted",
                    "allowed": sorted(ALLOWED_METHODS)}

        try:
            response = await self._client.request(
                method, url,
                headers=args.get("headers") or {},
                content=args.get("body"),
                follow_redirects=False,
                timeout=TARGET_TIMEOUT_SECONDS,
            )
        except httpx.HTTPError as exc:
            # A dead target is data the agent must reason about, not a tool
            # crash — an unreachable host is itself a recon finding.
            log.info("http %s %s failed: %s", method, url, exc)
            return {"error": f"request failed: {exc}", "url": url}

        raw = response.text
        body = strip_injection(raw[:HTTP_BODY_LIMIT])

        return {
            "url": str(response.url),
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": body,
            "truncated": len(raw) > HTTP_BODY_LIMIT,
            "redirect_to": response.headers.get("location"),
            "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
        }
