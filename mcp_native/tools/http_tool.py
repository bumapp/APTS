"""http_request — send one HTTP request and read the response.

The simplest tool: the model chooses the method, URL, headers, and body.
Redirects are not followed; the Location header is returned instead.
"""
from __future__ import annotations

import json
from typing import Any

import httpx

_ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_BODY_LIMIT = 8000


async def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | int | float | bool | dict | list | None = None,
) -> dict[str, Any]:
    """Perform a single HTTP request.

    Args:
        url: The full URL to request (scheme, host, path, and any query string).
        method: GET, POST, PUT, PATCH, DELETE, HEAD, or OPTIONS.
        headers: Optional request headers as a flat string->string map.
        body: Optional request body. A string is sent as-is; a dict/list is sent
            as JSON; a number/bool is stringified — so a model passing e.g. the
            engine.io frame ``40`` never crashes the tool on a type mismatch.
    """
    verb = method.upper()
    if verb not in _ALLOWED_METHODS:
        return {"error": f"method {verb!r} not allowed",
                "allowed": sorted(_ALLOWED_METHODS)}
    if body is not None and not isinstance(body, str):
        body = json.dumps(body) if isinstance(body, (dict, list)) else str(body)
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=20.0) as client:
            response = await client.request(
                verb, url, headers=headers or {}, content=body)
    except httpx.HTTPError as exc:
        return {"error": f"request failed: {exc}", "url": url}

    text = response.text
    return {
        "url": str(response.url),
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": text[:_BODY_LIMIT],
        "truncated": len(text) > _BODY_LIMIT,
        "redirect_to": response.headers.get("location"),
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Send one HTTP request and return the response. You choose the method, "
        "URL, headers, and body. Redirects are NOT followed — the Location "
        "header is returned so you can decide whether to request it next."
    ))(http_request)
    return ["http_request"]
