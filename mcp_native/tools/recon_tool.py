"""get_recorded_request — look up a request the recon crawler observed.

Reads the indexed ``recon_requests`` table (populated by the recon pipeline from
the authoritative AssetMap, never the crawl cache) and returns every request
matching an endpoint path, with full metadata: method, full URL, the page that
fired it, all request headers, and any request body.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse


def _normalise_endpoint(endpoint: str) -> str:
    """Reduce a full URL / path+query / bare path to just the path (lookup key)."""
    ep = (endpoint or "").strip()
    if "://" in ep:
        ep = urlparse(ep).path
    ep = ep.split("?", 1)[0].split("#", 1)[0]
    if not ep.startswith("/"):
        ep = "/" + ep
    return ep or "/"


def get_recorded_request(
    endpoint: str,
    engagement_id: str | None = None,
    method: str | None = None,
) -> dict[str, Any]:
    """Fetch recorded recon requests for an endpoint.

    Args:
        endpoint: The endpoint to look up, as a path or full URL (a full URL or
            a path with a query string are also accepted).
        engagement_id: Which scan to search; defaults to the latest recon scan.
        method: Optional filter, e.g. "POST" to get only the POST to that path.
    """
    from shared.db import get_conn  # lazy: only this tool needs the DB

    path = _normalise_endpoint(endpoint)
    with get_conn() as conn, conn.cursor() as cur:
        if not engagement_id:
            cur.execute("SELECT engagement_id FROM recon_requests "
                        "ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if row is None:
                return {"endpoint": path, "engagement_id": None,
                        "count": 0, "requests": [],
                        "note": "no recon requests are indexed yet"}
            engagement_id = str(row[0])

        query = ("SELECT method, url, path, source_page, content_type, "
                 "resource_type, headers, post_data FROM recon_requests "
                 "WHERE engagement_id = %s AND path = %s")
        params: list[Any] = [engagement_id, path]
        if method:
            query += " AND method = %s"
            params.append(method.upper())
        query += " ORDER BY seq"
        cur.execute(query, params)
        rows = cur.fetchall()

        matched = "exact"
        available: list[str] = []
        if not rows:
            cur.execute(
                "SELECT method, url, path, source_page, content_type, "
                "resource_type, headers, post_data FROM recon_requests "
                "WHERE engagement_id = %s AND path LIKE %s ORDER BY seq",
                [engagement_id, f"%{path}%"])
            rows = cur.fetchall()
            matched = "fuzzy (substring)" if rows else "none"
            if not rows:
                # Miss: hand back the real paths so the model corrects itself
                # rather than inventing an endpoint.
                cur.execute("SELECT DISTINCT path FROM recon_requests "
                            "WHERE engagement_id = %s ORDER BY path", [engagement_id])
                available = [r[0] for r in cur.fetchall()]

    requests = [
        {"method": m, "url": u, "path": p, "source_page": sp,
         "content_type": ct, "resource_type": rt, "headers": h, "post_data": pd}
        for (m, u, p, sp, ct, rt, h, pd) in rows
    ]
    result = {"endpoint": path, "engagement_id": engagement_id,
              "match": matched, "count": len(requests), "requests": requests}
    if matched == "none":
        result["available_paths"] = available
        result["guidance"] = (
            "No request was recorded for that exact endpoint. Do NOT invent a "
            "URL. Pick the correct one from available_paths and call this tool "
            "again with it.")
    return result


def list_recorded_requests(
    engagement_id: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    """List the requests recon observed, one per unique method+path.

    The batch the Vulnerability agent iterates over: every distinct endpoint the
    crawler actually hit, deduplicated (the earliest request for each method+path
    is kept, so a login POST keeps its real body). Full per-request detail is
    still available via :func:`get_recorded_request`.

    Args:
        engagement_id: Which scan to list; defaults to the latest recon scan.
        limit: Maximum distinct requests to return.
    """
    from shared.db import get_conn  # lazy: only this tool needs the DB

    with get_conn() as conn, conn.cursor() as cur:
        if not engagement_id:
            cur.execute("SELECT engagement_id FROM recon_requests "
                        "ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if row is None:
                return {"engagement_id": None, "count": 0, "requests": [],
                        "note": "no recon requests are indexed yet"}
            engagement_id = str(row[0])

        cur.execute(
            "SELECT method, url, path, source_page, content_type, "
            "resource_type, headers, post_data FROM recon_requests "
            "WHERE engagement_id = %s ORDER BY seq", [engagement_id])
        rows = cur.fetchall()

    seen: set[tuple[str, str]] = set()
    requests: list[dict[str, Any]] = []
    for (m, u, p, sp, ct, rt, h, pd) in rows:
        key = (m, p)
        if key in seen:
            continue
        seen.add(key)
        requests.append(
            {"method": m, "url": u, "path": p, "source_page": sp,
             "content_type": ct, "resource_type": rt, "headers": h,
             "post_data": pd})
        if len(requests) >= limit:
            break

    return {"engagement_id": engagement_id, "count": len(requests),
            "requests": requests}


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Fetch an HTTP request the reconnaissance crawler actually observed, by "
        "its endpoint path. Returns every matching request with full metadata: "
        "method, full URL, the page that fired it, all request headers, and any "
        "request body. Use this to see exactly how the app calls an endpoint — "
        "the real headers and payload — instead of guessing. If engagement_id is "
        "omitted, the most recent recon scan is used."
    ))(get_recorded_request)
    mcp.tool(description=(
        "List the requests reconnaissance observed, deduplicated to one per "
        "method+path — the batch of distinct endpoints to assess. If "
        "engagement_id is omitted, the most recent recon scan is used."
    ))(list_recorded_requests)
    return ["get_recorded_request", "list_recorded_requests"]
