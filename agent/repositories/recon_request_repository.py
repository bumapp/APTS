"""Indexes recon's observed HTTP requests into ``recon_requests``.

Recon already stores its captured requests inside the AssetMap it persists to
``agent_results``. That JSON array is the record; this repository is the
*indexed projection* of it, one row per request keyed by normalised path, so a
later consumer (the MCP ``get_recorded_request`` tool) can look a request up by
its endpoint precisely rather than scanning a blob.

Written from the recon persistence path, replacing any prior rows for the
engagement so a recon retry re-indexes cleanly rather than accumulating
duplicates. Reads live elsewhere: the MCP server queries this same table
directly.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import psycopg

from shared.db import get_conn


class ReconRequestRepository:
    """Projects recon's ``observed_requests`` into the indexed table."""

    def index(self, engagement_id: UUID,
              observed_requests: list[dict[str, Any]]) -> int:
        """Replace this engagement's indexed requests with ``observed_requests``.

        Returns the number of rows written. A no-op (still clears old rows) when
        the list is empty, so a re-run that found nothing does not leave stale
        rows behind.
        """
        rows = [self._row(engagement_id, seq, req)
                for seq, req in enumerate(observed_requests)]

        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM recon_requests WHERE engagement_id = %s",
                        (str(engagement_id),))
            if rows:
                cur.executemany(
                    """INSERT INTO recon_requests
                       (engagement_id, seq, method, url, path, source_page,
                        content_type, resource_type, headers, post_data)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)""",
                    rows,
                )
        return len(rows)

    @staticmethod
    def _row(engagement_id: UUID, seq: int, req: dict[str, Any]) -> tuple:
        url = str(req.get("url") or "")
        path = urlparse(url).path or "/"
        headers = req.get("headers") or {}
        # The page that fired the request is its Referer. Header casing varies by
        # source, so check both.
        source_page = str(headers.get("referer") or headers.get("Referer") or "")
        return (
            str(engagement_id),
            seq,
            str(req.get("method") or "GET").upper(),
            url,
            path,
            source_page,
            str(req.get("content_type") or ""),
            str(req.get("resource_type") or ""),
            psycopg.types.json.Json(headers),
            req.get("post_data"),
        )
