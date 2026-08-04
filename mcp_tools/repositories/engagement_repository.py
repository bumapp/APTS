"""Read access to the ``engagements`` table.

Raw data access only: one statement, one row, no caching and no policy. The
decision about how long a scope may be held in memory belongs one layer up in
:class:`~mcp_tools.services.engagement_service.EngagementService`, because it
is a judgement about the data rather than a fact about the table.

Scope is read from the database rather than taken from the caller's arguments
on purpose: an agent must not be able to widen its own boundary by claiming a
larger scope than the operator approved at intake.

Read-only by design. Per PRD §3.2 the MCP container has no business writing to
``engagements`` — the Orchestrator owns that table — so no write method exists
here to be called by mistake.
"""
from __future__ import annotations

import logging

from shared.db import get_conn
from shared.models import Scope

log = logging.getLogger("mcp.repositories.engagement")


class ScopeUnavailable(Exception):
    """Raised when an engagement's scope cannot be established.

    Callers must treat this as a denial rather than an error to retry around.
    "I could not determine the scope" and "this is out of scope" have to
    produce the same outcome, or the failure mode becomes a bypass.
    """


class EngagementRepository:
    """Fetches engagement scope from Postgres."""

    def get_scope(self, engagement_id: str) -> Scope:
        """Return the approved scope for ``engagement_id``.

        Raises :class:`ScopeUnavailable` for a missing row, an unreachable
        database, or a scope column that will not parse — three different
        causes with one correct response.
        """
        try:
            with get_conn() as conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT scope FROM engagements WHERE id = %s", (engagement_id,))
                row = cur.fetchone()
        except Exception as exc:
            log.error("scope lookup failed for %s: %s", engagement_id, exc)
            raise ScopeUnavailable(
                f"scope lookup failed for engagement {engagement_id}: {exc}") from exc

        if row is None:
            raise ScopeUnavailable(
                f"no engagement {engagement_id!r} on record; cannot establish scope")

        try:
            return Scope(**(row[0] or {}))
        except Exception as exc:
            log.error("engagement %s has a malformed scope column: %s",
                      engagement_id, exc)
            raise ScopeUnavailable(
                f"engagement {engagement_id!r} has an unreadable scope: {exc}") from exc
