"""Append-only writes to the ``audit_log`` table.

Raw data access only. What is worth recording is decided by
:class:`~mcp_tools.services.audit_service.AuditService` and the provider above
it; this knows only how a row reaches Postgres.
"""
from __future__ import annotations

from shared.db import audit


class AuditRepository:
    """Writes one row to ``audit_log``.

    Best-effort by way of ``shared.db.audit``, which swallows its own failures.
    That is a trade-off inherited from the skeleton: losing an audit row is bad,
    but taking down a live engagement because a log write failed is worse.

    It does not, however, satisfy PRD §8's "immutable audit log for every agent
    action" — best-effort and immutable are different claims. Closing that means
    either a durable local buffer or refusing tool calls outright when audit is
    unavailable, and which one is a product decision.
    """

    def record(self, component: str, event_type: str,
               engagement_id: str | None = None,
               detail: dict | None = None) -> None:
        audit(component, event_type,
              engagement_id=engagement_id, detail=detail or {})
