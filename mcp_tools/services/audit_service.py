"""Recording engagement events to the audit trail.

The audit trail is a product requirement, not a logging convenience: PRD §8
demands an immutable record of every agent action and every Guardrails
decision. Routing it through this service rather than calling the database
directly buys two things.

First, the layering stays honest — the provider decides *what* is worth
recording, this service knows *who* is recording it, and the repository knows
where the row goes.

Second, it makes the trail testable. A fake sink lets a test assert that a
blocked call was actually written down as blocked, which matters: enforcement
that works but leaves no trace still fails the requirement, and that gap is
invisible when audit is patched away.
"""
from __future__ import annotations

from typing import Protocol

from mcp_tools.repositories.audit_repository import AuditRepository


class AuditSink(Protocol):
    """What the provider needs in order to record an event."""

    def record(self, event_type: str, engagement_id: str | None = None,
               detail: dict | None = None) -> None: ...


class AuditService:
    """Records audit events on behalf of one component.

    The component name is bound at construction so callers cannot mislabel an
    event as originating somewhere else.
    """

    def __init__(self, component: str,
                 repository: AuditRepository | None = None) -> None:
        self._component = component
        self._repository = repository or AuditRepository()

    def record(self, event_type: str, engagement_id: str | None = None,
               detail: dict | None = None) -> None:
        self._repository.record(self._component, event_type,
                                engagement_id=engagement_id, detail=detail)
