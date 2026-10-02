"""The audit trail, bound to one component.

PRD §8 wants an immutable record of every agent action and every Guardrails
decision. The raw ``INSERT`` lives in :func:`shared.db.audit`; this adds the one
thing every caller needs on top of it — the component name — and binds it at
construction so a caller cannot mislabel an event as originating somewhere else.

Why this is in ``shared/`` rather than once per package
------------------------------------------------------
It used to be twice: ``agent.repositories.agent_result_repository.AuditRepository``
and ``mcp_tools.repositories.audit_repository.AuditRepository``, same name, same
signature, byte-identical bodies, both forwarding to ``shared.db.audit``.

Both containers' composition roots claim ``repositories/`` holds every SQL
statement the container issues. For audit that was already untrue — the
statement is in ``shared/db.py`` and always was, so the per-package classes
bought a name, not an encapsulation boundary. Collapsing them here removes the
duplicate without moving any SQL.

The agent side also passed its component on every single call. Five call sites
repeating ``self._component`` is five chances to pass the wrong one.
"""
from __future__ import annotations

from typing import Callable, Protocol

from shared.db import audit as _write_row


class AuditSink(Protocol):
    """What a caller needs in order to record an event.

    A Protocol rather than the concrete class so providers can be tested with an
    in-memory fake. That matters more than it looks: enforcement that works but
    leaves no trace still fails §8, and that gap is invisible when audit is
    patched away entirely.
    """

    def record(self, event_type: str, engagement_id: str | None = None,
               detail: dict | None = None) -> None: ...


class AuditLog:
    """Records audit events on behalf of one component."""

    def __init__(self, component: str,
                 writer: Callable[..., None] | None = None) -> None:
        self._component = component
        self._writer = writer or _write_row

    def record(self, event_type: str, engagement_id: str | None = None,
               detail: dict | None = None) -> None:
        """Append one row. Best-effort: ``shared.db.audit`` swallows its failures.

        Best-effort and immutable are different claims, and this is the former —
        §8 asks for the latter. Closing that gap means either a durable local
        buffer or refusing tool calls outright when audit is unavailable, and
        which one is a product decision rather than a coding one.
        """
        self._writer(self._component, event_type,
                     engagement_id=engagement_id, detail=detail or {})
