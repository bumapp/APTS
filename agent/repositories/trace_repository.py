"""Reads ``agent_trace`` back out for rendering.

The write side lives in :mod:`shared.trace`, because ``LlmClient`` and
``McpService`` both record and neither belongs to this container's layering.
Reading is only ever done here, by the terminal stage assembling the flow file,
so the query belongs in ``repositories/`` with every other SQL statement the
agent issues.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from shared.db import get_conn

log = logging.getLogger("agent.repositories.trace")


@dataclass(frozen=True)
class TraceEvent:
    """One recorded step in an engagement."""
    agent: str
    seq: int
    event_type: str
    payload: dict[str, Any]
    duration_ms: int | None
    logged_at: datetime


class TraceRepository:
    """Loads an engagement's full execution trace, in order."""

    def load(self, engagement_id: UUID) -> list[TraceEvent]:
        """Every event for this engagement, oldest first.

        Ordered by ``id`` rather than ``logged_at``: six agents write to this
        table and ``NOW()`` is transaction time, so two rows can share a
        timestamp. The serial ID is the only total order available, and it is
        the insertion order that the flow file wants.
        """
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT agent, seq, event_type, payload, duration_ms, logged_at
                   FROM agent_trace
                   WHERE engagement_id = %s
                   ORDER BY id""",
                (str(engagement_id),),
            )
            rows = cur.fetchall()

        return [TraceEvent(agent=agent, seq=seq, event_type=event_type,
                           payload=payload or {}, duration_ms=duration_ms,
                           logged_at=logged_at)
                for agent, seq, event_type, payload, duration_ms, logged_at in rows]
