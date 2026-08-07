"""Reads and writes ``agent_results`` — one stage's artifact for one engagement.

Upsert rather than insert on the result: a retried agent must overwrite its own
previous attempt, not accumulate rows the orchestrator would then have to
disambiguate. ``UNIQUE (engagement_id, agent)`` in the schema enforces that.

Audit writes used to live here too, in an ``AuditRepository`` this file's name
gave no hint of. They are now :class:`shared.audit.AuditLog`, shared with
mcp-tools, which had an identical copy.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

import psycopg

from shared.db import get_conn


class AgentResultRepository:
    """Persists one agent's artifact for one engagement."""

    def save(self, engagement_id: UUID, agent: str, payload: dict[str, Any]) -> None:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO agent_results (engagement_id, agent, payload)
                   VALUES (%s, %s, %s::jsonb)
                   ON CONFLICT (engagement_id, agent)
                   DO UPDATE SET payload = EXCLUDED.payload, written_at = NOW()""",
                (str(engagement_id), agent, psycopg.types.json.Json(payload)),
            )


    def load(self, engagement_id: UUID, agent: str) -> dict[str, Any] | None:
        """Read another stage's stored artifact.

        The shared context store is how stages see each other's work (PRD §4.1).
        A stage that needs more than its immediate predecessor's output — as
        Exploitation does, needing the Vulnerability Register that MITRE sits
        between it and — reads it from here rather than having every
        intervening stage forward it.
        """
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT payload FROM agent_results "
                "WHERE engagement_id = %s AND agent = %s",
                (str(engagement_id), agent),
            )
            row = cur.fetchone()
        return row[0] if row else None
