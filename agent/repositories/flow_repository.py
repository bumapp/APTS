"""Writes the execution flow to disk, next to the report.

Same directory and same failure policy as :mod:`agent.repositories.report_repository`:
two formats — JSON for machines, Markdown for people — and an unwritable
directory is logged rather than raised. The trace is already safe in
``agent_trace``; failing a completed engagement because its flow file could not
be written would trade the deliverable for a copy of the audit trail.

The JSON form is not a re-serialisation of the Markdown. It is the raw event
list, so anything the renderer chooses not to show is still recoverable from the
file without a database.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from uuid import UUID

from agent.repositories.trace_repository import TraceEvent
from agent.services.flow_renderer import render_markdown

log = logging.getLogger("agent.repositories.flow")

REPORT_DIR = os.environ.get("APTS_REPORT_DIR", "/var/apts/reports")


class FlowRepository:
    """Persists an engagement's execution trace as JSON and Markdown."""

    def __init__(self, directory: str = REPORT_DIR) -> None:
        self._dir = Path(directory)

    def save(self, engagement_id: UUID, events: list[TraceEvent]) -> list[str]:
        """Write both formats and return the paths written."""
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.error("cannot create report directory %s: %s", self._dir, exc)
            return []

        stem = f"flow-{engagement_id}"
        payload = {
            "engagement_id": str(engagement_id),
            "event_count": len(events),
            "events": [
                {
                    "agent": e.agent,
                    "seq": e.seq,
                    "event_type": e.event_type,
                    "duration_ms": e.duration_ms,
                    "logged_at": e.logged_at.isoformat(),
                    "payload": e.payload,
                }
                for e in events
            ],
        }

        written: list[str] = []
        for suffix, content in (
            (".json", json.dumps(payload, indent=2, default=str)),
            (".md", render_markdown(str(engagement_id), events)),
        ):
            path = self._dir / (stem + suffix)
            try:
                path.write_text(content, encoding="utf-8")
                written.append(str(path))
            except OSError as exc:
                log.error("failed writing %s: %s", path, exc)
        return written
