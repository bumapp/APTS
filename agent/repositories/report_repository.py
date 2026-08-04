"""Writes the finished report to disk.

A repository because it is persistence, even though the medium is a filesystem
rather than Postgres — the Adviser should no more know about file paths than
the vuln worker knows about SQL.

Two formats, per §5.8: JSON for machines, Markdown for people. Filenames carry
the engagement ID so concurrent engagements cannot overwrite each other.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from shared.models import EngagementReport

from agent.services.report_renderer import render_markdown

log = logging.getLogger("agent.repositories.report")

REPORT_DIR = os.environ.get("APTS_REPORT_DIR", "/var/apts/reports")


class ReportRepository:
    """Persists an engagement report as JSON and Markdown."""

    def __init__(self, directory: str = REPORT_DIR) -> None:
        self._dir = Path(directory)

    def save(self, report: EngagementReport) -> list[str]:
        """Write both formats and return the paths written.

        A failure to write is logged, not raised: the report also travels back
        through the pipeline as the Adviser's artifact and is safe in the
        database, so an unwritable directory should not fail the engagement
        after every stage has already succeeded.
        """
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.error("cannot create report directory %s: %s", self._dir, exc)
            return []

        stem = f"report-{report.engagement_id}"
        written: list[str] = []
        for suffix, content in (
            (".json", json.dumps(report.model_dump(mode="json"), indent=2, default=str)),
            (".md", render_markdown(report)),
        ):
            path = self._dir / (stem + suffix)
            try:
                path.write_text(content, encoding="utf-8")
                written.append(str(path))
            except OSError as exc:
                log.error("failed writing %s: %s", path, exc)
        return written
