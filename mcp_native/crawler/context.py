"""The crawler's call context (ported from the retired ``mcp_tools`` facade).

Only what the crawler needs: who is calling and the engagement boundary it must
enforce on every URL it derives. Frozen so a crawl cannot widen its own scope
mid-run.
"""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from shared.models import Scope


@dataclass(frozen=True)
class ToolContext:
    engagement_id: UUID
    caller: str
    scope: Scope
