"""What every agent's work unit looks like.

A worker turns the previous stage's output into this stage's artifact. It does
not post progress, write to the database, or hand off — those belong to the
provider that composes it. A worker that finds itself running can assume it was
supposed to run.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from shared.models import Scope


@dataclass(frozen=True)
class WorkContext:
    """Everything a worker is allowed to know about the engagement."""
    engagement_id: UUID
    target_url: str
    scope: Scope
    upstream: dict[str, Any]
    """The previous stage's artifact. Empty for Recon, the first stage."""


class Worker(Protocol):
    """Produces one stage's artifact."""

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        ...


class WorkFailed(Exception):
    """Raised when a stage cannot produce a valid artifact.

    Routed into the orchestrator's ordinary retry path (§2.2.4) rather than
    treated as a crash: a model that emits a malformed artifact has failed its
    task in the same sense as one that times out, and three-attempts-then-stop
    already handles that correctly.
    """
