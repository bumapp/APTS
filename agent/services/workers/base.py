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

from shared.llm import LlmClient, LlmError
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


async def ask_for(llm: LlmClient, system: str, user: str, *, key: str,
                  expect: type = list, what: str = "model call") -> Any:
    """Ask the model for a JSON object and return ``raw[key]``, or fail the stage.

    Four workers had this same eleven lines: call the model, convert an
    :class:`LlmError` into a :class:`WorkFailed` so the orchestrator retries
    rather than crashes, then check that the one key the stage needs is present
    and of the right type. Only the key name, the expected type, and the wording
    of the error differed.

    ``expect`` is the type the *collection* must be — ``list`` for candidates,
    attempts and scripts, ``dict`` for MITRE's id-keyed mappings. Checking it
    here is what stops a stage from iterating a string one character at a time
    because the model answered with prose.

    The missing-key message names the keys that *were* returned. When a prompt
    drifts and the model starts answering under a different key, that list is
    the whole diagnosis.

    Not used by the Adviser, deliberately: it degrades to a report without
    narrative rather than failing, because the findings are the deliverable and
    prose is not. Forcing that stage through a helper that raises would be
    wrong, so it keeps its own handler.
    """
    try:
        raw = await llm.complete_json(system, user)
    except LlmError as exc:
        raise WorkFailed(f"{what} failed: {exc}") from exc

    value = raw.get(key)
    if not isinstance(value, expect):
        noun = "object" if expect is dict else "list"
        raise WorkFailed(
            f"model returned no {key!r} {noun} (got keys: {sorted(raw)})")
    return value
