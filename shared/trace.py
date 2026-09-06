"""Execution trace: the whole flow from request to report, recorded.

``agent_results`` stores each stage's *conclusion* and ``audit_log`` stores the
security decisions, but neither answers the question you actually have when a
report says something surprising: what was this stage given, what did it ask the
model, what did the model say, and what did it fetch to check? This module
records that, one row per event in ``agent_trace``.

Ambient context rather than an injected recorder
------------------------------------------------
:class:`~shared.llm.LlmClient` and ``McpService`` are built once at startup and
outlive any single engagement, so they cannot be constructed knowing which run
they are serving. Threading an engagement ID down through every worker method
that might make a model call would touch every signature in ``workers/`` to
deliver something none of them use.

Instead :func:`stage` binds the current engagement and agent to a
:class:`~contextvars.ContextVar`, and :func:`record` reads it. ``ContextVar``
is the right primitive here and not a global: ``BackgroundTasks`` runs each
stage as an asyncio task, a task copies the context at creation, and concurrent
runs in the same process therefore cannot see each other's binding.

:func:`record` is a no-op outside a stage, which is what makes this safe to call
from shared code. A unit test exercising ``LlmClient`` with no database
configured records nothing and raises nothing.

Truncation
----------
Everything written passes through :func:`cap`. Prompts are large, crawled
response bodies are larger, and an uncapped trace would be dominated by one
stage's HTML. Caps are per-field and the marker stays inside the value, so a
truncated field is still self-describing when read back — a payload that looks
short is short, not silently clipped.

Writes are non-fatal, following ``shared.db.audit``. Losing an observability
row must never fail a stage that did its work.
"""
from __future__ import annotations

import contextlib
import logging
import os
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from itertools import count
from typing import Any, Iterator
from uuid import UUID

import psycopg

from shared.db import get_conn, strip_nul

log = logging.getLogger("shared.trace")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

#: Longest string kept in any single field. 8 KB holds a full system prompt and
#: a realistic model reply; response bodies get clipped, which is the intent.
MAX_FIELD_CHARS = int(os.environ.get("APTS_TRACE_MAX_FIELD_CHARS", "8000"))

#: Longest list kept. Recon's endpoint list can run to hundreds of entries and
#: the stage's own artifact in ``agent_results`` already holds all of them.
MAX_ITEMS = int(os.environ.get("APTS_TRACE_MAX_ITEMS", "200"))

#: Deepest nesting walked before a subtree is summarised rather than copied.
MAX_DEPTH = int(os.environ.get("APTS_TRACE_MAX_DEPTH", "6"))

#: Set ``APTS_TRACE_ENABLED=0`` to record nothing at all. Present for an
#: operator who wants no prompt text at rest; the flow file is then empty
#: rather than absent, which says "tracing off" instead of "nothing happened".
ENABLED = os.environ.get("APTS_TRACE_ENABLED", "1").lower() not in ("0", "false", "no")


# --------------------------------------------------------------------------- #
# Truncation
# --------------------------------------------------------------------------- #

def cap(value: Any, depth: int = 0) -> Any:
    """Bound ``value`` to something a trace row can hold.

    Strings are clipped with a marker that states the original length, lists
    are clipped with a marker element, and anything past :data:`MAX_DEPTH` is
    replaced by a one-line description of its type and size. Keys are never
    dropped — a missing key reads as "the stage did not set it", which would be
    a lie.
    """
    if isinstance(value, str):
        if len(value) <= MAX_FIELD_CHARS:
            return value
        return (f"{value[:MAX_FIELD_CHARS]}"
                f"… [truncated, {len(value)} chars total]")

    if isinstance(value, (int, float, bool)) or value is None:
        return value

    if isinstance(value, (UUID, datetime)):
        return str(value)

    if depth >= MAX_DEPTH:
        return f"[depth limit: {type(value).__name__}]"

    if isinstance(value, dict):
        return {str(k): cap(v, depth + 1) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        items = [cap(v, depth + 1) for v in list(value)[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append(f"… [truncated, {len(value)} items total]")
        return items

    return cap(str(value), depth)


# --------------------------------------------------------------------------- #
# Ambient stage context
# --------------------------------------------------------------------------- #

@dataclass
class _Stage:
    engagement_id: str
    agent: str
    counter: Iterator[int]


_CURRENT: ContextVar[_Stage | None] = ContextVar("apts_trace_stage", default=None)


@contextlib.contextmanager
def stage(engagement_id: UUID | str, agent: str) -> Iterator[None]:
    """Bind the current engagement and agent for the duration of a stage run.

    Every :func:`record` call inside the block — including ones made deep in
    ``LlmClient`` or ``McpService`` — is attributed to this stage and numbered
    in call order. The token is reset on exit so a worker cannot leak its
    attribution into whatever runs next on the same task.
    """
    token = _CURRENT.set(_Stage(str(engagement_id), agent, count(1)))
    try:
        yield
    finally:
        _CURRENT.reset(token)


def current_agent() -> str | None:
    """The stage currently bound, if any. For log lines and tests."""
    active = _CURRENT.get()
    return active.agent if active else None


# --------------------------------------------------------------------------- #
# Recording
# --------------------------------------------------------------------------- #

def record(event_type: str, payload: dict[str, Any] | None = None,
           duration_ms: int | None = None) -> None:
    """Record one event against the stage bound by :func:`stage`.

    A no-op outside a stage. That is deliberate rather than an error: shared
    code calls this unconditionally, and code paths that legitimately run
    outside an engagement (a health probe, a unit test) should record nothing
    rather than raise or invent an engagement ID.
    """
    active = _CURRENT.get()
    if active is None:
        log.debug("trace %r dropped: no stage bound", event_type)
        return
    record_for(active.engagement_id, active.agent, event_type,
               payload, duration_ms, seq=next(active.counter))


def record_for(engagement_id: UUID | str, agent: str, event_type: str,
               payload: dict[str, Any] | None = None,
               duration_ms: int | None = None, seq: int = 0) -> None:
    """Record an event for an explicitly named engagement and agent.

    The orchestrator's path — it records the request itself, retries, and
    completion, none of which happen inside a stage run. ``seq`` stays 0 for
    those; the flow file orders by the table's serial ID, not by ``seq``.
    """
    if not ENABLED:
        return
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO agent_trace
                       (engagement_id, agent, seq, event_type, payload, duration_ms)
                   VALUES (%s, %s, %s, %s, %s::jsonb, %s)""",
                (str(engagement_id), agent, seq, event_type,
                 psycopg.types.json.Json(strip_nul(cap(payload or {}))), duration_ms),
            )
    except Exception as exc:                                     # pragma: no cover
        # Same rule as shared.db.audit: a stage that did its work must not fail
        # because the record of it could not be written.
        log.error("trace write failed (%s/%s): %s", agent, event_type, exc)
