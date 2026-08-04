"""The contract every tool implementation satisfies.

A tool receives validated arguments and a context describing who is calling and
on whose behalf, and returns a JSON-serialisable payload.  It does not decide
whether it is allowed to run — authorisation and scope are settled by the
service layer before a handler is ever reached, so a handler that finds itself
executing can assume the call was permitted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from uuid import UUID


@dataclass(frozen=True)
class ToolContext:
    """Who is calling, and as part of which engagement."""
    engagement_id: UUID
    caller: str


@runtime_checkable
class ToolHandler(Protocol):
    """Callable interface for a tool implementation.

    Async across the board, including for tools that do no I/O today.  A
    uniform signature means the registry needs no special cases, and the stubs
    that currently return canned data will become genuinely async — nuclei
    subprocesses, NVD requests — without a signature change rippling outward.
    """

    async def __call__(self, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
        ...
