"""The contract every tool implementation satisfies.

A tool receives validated arguments and a context describing who is calling, on
whose behalf, and inside what boundary. It does not decide whether it is
allowed to run — authorisation and scope for the *requested* target are settled
by the provider before a handler is reached, so a handler that finds itself
executing can assume that call was permitted.

Why the context carries the scope. A single-shot tool touches exactly the URL
it was handed, and the checkpoint already vetted it. A *fanning-out* tool — a
crawler following links, a scanner pivoting to a discovered host — issues
requests the checkpoint never saw, because they did not exist when the call was
authorised. Those would otherwise leave the deployment unchecked, which is
exactly the out-of-scope traffic the guardrail exists to prevent. Handing the
scope down lets a fan-out tool re-check every URL it derives, and any tool that
follows a link it was not explicitly given **must** do so.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable
from uuid import UUID

from shared.models import Scope


@dataclass(frozen=True)
class ToolContext:
    """Who is calling, on whose behalf, and within what boundary."""
    engagement_id: UUID
    caller: str
    scope: Scope
    """The engagement's approved boundary, already loaded by the provider.

    Present so fan-out tools can enforce it on URLs they discover. Frozen, so a
    tool cannot widen its own boundary mid-run.
    """


@runtime_checkable
class ToolHandler(Protocol):
    """Callable interface for a tool implementation.

    Async across the board, including for tools that do no I/O today. A uniform
    signature means the registry needs no special cases, and stubs that return
    canned data become genuinely async — subprocesses, HTTP requests — without a
    signature change rippling outward.
    """

    async def __call__(self, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
        ...
