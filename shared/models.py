"""Message envelopes exchanged between components.

Every request between APTS components carries a JSON body matching one of these
models. Keeping them in one shared module means the orchestrator, every agent,
and the MCP tools container all agree on the wire format.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# The engagement itself
# --------------------------------------------------------------------------- #

class Scope(BaseModel):
    """The boundary the system is allowed to operate in (per Characterization §2.2.8)."""
    domains: list[str] = Field(default_factory=list, description="e.g. ['*.example.com']")
    allow_paths: list[str] = Field(default_factory=list, description="e.g. ['/app/']")
    deny_paths: list[str] = Field(default_factory=list, description="e.g. ['/admin/']")


class TimeWindow(BaseModel):
    starts_at: datetime | None = None
    ends_at: datetime | None = None


class EngagementSpec(BaseModel):
    """What the operator submits via the CLI to kick off a run."""
    target_url: str
    scope: Scope
    time_window: TimeWindow | None = None


# --------------------------------------------------------------------------- #
# Chain handoff — Agent → Agent (and Orchestrator → Recon for the first hop)
# --------------------------------------------------------------------------- #

class ChainHandoff(BaseModel):
    """The payload one agent pushes to the next.

    For the Orchestrator → Recon kickoff, `results` is empty and only
    `engagement_id`, `target_url`, and `scope` matter.
    """
    engagement_id: UUID
    from_component: str            # 'orchestrator' or 'agent-<name>'
    target_url: str
    scope: Scope
    time_window: TimeWindow | None = None
    results: dict[str, Any] = Field(default_factory=dict,
        description="The producing agent's result payload. Empty for the initial kickoff.")


class HandoffAck(BaseModel):
    """Immediate acknowledgment the receiving agent returns."""
    engagement_id: UUID
    accepted_by: str
    started_at: datetime


# --------------------------------------------------------------------------- #
# Progress updates — Agent → Orchestrator
# --------------------------------------------------------------------------- #

ProgressStatus = Literal["started", "in_progress", "done", "failed"]


class ProgressUpdate(BaseModel):
    engagement_id: UUID
    agent: str                     # 'recon', 'vuln', 'mitre', 'exploit', 'script', 'adviser'
    status: ProgressStatus
    message: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    at: datetime = Field(default_factory=datetime.utcnow)


class ProgressAck(BaseModel):
    received: bool = True


# --------------------------------------------------------------------------- #
# MCP tool call — Agent → MCP tools container
# --------------------------------------------------------------------------- #

class ToolCall(BaseModel):
    engagement_id: UUID
    tool: str                      # 'scanner', 'http', 'cve', 'attack_kb', 'sandbox', 'report'
    args: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    tool: str
    ok: bool
    output: dict[str, Any] = Field(default_factory=dict)
    blocked_by_guardrails: bool = False
    reason: str | None = None


# --------------------------------------------------------------------------- #
# Sandbox exec — MCP tools → sandbox container
# --------------------------------------------------------------------------- #

class SandboxExecRequest(BaseModel):
    engagement_id: UUID
    command: str                   # single command string (skeleton: no real execution)


class SandboxExecResult(BaseModel):
    ok: bool
    exit_code: int
    stdout: str
    stderr: str


# --------------------------------------------------------------------------- #
# Operator CLI → Orchestrator admin API
# --------------------------------------------------------------------------- #

class StartEngagementResponse(BaseModel):
    engagement_id: UUID
    status: str


class EngagementStatus(BaseModel):
    engagement_id: UUID
    target_url: str
    status: str
    per_agent: dict[str, dict[str, Any]] = Field(default_factory=dict,
        description="Keyed by agent name; each value has status + retry_count + last_error.")
    started_at: datetime | None = None
    completed_at: datetime | None = None
