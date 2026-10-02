"""Outbound calls to the orchestrator and to the next agent.

Progress reporting is best-effort on purpose. If the orchestrator cannot be
reached, the agent logs and carries on rather than failing the stage: losing a
status update is a visibility problem, but abandoning completed work because a
status POST timed out turns it into a correctness problem. The orchestrator's
own stall detection is what should catch a genuinely silent agent.

Handoff is the opposite — it is *not* best-effort. If the next stage cannot be
reached the chain has stopped, and the caller must hear about it.
"""
from __future__ import annotations

import logging
from uuid import UUID

import httpx

from shared.auth import bearer_headers
from shared.models import ChainHandoff, ProgressUpdate, Scope, TimeWindow

log = logging.getLogger("agent.services.orchestrator")


class OrchestratorService:
    """Talks to the orchestrator's progress endpoint."""

    def __init__(self, client: httpx.AsyncClient, token: str, agent: str,
                 base_url: str) -> None:
        self._client = client
        self._token = token
        self._agent = agent
        self._base_url = base_url.rstrip("/")

    async def report(self, engagement_id: UUID, status: str, message: str = "",
                     detail: dict | None = None) -> None:
        update = ProgressUpdate(engagement_id=engagement_id, agent=self._agent,
                                status=status, message=message, detail=detail or {})
        try:
            response = await self._client.post(
                f"{self._base_url}/progress",
                content=update.model_dump_json(),
                headers=bearer_headers(self._token),
            )
            response.raise_for_status()
        except Exception as exc:
            log.error("progress post failed (%s): %s", status, exc)


class HandoffService:
    """Pushes this stage's artifact to the next agent in the chain."""

    def __init__(self, client: httpx.AsyncClient, token: str, agent: str) -> None:
        self._client = client
        self._token = token
        self._agent = agent

    async def push(self, next_agent: str, engagement_id: UUID, target_url: str,
                   scope: Scope, time_window: TimeWindow | None,
                   result: dict) -> None:
        handoff = ChainHandoff(
            engagement_id=engagement_id,
            from_component=f"agent-{self._agent}",
            target_url=target_url,
            scope=scope,
            time_window=time_window,
            results=result,
        )
        response = await self._client.post(
            f"https://agent-{next_agent}:8443/run",
            content=handoff.model_dump_json(),
            headers=bearer_headers(self._token),
        )
        response.raise_for_status()
        log.info("pushed result to %s", next_agent)
