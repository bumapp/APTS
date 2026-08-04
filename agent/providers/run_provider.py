"""Runs one pipeline stage end to end.

The order here is the stage contract:

1. report ``started``
2. produce the artifact (the worker)
3. persist it to ``agent_results``
4. hand off to the next stage
5. report ``done``

Persist before handing off, always. The orchestrator's retry path reloads the
*previous* stage's stored output when it relaunches an agent, so an artifact
that was pushed downstream but never written is invisible to a retry — the
chain would restart from a result nobody can find.

Any failure is reported as ``failed`` and swallowed rather than raised. This
runs as a background task with no caller left to catch it, and the orchestrator
decides what a failure means: three retries, then stop for a critical agent,
continue for a minor one (§2.2.4). An exception escaping here would just be an
unhandled task error with none of that logic applied.
"""
from __future__ import annotations

import logging

from shared.models import ChainHandoff
from shared.pipeline import next_agent

from agent.repositories.agent_result_repository import (
    AgentResultRepository,
    AuditRepository,
)
from agent.services.orchestrator_service import HandoffService, OrchestratorService
from agent.services.workers.base import WorkContext, Worker

log = logging.getLogger("agent.providers.run")


class RunProvider:
    """Composes worker, repository, and outbound services into one stage run."""

    def __init__(self, agent: str, worker: Worker,
                 orchestrator: OrchestratorService, handoff: HandoffService,
                 results: AgentResultRepository, audit: AuditRepository,
                 failure_rate: float = 0.0) -> None:
        self._agent = agent
        self._component = f"agent-{agent}"
        self._worker = worker
        self._orchestrator = orchestrator
        self._handoff = handoff
        self._results = results
        self._audit = audit
        self._failure_rate = failure_rate

    async def run(self, handoff: ChainHandoff) -> None:
        engagement_id = handoff.engagement_id
        try:
            await self._orchestrator.report(engagement_id, "started", "beginning work")

            from agent.services.workers.stub_worker import maybe_fail
            await maybe_fail(self._failure_rate)

            result = await self._worker(WorkContext(
                engagement_id=engagement_id,
                target_url=handoff.target_url,
                scope=handoff.scope,
                upstream=handoff.results,
            ))

            self._results.save(engagement_id, self._agent, result)
            self._audit.record(self._component, "result_written",
                               engagement_id=str(engagement_id))

            successor = next_agent(self._agent)
            if successor is not None:
                await self._handoff.push(
                    successor, engagement_id, handoff.target_url,
                    handoff.scope, handoff.time_window, result)
                self._audit.record(self._component, "pushed_to_next",
                                   engagement_id=str(engagement_id),
                                   detail={"next": successor})

            await self._orchestrator.report(engagement_id, "done", "work complete",
                                            detail={"has_result": True})
        except Exception as exc:
            log.exception("stage failed: %s", exc)
            await self._orchestrator.report(engagement_id, "failed", str(exc))
