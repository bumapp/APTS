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

Tracing wraps the whole run. :func:`shared.trace.stage` binds this engagement
and agent for the duration, which is what lets the model calls inside the worker
and the tool calls inside ``McpService`` record themselves without either of
them being told which run they are serving. The stage's own input and output are
recorded here, at the only layer that sees both.

The terminal stage additionally writes the flow file. It happens here rather
than in the Adviser worker because the Adviser's own ``stage_output`` is not
recorded until its worker has returned — a flow file written from inside the
worker would be missing the stage that wrote it.
"""
from __future__ import annotations

import json
import logging
import time
import traceback

from shared import trace
from shared.audit import AuditSink
from shared.models import ChainHandoff
from shared.pipeline import is_terminal, next_agent

from agent.repositories.agent_result_repository import AgentResultRepository
from agent.repositories.flow_repository import FlowRepository
from agent.repositories.trace_repository import TraceRepository
from agent.services.fault_injection import maybe_fail
from agent.services.orchestrator_service import HandoffService, OrchestratorService
from agent.services.workers.base import WorkContext, Worker

log = logging.getLogger("agent.providers.run")


def _summarise(artifact: dict) -> str:
    """A short, human line about what a stage produced.

    Generic on purpose: it counts whatever list-valued keys the artifact has, so
    a new stage with a new artifact shape shows something useful in the flow
    file's timeline without this function learning about it.
    """
    # Not singularised. The artifact keys are the schema's own plural nouns
    # ("weaknesses", "endpoints"), and stripping a trailing "s" turns
    # "weaknesses" into "weaknesse" — a wrong word reads worse than "1
    # weaknesses" does.
    parts = [f"{len(v)} {k}" for k, v in artifact.items()
             if isinstance(v, (list, dict)) and v]
    return ", ".join(parts[:5]) or "empty artifact"


class RunProvider:
    """Composes worker, repository, and outbound services into one stage run."""

    def __init__(self, agent: str, worker: Worker,
                 orchestrator: OrchestratorService, handoff: HandoffService,
                 results: AgentResultRepository, audit: AuditSink,
                 traces: TraceRepository | None = None,
                 flows: FlowRepository | None = None,
                 failure_rate: float = 0.0) -> None:
        self._agent = agent
        self._component = f"agent-{agent}"
        self._worker = worker
        self._orchestrator = orchestrator
        self._handoff = handoff
        self._results = results
        self._audit = audit
        self._traces = traces
        self._flows = flows
        self._failure_rate = failure_rate

    async def run(self, handoff: ChainHandoff) -> None:
        with trace.stage(handoff.engagement_id, self._agent):
            await self._run(handoff)

    # ----------------------------------------------------------------- #

    async def _run(self, handoff: ChainHandoff) -> None:
        engagement_id = handoff.engagement_id
        started = time.perf_counter()
        try:
            await self._orchestrator.report(engagement_id, "started", "beginning work")
            self._trace_input(handoff)

            await maybe_fail(self._failure_rate)

            result = await self._worker(WorkContext(
                engagement_id=engagement_id,
                target_url=handoff.target_url,
                scope=handoff.scope,
                upstream=handoff.results,
            ))

            self._results.save(engagement_id, self._agent, result)
            self._audit.record("result_written",
                               engagement_id=str(engagement_id))
            trace.record("stage_output",
                         {"artifact": result, "summary": _summarise(result)},
                         duration_ms=int((time.perf_counter() - started) * 1000))

            successor = next_agent(self._agent)
            if successor is not None:
                await self._handoff.push(
                    successor, engagement_id, handoff.target_url,
                    handoff.scope, handoff.time_window, result)
                self._audit.record("pushed_to_next",
                                   engagement_id=str(engagement_id),
                                   detail={"next": successor})
                trace.record("handoff", {"next_agent": successor})

            # Last stage: the trace is now complete, so turn it into a file.
            # Before reporting ``done``, because that status is what marks the
            # engagement complete — an operator reading "complete" should find
            # the flow file already on disk.
            if is_terminal(self._agent):
                self._write_flow(engagement_id)

            await self._orchestrator.report(engagement_id, "done", "work complete",
                                            detail={"has_result": True})
        except Exception as exc:
            log.exception("stage failed: %s", exc)
            trace.record(
                "stage_failed",
                {"error": str(exc), "type": type(exc).__name__,
                 "traceback": traceback.format_exc()},
                duration_ms=int((time.perf_counter() - started) * 1000))
            await self._orchestrator.report(engagement_id, "failed", str(exc))

    def _trace_input(self, handoff: ChainHandoff) -> None:
        """Record what this stage was handed.

        The upstream artifact is also the previous stage's ``stage_output``, but
        recording it again on receipt is not redundant: a retry re-reads it from
        the store, and the orchestrator may hand a stage something different
        from what its predecessor pushed. When those two rows disagree, the
        disagreement is the bug.
        """
        upstream = handoff.results or {}
        trace.record("stage_input", {
            "from_component": handoff.from_component,
            "target_url": handoff.target_url,
            "scope": handoff.scope.model_dump(mode="json"),
            "upstream": upstream,
            "upstream_keys": sorted(upstream),
            "upstream_bytes": len(json.dumps(upstream, default=str)),
        })

    def _write_flow(self, engagement_id) -> None:
        """Assemble the flow file. Never allowed to fail the engagement.

        Reached only after every stage has already succeeded, so an error here
        must not turn a finished run into a failed one — it would be reported as
        an Adviser failure and retried, re-running the report generation to fix
        an observability write.
        """
        if self._traces is None or self._flows is None:
            return
        try:
            events = self._traces.load(engagement_id)
            paths = self._flows.save(engagement_id, events)
            log.info("flow file: %d events → %s", len(events), ", ".join(paths))
            self._audit.record("flow_written",
                               engagement_id=str(engagement_id),
                               detail={"paths": paths, "events": len(events)})
        except Exception as exc:
            log.error("could not write flow file: %s", exc)
