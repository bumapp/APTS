"""Working agent service — composition root.

One image, six containers. ``AGENT_NAME`` selects which stage this instance is
(``recon``, ``vuln``, ``mitre``, ``exploit``, ``script``, ``adviser``).

Layering — each layer calls only the one below it::

    controllers/   HTTP surface: routing, auth, status codes
    providers/     orchestration: composes one stage run
    services/      units of work: the stage workers, progress, handoff, renderers
    repositories/  persistence: agent_results, agent_trace, report + flow files

Two notes on where things sit, both of which have caught someone out:

* **Audit writes are not in ``repositories/``.** They go through
  :class:`shared.audit.AuditLog`, because mcp-tools needs the identical thing
  and the ``INSERT`` has always lived in ``shared/db.py``. A per-package copy
  bought a class name, not an encapsulation boundary.

* **``repositories/`` is persistence, not "the database".** ``report_repository``
  and ``flow_repository`` write files. The medium is not the point; the point is
  that a worker should no more know a filesystem path than it knows SQL.

The renderers are pure — model in, string out — but they live in ``services/``
rather than a ``utils/`` package. mcp-tools reserves ``utils/`` for small
primitives (URL parsing, sanitisation); a 300-line document renderer is a unit
of work that happens to have no I/O, not a helper.

Only this module decides which concrete worker a given agent gets. Every LLM-backed
worker drives its own LangChain model (``shared.llm.build_chat_model``) + the
native MCP tools on LangGraph, and traces to Langfuse when configured; the model
backend is a URL/key the worker resolves, not something wired here.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI

from shared import logging_config
from shared.audit import AuditLog
from shared.auth import load_own_token
from shared.tls import client_ssl_context, uvicorn_ssl_kwargs

from agent.config import (
    AGENT_NAME,
    COMPONENT,
    HTTP_CONNECT_TIMEOUT_SECONDS,
    HTTP_TIMEOUT_SECONDS,
    LISTEN_HOST,
    LISTEN_PORT,
    ORCHESTRATOR_URL,
    stub_failure_rate,
)
from agent.controllers import run_controller
from agent.providers.run_provider import RunProvider
from agent.repositories.agent_result_repository import AgentResultRepository
from agent.repositories.flow_repository import FlowRepository
from agent.repositories.report_repository import ReportRepository
from agent.repositories.trace_repository import TraceRepository
from agent.services.orchestrator_service import HandoffService, OrchestratorService
from agent.services.workers.adviser import AdviserWorker
from agent.services.workers.base import Worker
from agent.services.workers.exploit import ExploitWorker
from agent.services.workers.mitre import MitreWorker
from agent.services.workers.recon import ReconWorker
from agent.services.workers.script import ScriptWorker
from agent.services.workers.vuln import VulnWorker

logging_config.configure(COMPONENT)
log = logging.getLogger(COMPONENT)

# Stages backed by a real model. Together with TOOL_BACKED this must cover every
# stage in ``shared.pipeline.CHAIN``; :func:`build_worker` raises if it does not.
# There is no longer a canned-stub fallback — all six stages are implemented, and
# a silent stub standing in for a missing worker would report a stage as "done"
# having produced a fabricated artifact.
LLM_BACKED = {"vuln", "mitre", "exploit", "script", "adviser"}

# Stages that do real work through MCP tools but need no model to decide "what
# exists". Recon belongs here on purpose: "what URLs exist" is a question a
# crawler answers exactly and a model answers approximately, and an invented
# endpoint would propagate through every stage downstream. (Recon still runs a
# small model pass to *triage* what the crawler found — rank, never invent.)
TOOL_BACKED = {"recon"}


def build_worker(results: AgentResultRepository) -> Worker:
    """Pick this agent's worker.

    Every worker drives the agentic loop itself — a LangGraph ``create_react_agent``
    over a ``shared.llm`` chat model and the native MCP tools — so there is no
    long-lived client for this composition root to open or close. The exploit,
    script, and adviser workers take the result store because they read an earlier
    stage's artifact back.
    """
    if AGENT_NAME in TOOL_BACKED:
        if AGENT_NAME == "recon":
            return ReconWorker()
        raise RuntimeError(f"{AGENT_NAME!r} is marked tool-backed but has no worker")

    if AGENT_NAME not in LLM_BACKED:
        raise RuntimeError(
            f"{AGENT_NAME!r} is in the pipeline but is neither tool-backed nor "
            f"LLM-backed; it has no worker")

    if AGENT_NAME == "vuln":
        return VulnWorker()
    if AGENT_NAME == "mitre":
        return MitreWorker()
    if AGENT_NAME == "exploit":
        # Also reads the register from the store — MITRE sits between this
        # stage and the artifact it needs.
        return ExploitWorker(results)
    if AGENT_NAME == "script":
        return ScriptWorker(results)
    if AGENT_NAME == "adviser":
        # Reads every stage's artifact and writes the deliverable to disk.
        return AdviserWorker(results, ReportRepository())
    raise RuntimeError(f"{AGENT_NAME!r} is marked LLM-backed but has no worker")


@asynccontextmanager
async def lifespan(app: FastAPI):
    token = load_own_token()
    client = httpx.AsyncClient(
        verify=client_ssl_context(),
        timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_CONNECT_TIMEOUT_SECONDS),
    )
    audit = AuditLog(COMPONENT)

    results = AgentResultRepository()
    worker = build_worker(results)

    # Recon is the only stage that captures observed requests, so it is the only
    # one given an indexer that projects them into the queryable recon_requests
    # table. Every other provider gets None and stays generic.
    recon_index = None
    if AGENT_NAME == "recon":
        from agent.repositories.recon_request_repository import ReconRequestRepository
        recon_index = ReconRequestRepository()

    app.state.run_provider = RunProvider(
        agent=AGENT_NAME,
        worker=worker,
        orchestrator=OrchestratorService(client, token, AGENT_NAME, ORCHESTRATOR_URL),
        handoff=HandoffService(client, token, AGENT_NAME),
        results=results,
        audit=audit,
        # Only the terminal stage reads the trace back and writes the flow file,
        # but every agent is wired the same way — which stage is terminal is
        # shared.pipeline's decision, not this composition root's.
        traces=TraceRepository(),
        flows=FlowRepository(),
        recon_index=recon_index,
        failure_rate=stub_failure_rate(),
    )

    log.info("agent %s ready (worker=%s)", AGENT_NAME, type(worker).__name__)
    audit.record("startup")
    try:
        yield
    finally:
        await client.aclose()
        audit.record("shutdown")


def create_app() -> FastAPI:
    application = FastAPI(title=f"APTS Agent — {AGENT_NAME}", lifespan=lifespan)
    application.include_router(run_controller.router)
    return application


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "agent.main:app",
        host=LISTEN_HOST, port=LISTEN_PORT,
        log_config=None,
        **uvicorn_ssl_kwargs(),
    )
