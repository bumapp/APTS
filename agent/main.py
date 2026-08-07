"""Working agent service — composition root.

One image, six containers. ``AGENT_NAME`` selects which stage this instance is
(``recon``, ``vuln``, ``mitre``, ``exploit``, ``script``, ``adviser``).

Layering — each layer calls only the one below it::

    controllers/   HTTP surface: routing, auth, status codes
    providers/     orchestration: composes one stage run
    services/      units of work: the stage worker, progress, handoff
    repositories/  database: agent_results and audit_log writes

Only this module decides which concrete worker a given agent gets, and it is
the one place that knows an LLM exists. Swapping a stub for a real model is a
line in :func:`build_worker`.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI

from shared import logging_config
from shared.auth import load_own_token
from shared.llm import LlmClient
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
from agent.repositories.agent_result_repository import (
    AgentResultRepository,
    AuditRepository,
)
from agent.repositories.flow_repository import FlowRepository
from agent.repositories.trace_repository import TraceRepository
from agent.services.mcp_service import McpService
from agent.services.orchestrator_service import HandoffService, OrchestratorService
from agent.services.workers.base import Worker
from agent.services.workers.mitre_worker import MitreWorker
from agent.repositories.report_repository import ReportRepository
from agent.services.workers.adviser_worker import AdviserWorker
from agent.services.workers.exploit_worker import ExploitWorker
from agent.services.workers.recon_worker import ReconWorker
from agent.services.workers.script_worker import ScriptWorker
from agent.services.workers.vuln_worker import VulnWorker
from agent.services.workers.stub_worker import StubWorker

logging_config.configure(COMPONENT)
log = logging.getLogger(COMPONENT)

# Stages backed by a real model. Everything absent from this set and from
# TOOL_BACKED still runs the canned StubWorker, so the pipeline stays runnable
# while stages are migrated one at a time.
LLM_BACKED = {"vuln", "mitre", "exploit", "script", "adviser"}

# Stages that do real work through MCP tools but need no model. Recon belongs
# here on purpose: "what URLs exist" is a question a crawler answers exactly and
# a model answers approximately, and an invented endpoint would propagate
# through every stage downstream.
TOOL_BACKED = {"recon"}


def build_worker(mcp: McpService, results: AgentResultRepository,
                 exit_stack: list) -> Worker:
    """Pick this agent's worker, opening an LLM client only if it needs one.

    Appends any async context manager it opens to ``exit_stack`` so lifespan can
    close it — an agent with no model must not hold an idle client, and an agent
    with one must not leak it.
    """
    if AGENT_NAME in TOOL_BACKED:
        if AGENT_NAME == "recon":
            return ReconWorker(mcp)
        raise RuntimeError(f"{AGENT_NAME!r} is marked tool-backed but has no worker")

    if AGENT_NAME not in LLM_BACKED:
        return StubWorker(AGENT_NAME)

    llm = LlmClient(AGENT_NAME)
    exit_stack.append(llm)
    if AGENT_NAME == "mitre":
        return MitreWorker(llm)
    if AGENT_NAME == "vuln":
        # The only worker needing both: a model to judge, and tools to verify.
        return VulnWorker(llm, mcp)
    if AGENT_NAME == "exploit":
        # Also reads the register from the store — MITRE sits between this
        # stage and the artifact it needs.
        return ExploitWorker(llm, mcp, results)
    if AGENT_NAME == "script":
        return ScriptWorker(llm, results)
    if AGENT_NAME == "adviser":
        # Reads every stage's artifact and writes the deliverable to disk.
        return AdviserWorker(llm, results, ReportRepository())
    raise RuntimeError(f"{AGENT_NAME!r} is marked LLM-backed but has no worker")


@asynccontextmanager
async def lifespan(app: FastAPI):
    token = load_own_token()
    client = httpx.AsyncClient(
        verify=client_ssl_context(),
        timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_CONNECT_TIMEOUT_SECONDS),
    )
    audit = AuditRepository()

    mcp = McpService(client, token)
    results = AgentResultRepository()
    opened: list = []
    worker = build_worker(mcp, results, opened)
    for resource in opened:
        await resource.__aenter__()

    app.state.http_client = client
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
        failure_rate=stub_failure_rate(),
    )

    log.info("agent %s ready (worker=%s)", AGENT_NAME, type(worker).__name__)
    audit.record(COMPONENT, "startup")
    try:
        yield
    finally:
        for resource in reversed(opened):
            await resource.__aexit__(None, None, None)
        await client.aclose()
        audit.record(COMPONENT, "shutdown")


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
