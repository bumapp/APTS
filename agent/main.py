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

Only this module decides which concrete worker a given agent gets, and it is the
one place that knows an LLM exists.
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

import httpx
import uvicorn
from fastapi import FastAPI

from shared import logging_config
from shared.audit import AuditLog
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
from agent.repositories.agent_result_repository import AgentResultRepository
from agent.repositories.flow_repository import FlowRepository
from agent.repositories.trace_repository import TraceRepository
from agent.services.orchestrator_service import HandoffService, OrchestratorService
from agent.services.workers.base import Worker
from agent.services.workers.mitre_worker import MitreWorker
from agent.repositories.report_repository import ReportRepository
from agent.services.workers.adviser_worker import AdviserWorker
from agent.services.workers.exploit_worker import ExploitWorker
from agent.services.workers.recon_worker import ReconWorker
from agent.services.workers.script_worker import ScriptWorker
from agent.services.workers.vuln_worker import VulnWorker

logging_config.configure(COMPONENT)
log = logging.getLogger(COMPONENT)

# Stages backed by a real model. Together with TOOL_BACKED this must cover every
# stage in ``shared.pipeline.CHAIN``; :func:`build_worker` raises if it does not.
# There is no longer a canned-stub fallback — all six stages are implemented, and
# a silent stub standing in for a missing worker would report a stage as "done"
# having produced a fabricated artifact.
LLM_BACKED = {"vuln", "mitre", "exploit", "script", "adviser"}

# Stages that do real work through MCP tools but need no model. Recon belongs
# here on purpose: "what URLs exist" is a question a crawler answers exactly and
# a model answers approximately, and an invented endpoint would propagate
# through every stage downstream.
TOOL_BACKED = {"recon"}


def _make_llm_client(agent_name: str):
    """Choose the LLM backend for this agent.

    Default is the OpenAI-compatible client (:mod:`shared.llm`, pointed at
    DeepSeek). ``APTS_LLM_PROVIDER=hf`` selects the Hugging Face Space client
    (:mod:`shared.llm_hf`) instead — a drop-in with the same async interface, so
    the workers below never learn which one they got. The HF import is lazy so a
    DeepSeek deployment does not pull ``gradio_client``.
    """
    provider = os.environ.get("APTS_LLM_PROVIDER", "local").lower()
    if provider in ("hf", "huggingface", "gradio"):
        from shared.llm_hf import HuggingFaceLlmClient
        log.info("LLM backend: Hugging Face Space (APTS_LLM_PROVIDER=%s)", provider)
        return HuggingFaceLlmClient(agent_name)
    if provider in ("local", "llamacpp", "localhost"):
        from shared.llm_local import LocalLlmClient
        log.info("LLM backend: local server (APTS_LLM_PROVIDER=%s)", provider)
        return LocalLlmClient(agent_name)
    if provider in ("aws", "bedrock", "openai"):
        from shared.llm_aws import AwsLlmClient
        log.info("LLM backend: hosted OpenAI-compatible (APTS_LLM_PROVIDER=%s)", provider)
        return AwsLlmClient(agent_name)
    return LlmClient(agent_name)


def build_worker(results: AgentResultRepository, exit_stack: list) -> Worker:
    """Pick this agent's worker, opening an LLM client only if it needs one.

    Appends any async context manager it opens to ``exit_stack`` so lifespan can
    close it — an agent with no model must not hold an idle client, and an agent
    with one must not leak it. The recon/vuln/mitre/exploit workers drive the
    native MCP server directly, so none of them take the old REST-facade client.
    """
    if AGENT_NAME in TOOL_BACKED:
        if AGENT_NAME == "recon":
            return ReconWorker()
        raise RuntimeError(f"{AGENT_NAME!r} is marked tool-backed but has no worker")

    if AGENT_NAME not in LLM_BACKED:
        raise RuntimeError(
            f"{AGENT_NAME!r} is in the pipeline but is neither tool-backed nor "
            f"LLM-backed; it has no worker")

    llm = _make_llm_client(AGENT_NAME)
    exit_stack.append(llm)
    if AGENT_NAME == "mitre":
        return MitreWorker(llm)
    if AGENT_NAME == "vuln":
        return VulnWorker(llm)
    if AGENT_NAME == "exploit":
        # Also reads the register from the store — MITRE sits between this
        # stage and the artifact it needs.
        return ExploitWorker(llm, results)
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
    audit = AuditLog(COMPONENT)

    results = AgentResultRepository()
    opened: list = []
    worker = build_worker(results, opened)
    for resource in opened:
        await resource.__aenter__()

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
        for resource in reversed(opened):
            await resource.__aexit__(None, None, None)
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
