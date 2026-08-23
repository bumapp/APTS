"""Bundled MCP tools container — composition root.

This module wires the object graph and nothing else. The only thing decided
here is which concrete implementation each layer gets, once, at startup.

Layering — each layer calls only the one below it::

    controllers/   HTTP surface: routing, auth, status-code mapping
    providers/     orchestration: composes services into one operation
    services/      the decisions and units of work
    repositories/  database: engagement scope reads
    utils/         pure helpers: URL parsing, response sanitisation

A controller never reaches past its provider, and a provider never issues SQL.
The decision services (``policy_service``, ``guardrails_service``) touch no I/O
at all, which is what makes the security rules testable without a database, an
HTTP client, or a running app.

``repositories/`` holds every SQL statement this container issues *of its own*,
so the component's database footprint is reviewable against the access rules in
PRD §3.2 by reading one folder. The audit-log ``INSERT`` is the exception and
always was: it lives in ``shared/db.py``, reached through
:class:`shared.audit.AuditLog`, because every component writes the same row and
two copies of that statement is one too many.

Tools are exposed today as ``POST /tool/{name}``. When the MCP transport is
mounted (the SDK's ``streamable_http_app()`` as a sub-app on this same server),
it becomes another controller over the same provider — no rule moves.
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

from mcp_tools.config import (
    HTTP_CONNECT_TIMEOUT_SECONDS,
    HTTP_TIMEOUT_SECONDS,
    LISTEN_HOST,
    LISTEN_PORT,
)
from mcp_tools.controllers import health_controller, tool_controller
from mcp_tools.providers.tool_provider import ToolProvider
from mcp_tools.services.engagement_service import EngagementService
from mcp_tools.services.guardrails_service import GuardrailsService
from mcp_tools.services.policy_service import PolicyService
from mcp_tools.services.tools.crawl_tool import CrawlTool
from mcp_tools.services.tools.http_tool import HttpTool
from mcp_tools.services.tools.registry import ToolRegistry
from mcp_tools.services.tools.sandbox_service import SandboxService
from mcp_tools.services.tools.stub_tools import register_stub_tools

COMPONENT = "mcp-tools"

logging_config.configure(COMPONENT)
log = logging.getLogger(COMPONENT)


def build_registry(client: httpx.AsyncClient,
                   token: str) -> tuple[ToolRegistry, httpx.AsyncClient]:
    """Assemble the tool registry.

    Returns the registry and the outbound client it created, so lifespan can
    close the latter. Two clients, deliberately: one that verifies the internal
    trust bundle for service-to-service calls, and one for the target, which is
    untrusted by definition and whose certificate means nothing here.
    """
    registry = ToolRegistry()
    register_stub_tools(registry)

    # Real tools that reach the engagement target. `http` gets its own client:
    # `client` is configured to trust the internal CA for service-to-service
    # calls, and a pentest target's certificate is nobody's business to verify.
    # `crawl` no longer uses this client at all — it drives its own headless
    # browser (see crawl_tool.py) and opens/closes it per call.
    target_client = httpx.AsyncClient(verify=False, follow_redirects=False)
    registry.register("http", HttpTool(target_client))
    registry.register("crawl", CrawlTool())

    registry.register("sandbox", SandboxService(client, token).execute)
    return registry, target_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build the object graph, hold it on ``app.state``, tear it down on exit."""
    token = load_own_token()
    client = httpx.AsyncClient(
        verify=client_ssl_context(),
        timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_CONNECT_TIMEOUT_SECONDS),
    )
    audit = AuditLog(COMPONENT)
    registry, target_client = build_registry(client, token)

    app.state.tool_provider = ToolProvider(
        policy=PolicyService(),
        guardrails=GuardrailsService(),
        engagements=EngagementService(),
        registry=registry,
        audit=audit,
    )

    log.info("mcp-tools ready (tools=%s)",
             ", ".join(app.state.tool_provider.allowed_tools("agent-exploit")) or "none")
    audit.record("startup")
    try:
        yield
    finally:
        await target_client.aclose()
        await client.aclose()
        audit.record("shutdown")


def create_app() -> FastAPI:
    """Application factory.

    A factory rather than a module-level ``app`` so tests can build an instance
    with a substituted provider. The uvicorn entry point below still passes an
    import string, which is what keeps reload and multi-worker modes working.
    """
    application = FastAPI(title="APTS MCP tools", lifespan=lifespan)
    application.include_router(health_controller.router)
    application.include_router(tool_controller.router)
    return application


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "mcp_tools.main:app",
        host=LISTEN_HOST, port=LISTEN_PORT,
        log_config=None,
        **uvicorn_ssl_kwargs(),
    )
