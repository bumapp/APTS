"""Bundled MCP tools container — composition root.

This module wires the object graph and nothing else. The only thing decided
here is which concrete implementation each layer gets, once, at startup.

Layering — each layer calls only the one below it::

    controllers/   HTTP surface: routing, auth, status-code mapping
    providers/     orchestration: composes services into one operation
    services/      the decisions and units of work
    repositories/  database: engagement scope reads, audit-log writes
    utils/         pure helpers: URL parsing, response sanitisation

A controller never reaches past its provider, and a provider never issues SQL.
The decision services (``policy_service``, ``guardrails_service``) touch no I/O
at all, which is what makes the security rules testable without a database, an
HTTP client, or a running app.

``repositories/`` holds every SQL statement this container issues, so the
component's full database footprint is reviewable against the access rules in
PRD §3.2 by reading one folder.

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
from mcp_tools.services.audit_service import AuditService
from mcp_tools.services.engagement_service import EngagementService
from mcp_tools.services.guardrails_service import GuardrailsService
from mcp_tools.services.policy_service import PolicyService
from mcp_tools.services.tools.registry import ToolRegistry
from mcp_tools.services.tools.sandbox_service import SandboxService
from mcp_tools.services.tools.stub_tools import register_stub_tools

COMPONENT = "mcp-tools"

logging_config.configure(COMPONENT)
log = logging.getLogger(COMPONENT)


def build_registry(client: httpx.AsyncClient, token: str) -> ToolRegistry:
    """Assemble the tool registry.

    The stubs are self-contained; ``sandbox`` is constructed here because it
    needs the shared HTTP client and this container's bearer token.
    """
    registry = ToolRegistry()
    register_stub_tools(registry)
    registry.register("sandbox", SandboxService(client, token).execute)
    return registry


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Build the object graph, hold it on ``app.state``, tear it down on exit."""
    token = load_own_token()
    client = httpx.AsyncClient(
        verify=client_ssl_context(),
        timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS, connect=HTTP_CONNECT_TIMEOUT_SECONDS),
    )
    audit = AuditService(COMPONENT)

    app.state.http_client = client
    app.state.tool_provider = ToolProvider(
        policy=PolicyService(),
        guardrails=GuardrailsService(),
        engagements=EngagementService(),
        registry=build_registry(client, token),
        audit=audit,
    )

    log.info("mcp-tools ready (tools=%s)",
             ", ".join(app.state.tool_provider.allowed_tools("agent-exploit")) or "none")
    audit.record("startup")
    try:
        yield
    finally:
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
