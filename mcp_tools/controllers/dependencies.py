"""FastAPI dependencies shared by the controllers.

The object graph is built once during the app's lifespan and stashed on
``app.state``; these resolve it per request. Going through the app rather than
a module-level singleton is what allows a test to construct an app with fake
services and no database.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request

from shared.auth import Caller, require_auth

from mcp_tools.providers.tool_provider import ToolProvider


def get_tool_provider(request: Request) -> ToolProvider:
    return request.app.state.tool_provider


def require_agent(caller: Caller = Depends(require_auth)) -> Caller:
    """Authenticate, and require the caller to be one of the agents.

    Only agents call tools. The orchestrator coordinates and the sandbox is
    called *by* this container, so neither has any business here — and the
    per-agent policy table has no entry for them regardless.
    """
    if not caller.component.startswith("agent-"):
        raise HTTPException(403, f"{caller.component!r} may not call MCP tools")
    return caller
