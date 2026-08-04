"""The tool endpoints.

Two routes: discovery, and invocation. Both authenticate the caller and hand
straight off to :class:`~mcp_tools.providers.tool_provider.ToolProvider` — the
only decisions made in this module are which HTTP status a given provider
outcome deserves.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from shared.auth import Caller
from shared.models import ToolCall, ToolResult

from mcp_tools.controllers.dependencies import get_tool_provider, require_agent
from mcp_tools.providers.tool_provider import (
    ToolNotPermitted,
    ToolProvider,
    UnknownTool,
)

log = logging.getLogger("mcp.controllers.tool")

router = APIRouter(tags=["tools"])


@router.get("/tools")
def list_tools(caller: Caller = Depends(require_agent),
               provider: ToolProvider = Depends(get_tool_provider)) -> dict[str, Any]:
    """Advertise only the tools this caller may actually invoke.

    Filtered by the same policy that enforces the calls, so an agent is never
    told about a tool it would be refused. When the MCP transport is mounted,
    its ``tools/list`` response should be built from this.
    """
    return {"component": caller.component, "tools": provider.allowed_tools(caller.component)}


@router.post("/tool/{tool_name}", response_model=ToolResult)
async def call_tool(tool_name: str, call: ToolCall,
                    caller: Caller = Depends(require_agent),
                    provider: ToolProvider = Depends(get_tool_provider)) -> ToolResult:
    """Invoke one tool.

    A guardrails rejection comes back as HTTP 200 carrying a
    ``blocked_by_guardrails`` result rather than an error status: the call was
    well-formed and properly authorised, and the agent is expected to read the
    reason and adapt. Reserving 4xx for authorisation and wiring faults keeps
    that distinction legible in both logs and agent code.
    """
    if call.tool != tool_name:
        raise HTTPException(400, "tool in URL and body must match")

    try:
        return await provider.execute(caller.component, tool_name, call)
    except ToolNotPermitted as exc:
        raise HTTPException(403, str(exc))
    except UnknownTool as exc:
        log.error("wiring fault: %s", exc)
        raise HTTPException(404, str(exc))
