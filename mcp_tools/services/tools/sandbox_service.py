"""Adapter over the sandbox executor container.

The only tool that leaves this process today.  It exists as a class rather than
a bare function because it needs collaborators — an HTTP client configured with
the trust bundle, and this container's own bearer token — and wiring those at
construction time is what keeps them out of module-level globals.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from shared.auth import bearer_headers
from shared.models import SandboxExecRequest, SandboxExecResult

from mcp_tools.config import SANDBOX_URL
from mcp_tools.services.tools.base import ToolContext

log = logging.getLogger("mcp.services.tools.sandbox")


class SandboxService:
    """Forwards a command to the sandbox container and returns its result."""

    def __init__(self, client: httpx.AsyncClient, token: str,
                 base_url: str = SANDBOX_URL) -> None:
        self._client = client
        self._token = token
        self._base_url = base_url.rstrip("/")

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
        """Run one command in the sandbox.

        Conforms to :class:`~mcp_tools.services.tools.base.ToolHandler`, so it
        registers as ``sandbox`` alongside the ordinary tools.
        """
        payload = SandboxExecRequest(
            engagement_id=ctx.engagement_id,
            command=str(args.get("command", "")),
        )
        response = await self._client.post(
            f"{self._base_url}/exec",
            content=payload.model_dump_json(),
            headers=bearer_headers(self._token),
        )
        response.raise_for_status()
        result = SandboxExecResult(**response.json())

        return {
            "ok": result.ok,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
