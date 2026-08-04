"""The agent's client for the MCP tool surface.

Agents never reach the target directly. Every outbound request goes through
mcp-tools, which is where the per-agent allowlist and the scope guardrail live.
An agent that opened its own HTTP client to the target would be routing around
both, so this is the only network path an agent has.

A guardrails block is *not* an exception here. It comes back as a
:class:`ToolOutcome` with ``blocked`` set, because the worker is expected to
read the reason and adapt — noting an out-of-scope link and moving on is normal
recon behaviour, not a failure. Only transport faults and refusals raise.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx

from shared.auth import bearer_headers
from shared.models import ToolCall

log = logging.getLogger("agent.services.mcp")


class ToolCallFailed(Exception):
    """Raised when a tool call could not be completed at all."""


@dataclass(frozen=True)
class ToolOutcome:
    ok: bool
    output: dict[str, Any]
    blocked: bool = False
    reason: str = ""


class McpService:
    """Calls tools on the mcp-tools container."""

    def __init__(self, client: httpx.AsyncClient, token: str,
                 base_url: str = "https://mcp-tools:8443") -> None:
        self._client = client
        self._token = token
        self._base_url = base_url.rstrip("/")

    async def call(self, tool: str, engagement_id: UUID,
                   **args: Any) -> ToolOutcome:
        payload = ToolCall(engagement_id=engagement_id, tool=tool, args=args)
        try:
            response = await self._client.post(
                f"{self._base_url}/tool/{tool}",
                content=payload.model_dump_json(),
                headers=bearer_headers(self._token),
            )
        except httpx.HTTPError as exc:
            raise ToolCallFailed(f"tool {tool!r} unreachable: {exc}") from exc

        if response.status_code == 403:
            # The allowlist refused this agent. A code fault, not a runtime
            # condition — the agent asked for something it is never allowed.
            raise ToolCallFailed(
                f"tool {tool!r} refused for this agent: {response.text[:200]}")
        if response.status_code != 200:
            raise ToolCallFailed(
                f"tool {tool!r} returned HTTP {response.status_code}: "
                f"{response.text[:200]}")

        body = response.json()
        if body.get("blocked_by_guardrails"):
            reason = body.get("reason") or "blocked"
            log.info("guardrails blocked %s: %s", tool, reason)
            return ToolOutcome(ok=False, output={}, blocked=True, reason=reason)

        return ToolOutcome(ok=bool(body.get("ok")), output=body.get("output") or {})
