"""Orchestration for a single tool call.

The first layer a controller reaches. It owns no rules of its own — it composes
the services that do, and the order it composes them in is the security model:

1. **Authorise** — may this component call this tool at all? A refusal here is
   an authorisation failure and surfaces as 403.
2. **Resolve scope** — read the engagement's approved boundary. Failing to
   resolve it is a denial, never a pass.
3. **Guardrails** — is this specific call within scope and non-destructive?
4. **Execute** — only now does a handler run.

Steps 1–3 all precede any side effect. Putting authorisation before scope
resolution also means a component reaching for a tool it has no business
touching is refused without a database round trip.

Audit lands here rather than in the controller because the trail is a product
requirement (§8, immutable log of every agent action and Guardrails decision),
not an HTTP concern — it must record the call the same way however the call
arrived, REST today or MCP transport tomorrow. It goes through an injected
:class:`AuditSink`, so this module imports no persistence code.
"""
from __future__ import annotations

import logging

from shared.models import ToolCall, ToolResult

from mcp_tools.services.audit_service import AuditSink
from mcp_tools.services.engagement_service import ScopeSource, ScopeUnavailable
from mcp_tools.services.guardrails_service import GuardrailsBlocked, GuardrailsService
from mcp_tools.services.policy_service import PolicyService, ToolNotPermitted
from mcp_tools.services.tools.base import ToolContext
from mcp_tools.services.tools.registry import ToolRegistry

log = logging.getLogger("mcp.providers.tool")


class UnknownTool(Exception):
    """Raised when a permitted tool has no registered implementation."""


# Re-exported so a controller can map every failure this provider raises without
# importing from ``services/``. The controller's only dependency is its provider;
# reaching past it for an exception type would be the same layering break as
# reaching past it for a decision.
__all__ = ["ToolProvider", "ToolNotPermitted", "UnknownTool"]


class ToolProvider:
    """Vets and executes tool calls on behalf of authenticated agents."""

    def __init__(self, policy: PolicyService, guardrails: GuardrailsService,
                 engagements: ScopeSource, registry: ToolRegistry,
                 audit: AuditSink) -> None:
        self._policy = policy
        self._guardrails = guardrails
        self._engagements = engagements
        self._registry = registry
        self._audit = audit

    def allowed_tools(self, caller: str) -> list[str]:
        """Tools ``caller`` may invoke that also have an implementation.

        Intersected with the registry so discovery never advertises a tool that
        is in the policy table but not actually wired up.
        """
        return [t for t in self._policy.allowed_tools(caller) if self._registry.has(t)]

    async def execute(self, caller: str, tool_name: str, call: ToolCall) -> ToolResult:
        """Run ``tool_name`` for ``caller``, or explain why it did not run.

        Raises :class:`ToolNotPermitted` for an authorisation failure and
        :class:`UnknownTool` for a permitted-but-unimplemented tool; both are
        mapped to HTTP status codes by the controller. A guardrails rejection
        is *not* an exception at this boundary — it is a legitimate, expected
        outcome the calling agent needs to read and adapt to, so it comes back
        as a :class:`ToolResult` carrying the reason.
        """
        engagement_id = str(call.engagement_id)
        self._audit.record("tool_call_received", engagement_id=engagement_id,
                           detail={"tool": tool_name, "by": caller})

        self._authorise(caller, tool_name, engagement_id)

        try:
            scope = self._engagements.get_scope(call.engagement_id)
            self._guardrails.check(tool_name, call.args, scope)
        except (GuardrailsBlocked, ScopeUnavailable) as exc:
            return self._blocked(tool_name, caller, engagement_id, exc)

        handler = self._registry.get(tool_name)
        if handler is None:
            # Reachable only if the policy table permits a tool the registry
            # never registered — a wiring mistake, so it should be loud.
            raise UnknownTool(
                f"tool {tool_name!r} is permitted for {caller!r} but has no "
                f"registered implementation")

        ctx = ToolContext(engagement_id=call.engagement_id, caller=caller,
                          scope=scope)
        output = await handler(call.args, ctx)

        self._audit.record("tool_call_completed", engagement_id=engagement_id,
                           detail={"tool": tool_name, "by": caller})
        return ToolResult(tool=tool_name, ok=True, output=output)

    # ----------------------------------------------------------------- #

    def _authorise(self, caller: str, tool_name: str, engagement_id: str) -> None:
        try:
            self._policy.check(caller, tool_name)
        except ToolNotPermitted as exc:
            log.warning("tool policy DENY %s -> %s: %s", caller, tool_name, exc)
            self._audit.record(
                "tool_call_denied", engagement_id=engagement_id,
                detail={"tool": tool_name, "by": caller, "reason": str(exc)})
            raise

    def _blocked(self, tool_name: str, caller: str, engagement_id: str,
                 exc: Exception) -> ToolResult:
        log.warning("mcp guardrails BLOCK %s (%s): %s", tool_name, caller, exc)
        self._audit.record(
            "tool_call_blocked", engagement_id=engagement_id,
            detail={"tool": tool_name, "by": caller, "reason": str(exc)})
        return ToolResult(tool=tool_name, ok=False,
                          blocked_by_guardrails=True, reason=str(exc))
