"""Orchestration tests for :class:`ToolProvider`.

These assert the *order* in which a call is vetted, which is the security model
itself: authorise, resolve scope, guardrails, only then execute. The fake
handler records whether it ran, so every test below can state plainly whether a
rejected call reached a side effect.

Nothing here needs Postgres or the sandbox. The service depends on protocols
throughout — ``ScopeSource``, ``AuditSink``, and a registry of callables — so
every collaborator is substituted with an in-memory fake and nothing is
monkeypatched.

That includes audit. Recording the trail through an injected sink rather than a
direct database call means these tests can assert that a blocked call was
*written down as blocked*, which PRD §8 requires: enforcement that works but
leaves no trace still fails the requirement.
"""
from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from mcp_tools.services.tools.registry import ToolRegistry
from mcp_tools.services.engagement_service import ScopeUnavailable
from mcp_tools.services.guardrails_service import GuardrailsService
from mcp_tools.services.policy_service import PolicyService, ToolNotPermitted
from mcp_tools.providers.tool_provider import ToolProvider, UnknownTool
from shared.models import Scope, ToolCall

IN_SCOPE = Scope(domains=["*.target.test"])


class FakeScopes:
    """In-memory ``ScopeSource``; raises like the real provider when asked to fail."""

    def __init__(self, scope: Scope | None = IN_SCOPE, fail: str | None = None) -> None:
        self._scope = scope
        self._fail = fail

    def get_scope(self, engagement_id: UUID) -> Scope:
        if self._fail:
            raise ScopeUnavailable(self._fail)
        assert self._scope is not None
        return self._scope


class SpyTool:
    """Records whether it was invoked, so tests can assert on side effects."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __call__(self, args, ctx):
        self.calls.append({"args": args, "caller": ctx.caller})
        return {"ran": True}

    @property
    def ran(self) -> bool:
        return bool(self.calls)


class FakeAudit:
    """In-memory ``AuditSink`` that keeps the events it was handed."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def record(self, event_type, engagement_id=None, detail=None):
        self.events.append((event_type, detail or {}))

    @property
    def types(self) -> list[str]:
        return [event for event, _ in self.events]


class Harness:
    """A wired ToolProvider plus handles on every fake it was built with."""

    def __init__(self, scopes: FakeScopes | None = None) -> None:
        self.scanner, self.sandbox = SpyTool(), SpyTool()
        self.audit = FakeAudit()
        registry = ToolRegistry()
        registry.register("scanner", self.scanner)
        registry.register("sandbox", self.sandbox)
        self.provider = ToolProvider(
            policy=PolicyService(),
            guardrails=GuardrailsService(),
            engagements=scopes or FakeScopes(),
            registry=registry,
            audit=self.audit,
        )


def build(scopes: FakeScopes | None = None) -> Harness:
    return Harness(scopes)


def call(tool: str, **args) -> ToolCall:
    return ToolCall(engagement_id=uuid4(), tool=tool, args=args)


# --------------------------------------------------------------------------- #

async def test_permitted_in_scope_call_executes():
    h = build()
    result = await h.provider.execute(
        "agent-recon", "scanner", call("scanner", url="https://target.test/"))

    assert result.ok and result.output == {"ran": True}
    assert h.scanner.calls[0]["caller"] == "agent-recon"
    assert h.audit.types == ["tool_call_received", "tool_call_completed"]


async def test_policy_denial_raises_and_never_executes():
    """Recon reaching for the sandbox is refused before any argument is read."""
    h = build()
    with pytest.raises(ToolNotPermitted):
        await h.provider.execute(
            "agent-recon", "sandbox", call("sandbox", command="curl https://target.test/"))

    assert not h.sandbox.ran
    assert "tool_call_denied" in h.audit.types


async def test_out_of_scope_call_is_blocked_not_executed():
    h = build()
    result = await h.provider.execute(
        "agent-recon", "scanner", call("scanner", url="https://evil.test/"))

    assert result.blocked_by_guardrails and not result.ok
    assert "outside the approved scope" in (result.reason or "")
    assert not h.scanner.ran
    assert "tool_call_blocked" in h.audit.types


async def test_unresolvable_scope_fails_closed():
    """An unknown engagement must deny, not pass — same outcome as out-of-scope."""
    h = build(FakeScopes(fail="no engagement on record"))
    result = await h.provider.execute(
        "agent-recon", "scanner", call("scanner", url="https://target.test/"))

    assert result.blocked_by_guardrails and not h.scanner.ran
    assert "tool_call_blocked" in h.audit.types


async def test_destructive_sandbox_command_blocked():
    h = build()
    result = await h.provider.execute(
        "agent-exploit", "sandbox",
        call("sandbox", command="curl https://target.test/ ; rm -rf /"))

    assert result.blocked_by_guardrails and not h.sandbox.ran


async def test_permitted_but_unregistered_tool_is_a_wiring_fault():
    """agent-adviser may call 'report', but this registry never registered it."""
    h = build()
    with pytest.raises(UnknownTool):
        await h.provider.execute("agent-adviser", "report", call("report"))


async def test_every_outcome_is_recorded():
    """No path through execute() may complete without leaving an audit trail."""
    h = build()
    await h.provider.execute("agent-recon", "scanner", call("scanner", url="https://target.test/"))
    await h.provider.execute("agent-recon", "scanner", call("scanner", url="https://evil.test/"))
    with pytest.raises(ToolNotPermitted):
        await h.provider.execute("agent-recon", "sandbox", call("sandbox", command="x"))

    assert h.audit.types == [
        "tool_call_received", "tool_call_completed",
        "tool_call_received", "tool_call_blocked",
        "tool_call_received", "tool_call_denied",
    ]


# --------------------------------------------------------------------------- #

def test_discovery_hides_tools_with_no_implementation():
    """agent-adviser is permitted attack_kb and report; neither is registered here."""
    service = build().provider
    assert service.allowed_tools("agent-recon") == ["scanner"]
    assert service.allowed_tools("agent-exploit") == ["sandbox"]
    assert service.allowed_tools("agent-adviser") == []
    assert service.allowed_tools("agent-rogue") == []
