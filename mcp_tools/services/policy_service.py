"""Per-agent tool allowlist.

The MCP container authenticates its caller and therefore knows exactly which
component is on the other end.  This service turns that identity into an
authorisation decision: which tools that component may invoke at all.

Distinct from guardrails on purpose.  Guardrails asks "is this particular call
safe?" — scope, destructive patterns, injection.  This asks the blunter
question "should this agent ever be able to make this kind of call?"  The
Reconnaissance agent has no legitimate reason to reach the sandbox shell
executor, and no amount of argument inspection should be what stands between
it and one.  Structural denial is easier to reason about than per-call
filtering, and it shrinks each agent's tool-selection space to a handful of
entries, which measurably improves model tool choice once the stubs are gone.
"""
from __future__ import annotations

import logging

log = logging.getLogger("mcp.services.policy")


class ToolNotPermitted(Exception):
    """Raised when a component invokes a tool outside its allowlist."""


# Keys are component names exactly as they appear in ``token_hashes`` and in
# ``Caller.component`` — ``agent-recon``, not ``recon``.  Values must match the
# names registered in the tool registry.
DEFAULT_TOOL_POLICY: dict[str, frozenset[str]] = {
    # Discovery: read the target, never execute against it.
    "agent-recon":   frozenset({"scanner", "http", "crawl"}),
    # Analysis: recon's tools plus vulnerability intelligence lookups.
    "agent-vuln":    frozenset({"scanner", "http", "crawl", "cve"}),
    # Methodology: pure knowledge-base work, no network reach at all.
    "agent-mitre":   frozenset({"attack_kb"}),
    # Offense: the only component permitted to reach the sandbox executor.
    "agent-exploit": frozenset({"http", "sandbox"}),
    # Scripting: needs technique metadata to tag generated scripts.
    "agent-script":  frozenset({"attack_kb"}),
    # Advisory: report rendering plus technique lookups for the coverage map.
    "agent-adviser": frozenset({"attack_kb", "report"}),
}


class PolicyService:
    """Deny-by-default authorisation over the tool surface.

    Deny-by-default runs in both directions: a component with no entry gets
    nothing, and a tool absent from a component's set is refused even when the
    tool exists.  Registering a new tool therefore requires a deliberate edit
    here before any agent can call it — the failure mode of forgetting is an
    unreachable tool, not an unguarded one.
    """

    def __init__(self, policy: dict[str, frozenset[str]] | None = None) -> None:
        self._policy = DEFAULT_TOOL_POLICY if policy is None else policy

    def check(self, component: str, tool: str) -> None:
        """Raise :class:`ToolNotPermitted` unless ``component`` may call ``tool``."""
        allowed = self._policy.get(component)
        if allowed is None:
            raise ToolNotPermitted(
                f"component {component!r} has no tool policy entry; "
                f"denying by default")
        if tool not in allowed:
            raise ToolNotPermitted(
                f"{component!r} may not call tool {tool!r} "
                f"(permitted: {', '.join(sorted(allowed)) or 'none'})")

    def allowed_tools(self, component: str) -> list[str]:
        """Tools ``component`` may call, sorted.  Empty for an unknown component.

        Discovery is filtered through the same table that enforces the calls,
        so an agent is never advertised a tool it would be refused.
        """
        return sorted(self._policy.get(component, frozenset()))
