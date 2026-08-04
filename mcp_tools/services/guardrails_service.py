"""MCP outbound Guardrails — Characterization §7.2.

Every tool call an agent makes passes through :meth:`GuardrailsService.check`
and reaches its handler only if the checkpoint allows it.  Two checks live
here: scope re-verification, and the destructive-action denylist.  A third —
prompt-injection stripping on the way back — is applied by tool
implementations via ``utils.sanitise``.

This service is pure.  It takes an already-loaded :class:`Scope` rather than
looking one up, which keeps the database out of the decision logic and lets
every rule be tested without a running Postgres.  Loading the scope, and
failing closed when it cannot be loaded, belongs to
:class:`~mcp_tools.repositories.engagement_repository.EngagementRepository`.

Skeleton status: the destructive denylist is a hard-coded regex list.  The
modelling phase replaces it with the ``guardrails-ai`` library and a real
action classifier.  Scope enforcement below is production logic.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from shared.models import Scope
from shared.scope_match import host_matches, matching_deny_path, path_allowed

from mcp_tools.utils.url import extract_urls, split_host_path

log = logging.getLogger("mcp.services.guardrails")


class GuardrailsBlocked(Exception):
    """Raised when the MCP checkpoint rejects an outbound call."""


# Tools that can put packets on the wire toward the engagement target.  Only
# these are scope-checked; ``cve``, ``attack_kb``, and ``report`` talk to
# internal or third-party services, never to the target.
NETWORK_TOOLS = frozenset({"scanner", "http", "sandbox"})

# Tools whose target is embedded in free text rather than a named argument.
_FREE_TEXT_TARGET_TOOLS = frozenset({"sandbox"})

_DENY_SHELL_PATTERNS = [
    re.compile(r"\brm\s+-rf\s+/(?:\s|$)", re.IGNORECASE),
    re.compile(r"\bmkfs\.", re.IGNORECASE),
    re.compile(r"\b:\(\)\{.*\};\s*:", re.IGNORECASE),          # fork bomb
    re.compile(r"\bshutdown\b", re.IGNORECASE),
]


class GuardrailsService:
    """Scope and destructive-action enforcement for outbound tool calls."""

    def __init__(self, network_tools: frozenset[str] = NETWORK_TOOLS) -> None:
        self._network_tools = network_tools

    def check(self, tool: str, args: dict[str, Any], scope: Scope) -> None:
        """Raise :class:`GuardrailsBlocked` if this call must not proceed.

        ``scope`` is the engagement's approved boundary.  There is deliberately
        no "allow any" mode: a :class:`Scope` naming no domains blocks every
        network tool, because a scope check that defaults to open is not one.
        """
        self._check_scope(tool, args, scope)
        self._check_destructive(tool, args)

    # ----------------------------------------------------------------- #
    # Scope
    # ----------------------------------------------------------------- #

    def _check_scope(self, tool: str, args: dict[str, Any], scope: Scope) -> None:
        if tool not in self._network_tools:
            return

        targets = self._extract_targets(tool, args)
        if not targets:
            raise GuardrailsBlocked(
                f"{tool!r} is a network tool but the call carries no resolvable "
                f"target; refusing to send an unscoped request")

        for target in targets:
            self._check_one_target(tool, target, scope)

    @staticmethod
    def _extract_targets(tool: str, args: dict[str, Any]) -> list[str]:
        """Every host this call would reach.

        For free-text tools the target is buried in a command string, so all
        embedded URLs are scraped out — a command may fetch from an approved
        host and post the result to an unapproved one, and checking only the
        first URL would wave that through.
        """
        if tool in _FREE_TEXT_TARGET_TOOLS:
            return extract_urls(str(args.get("command", "")))
        raw = args.get("url") or args.get("target") or args.get("host")
        return [str(raw)] if raw else []

    @staticmethod
    def _check_one_target(tool: str, target: str, scope: Scope) -> None:
        host, path = split_host_path(target)
        if not host:
            raise GuardrailsBlocked(
                f"could not parse a hostname out of {target!r} for tool {tool!r}")

        if not host_matches(host, scope.domains):
            raise GuardrailsBlocked(
                f"tool call to {host!r} is outside the approved scope "
                f"(domains: {', '.join(scope.domains) or 'none'})")

        denied = matching_deny_path(path, scope.deny_paths)
        if denied:
            raise GuardrailsBlocked(
                f"path {path!r} on {host!r} is explicitly out of scope "
                f"(deny_paths entry {denied!r})")

        if not path_allowed(path, scope.allow_paths):
            raise GuardrailsBlocked(
                f"path {path!r} on {host!r} is outside allow_paths "
                f"({', '.join(scope.allow_paths)})")

    # ----------------------------------------------------------------- #
    # Destructive actions
    # ----------------------------------------------------------------- #

    @staticmethod
    def _check_destructive(tool: str, args: dict[str, Any]) -> None:
        if tool != "sandbox":
            return
        command = args.get("command", "") or ""
        for pattern in _DENY_SHELL_PATTERNS:
            if pattern.search(command):
                raise GuardrailsBlocked(
                    f"sandbox command matches destructive pattern: "
                    f"{pattern.pattern!r}")
