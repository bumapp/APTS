"""MCP outbound Guardrails — Characterization §7.2.

Every tool call an agent makes enters the MCP-tools container, passes through
:func:`check_tool_call`, and is only forwarded to the real (or stub) tool if
the checkpoint allows it.  The three checks are: scope re-verification, the
destructive-action denylist, and prompt-injection stripping in tool responses.

Skeleton implementation: allowlist/denylist patterns are hard-coded strings.
The modelling phase will replace them with the ``guardrails-ai`` library and
real classifiers.
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("mcp.guardrails")


class GuardrailsMcpBlocked(Exception):
    """Raised when the MCP checkpoint rejects an outbound call."""


# Commands / URLs that are always denied at this checkpoint.  Illustrative only.
_DENY_SHELL_PATTERNS = [
    re.compile(r"\brm\s+-rf\s+/(?:\s|$)", re.IGNORECASE),
    re.compile(r"\bmkfs\.", re.IGNORECASE),
    re.compile(r"\b:\(\)\{.*\};\s*:", re.IGNORECASE),          # fork bomb
    re.compile(r"\bshutdown\b", re.IGNORECASE),
]

_INJECTION_STRIP_PATTERNS = [
    re.compile(r"ignore (?:all )?(?:previous|prior) instructions", re.IGNORECASE),
    re.compile(r"you are now.*mode", re.IGNORECASE),
    re.compile(r"<\s*system\s*>.*?<\s*/\s*system\s*>", re.IGNORECASE | re.DOTALL),
]


def check_tool_call(tool: str, args: dict[str, Any],
                    allowed_hosts: set[str] | None = None) -> None:
    """Reject a tool call that violates scope or contains a destructive action.

    ``allowed_hosts`` is derived from the engagement's scope (passed by the
    caller).  If ``None``, the skeleton allows any host — production must
    always pass one.
    """
    _check_scope(tool, args, allowed_hosts)
    _check_destructive(tool, args)


def strip_injection(text: str) -> str:
    """Return ``text`` with common prompt-injection markers removed."""
    for pat in _INJECTION_STRIP_PATTERNS:
        text = pat.sub("", text)
    return text


# --------------------------------------------------------------------------- #

def _check_scope(tool: str, args: dict[str, Any],
                 allowed_hosts: set[str] | None) -> None:
    if allowed_hosts is None:
        return
    target = args.get("url") or args.get("target") or args.get("host")
    if not target:
        return
    host = urlparse(target).hostname if target.startswith(("http://", "https://")) else target
    host = (host or "").lower()
    for entry in allowed_hosts:
        if entry.startswith("*.") and host.endswith(entry[1:]):
            return
        if host == entry:
            return
    raise GuardrailsMcpBlocked(
        f"tool call to {host!r} is outside the approved scope")


def _check_destructive(tool: str, args: dict[str, Any]) -> None:
    if tool == "sandbox":
        cmd = args.get("command", "") or ""
        for pat in _DENY_SHELL_PATTERNS:
            if pat.search(cmd):
                raise GuardrailsMcpBlocked(
                    f"sandbox command matches destructive pattern: {pat.pattern!r}")
