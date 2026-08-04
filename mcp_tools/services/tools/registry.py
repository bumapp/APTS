"""Tool name → implementation lookup.

A registry rather than a module-level dict of functions, so that tools needing
collaborators (the sandbox handler needs an HTTP client and a bearer token) can
be constructed at startup and registered as bound callables, instead of
reaching for module globals at call time.

Adding a tool is then a two-line change here plus an entry in the policy table
— and forgetting the policy entry leaves the tool unreachable rather than
silently open to everyone.
"""
from __future__ import annotations

import logging

from mcp_tools.services.tools.base import ToolHandler

log = logging.getLogger("mcp.services.tools")


class ToolRegistry:
    """Mutable collection of the tools this container can execute."""

    def __init__(self) -> None:
        self._handlers: dict[str, ToolHandler] = {}

    def register(self, name: str, handler: ToolHandler) -> None:
        if name in self._handlers:
            raise ValueError(f"tool {name!r} is already registered")
        self._handlers[name] = handler
        log.debug("registered tool %r", name)

    def get(self, name: str) -> ToolHandler | None:
        return self._handlers.get(name)

    def has(self, name: str) -> bool:
        return name in self._handlers

    def names(self) -> list[str]:
        return sorted(self._handlers)
