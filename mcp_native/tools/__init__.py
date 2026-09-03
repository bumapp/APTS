"""Tool implementations for the native MCP server.

Each module here defines one tool (or a small related set) and exposes a
``register(mcp)`` function that attaches it to the server. ``server.py`` imports
every module listed in :data:`ALL` and calls its ``register`` — so adding a new
tool is: drop a module in here, give it a ``register(mcp)``, and add its name to
``ALL``. Nothing else changes.
"""
from __future__ import annotations

from mcp_native.tools import (
    crawl_tool, hacktricks_tool, http_tool, recon_tool, sqlmap_tool)

# The modules server.py will register, in order. Add new tool modules here.
ALL = (http_tool, recon_tool, sqlmap_tool, hacktricks_tool, crawl_tool)


def register_all(mcp) -> list[str]:
    """Register every tool module on ``mcp``. Returns the tool names registered."""
    names: list[str] = []
    for module in ALL:
        names.extend(module.register(mcp))
    return names
