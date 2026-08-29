"""The project's native MCP server — thin wiring only.

A genuine Model Context Protocol server (official SDK). It owns no tool logic:
each tool lives in its own module under ``mcp_native/tools/`` and is attached
here via :func:`mcp_native.tools.register_all`. Adding a tool means adding a
module there, not editing this file.

Standalone by design — no agent depends on it and it calls no agent. Some tools
need the database or the target network, so run it in the ``mcp-native``
container (docker-compose), which has both.

Run:
    python -m mcp_native.server           # stdio transport (default)
    python -m mcp_native.server --http    # streamable-HTTP on :9000
"""
from __future__ import annotations

import logging
import sys

from mcp.server.mcpserver import MCPServer

from mcp_native.tools import register_all

log = logging.getLogger("mcp_native.server")

mcp = MCPServer(
    name="apts-tools",
    instructions=("HTTP requests, lookup of requests recon observed, and sqlmap "
                  "for SQL-injection testing."),
)

_registered = register_all(mcp)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    log.info("native MCP server tools: %s", ", ".join(_registered))
    if "--http" in sys.argv:
        mcp.run(transport="streamable-http", host="0.0.0.0", port=9000)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
