"""Native Model Context Protocol server for the project.

A real MCP server (official SDK), distinct from the REST ``mcp_tools/`` facade.
Exposes its tools over the genuine protocol (tools/list, tools/call) so any
MCP-compliant client or model host can use them. See ``server.py``.
"""
