"""Placeholder tool implementations.

Each of these returns canned data of roughly the right shape so the transport,
authorisation, and guardrails layers can be exercised end to end before any
real scanner exists.  They are the *only* thing in this package that is fake.

As each real tool lands it should move out of this file into its own module
(``scanner_tool.py`` wrapping nuclei, ``cve_tool.py`` over the NVD API, and so
on) and register itself the same way.  Keeping them together while they are
one-liners avoids six near-empty modules; splitting them up once they have
real bodies keeps the diffs readable.
"""
from __future__ import annotations

from typing import Any

from mcp_tools.services.tools.base import ToolContext
from mcp_tools.services.tools.registry import ToolRegistry
from mcp_tools.utils.sanitise import strip_injection


async def scanner_tool(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    return {"findings": [{"target": args.get("url"), "hits": []}]}


async def http_tool(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    # The body is modelled as coming back from the target, so it is sanitised
    # on the way out — a real HTTP tool must do the same with the live response.
    body = strip_injection(str(args.get("expected_body", "")))
    return {"status_code": 200, "body": body}


async def cve_tool(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    return {"query": args.get("query"), "matches": []}


async def attack_kb_tool(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    return {"technique": args.get("technique"), "description": "(stub)"}


async def report_tool(args: dict[str, Any], ctx: ToolContext) -> dict[str, Any]:
    return {"pdf_path": "/tmp/report.pdf", "json_path": "/tmp/report.json"}


def register_stub_tools(registry: ToolRegistry) -> None:
    """Register every placeholder tool.

    ``sandbox`` is absent deliberately — it is the one tool that really calls
    another container, so it is built with its dependencies in
    ``providers/sandbox_provider.py``.
    """
    registry.register("scanner", scanner_tool)
    registry.register("http", http_tool)
    registry.register("cve", cve_tool)
    registry.register("attack_kb", attack_kb_tool)
    registry.register("report", report_tool)
