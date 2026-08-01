"""Bundled MCP tools container.

One HTTPS server exposing one endpoint per tool listed in Characterization §6:

======================  ================================================
tool                    endpoint
======================  ================================================
scanner                 POST /tool/scanner
http                    POST /tool/http
cve                     POST /tool/cve
attack_kb               POST /tool/attack_kb
sandbox                 POST /tool/sandbox    (forwards to sandbox container)
report                  POST /tool/report
======================  ================================================

Every request is bearer-token authenticated and passes through the MCP
outbound Guardrails checkpoint (:mod:`mcp_tools.guardrails_mcp`) before the
tool logic runs.

Skeleton: each tool returns a canned response.  The sandbox endpoint is the
only one that actually calls another container.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any

import httpx
import uvicorn
from fastapi import Depends, FastAPI, HTTPException

from shared import logging_config
from shared.auth import Caller, bearer_headers, load_own_token, require_auth
from shared.db import audit
from shared.models import SandboxExecRequest, SandboxExecResult, ToolCall, ToolResult
from shared.tls import client_ssl_context, uvicorn_ssl_kwargs

from mcp_tools.guardrails_mcp import (
    GuardrailsMcpBlocked,
    check_tool_call,
    strip_injection,
)

logging_config.configure("mcp-tools")
log = logging.getLogger("mcp-tools")

SANDBOX_URL = "https://sandbox:8443"
_OWN_TOKEN: str | None = None
_client: httpx.AsyncClient | None = None


# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _OWN_TOKEN, _client
    _OWN_TOKEN = load_own_token()
    _client = httpx.AsyncClient(
        verify=client_ssl_context(),
        timeout=httpx.Timeout(15.0, connect=5.0),
    )
    log.info("mcp-tools ready")
    audit("mcp-tools", "startup")
    try:
        yield
    finally:
        await _client.aclose()


app = FastAPI(title="APTS MCP tools", lifespan=lifespan)


# --------------------------------------------------------------------------- #

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/tool/{tool_name}", response_model=ToolResult)
async def call_tool(tool_name: str, req: ToolCall,
                    caller: Caller = Depends(require_auth)) -> ToolResult:
    if not caller.component.startswith("agent-"):
        raise HTTPException(403, f"{caller.component!r} may not call MCP tools")

    if req.tool != tool_name:
        raise HTTPException(400, "tool in URL and body must match")

    audit("mcp-tools", "tool_call_received",
          engagement_id=str(req.engagement_id),
          detail={"tool": tool_name, "by": caller.component})

    # Guardrails MCP outbound checkpoint
    try:
        # ``allowed_hosts`` would normally come from the engagement's scope in
        # the database; the skeleton passes None (allow-any) so the plumbing
        # stays testable without a real target.  Replace this with a lookup
        # in the ``engagements`` row when the engagement store settles.
        check_tool_call(tool_name, req.args, allowed_hosts=None)
    except GuardrailsMcpBlocked as exc:
        log.warning("mcp guardrails BLOCK %s: %s", tool_name, exc)
        audit("mcp-tools", "tool_call_blocked",
              engagement_id=str(req.engagement_id),
              detail={"tool": tool_name, "reason": str(exc)})
        return ToolResult(tool=tool_name, ok=False, blocked_by_guardrails=True,
                          reason=str(exc))

    # Dispatch to the correct stub
    if tool_name == "sandbox":
        return await _tool_sandbox(req)
    handler = _STUBS.get(tool_name)
    if handler is None:
        raise HTTPException(404, f"unknown tool {tool_name!r}")
    output = handler(req.args)
    return ToolResult(tool=tool_name, ok=True, output=output)


# --------------------------------------------------------------------------- #
# Tool stubs — every one of these gets replaced with a real integration later
# --------------------------------------------------------------------------- #

def _stub_scanner(args: dict[str, Any]) -> dict[str, Any]:
    return {"findings": [{"target": args.get("url"), "hits": []}]}


def _stub_http(args: dict[str, Any]) -> dict[str, Any]:
    body = strip_injection(str(args.get("expected_body", "")))
    return {"status_code": 200, "body": body}


def _stub_cve(args: dict[str, Any]) -> dict[str, Any]:
    return {"query": args.get("query"), "matches": []}


def _stub_attack_kb(args: dict[str, Any]) -> dict[str, Any]:
    return {"technique": args.get("technique"), "description": "(stub)"}


def _stub_report(args: dict[str, Any]) -> dict[str, Any]:
    return {"pdf_path": "/tmp/report.pdf", "json_path": "/tmp/report.json"}


_STUBS = {
    "scanner":   _stub_scanner,
    "http":      _stub_http,
    "cve":       _stub_cve,
    "attack_kb": _stub_attack_kb,
    "report":    _stub_report,
}


async def _tool_sandbox(req: ToolCall) -> ToolResult:
    assert _client is not None
    assert _OWN_TOKEN is not None
    payload = SandboxExecRequest(engagement_id=req.engagement_id,
                                 command=str(req.args.get("command", "")))
    resp = await _client.post(
        f"{SANDBOX_URL}/exec",
        content=payload.model_dump_json(),
        headers=bearer_headers(_OWN_TOKEN),
    )
    resp.raise_for_status()
    sandbox_result = SandboxExecResult(**resp.json())
    return ToolResult(
        tool="sandbox", ok=sandbox_result.ok,
        output={"exit_code": sandbox_result.exit_code,
                "stdout":    sandbox_result.stdout,
                "stderr":    sandbox_result.stderr},
    )


# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    uvicorn.run(
        "mcp_tools.main:app",
        host="0.0.0.0", port=8443,
        log_config=None,
        **uvicorn_ssl_kwargs(),
    )
