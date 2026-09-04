"""The orchestrator's control surface, as a native MCP server.

This is what the Composer (and any MCP client) drives to run APTS end to end
without touching an agent directly: describe capabilities, create an engagement,
check its status, stop it, and read back the artifacts each stage produced. It
runs inside the orchestrator container as a third server (alongside the public
:8443 and admin :8080 FastAPI apps), so "the orchestrator is the single
interface and controller" holds literally.

Deliberately self-contained. The tools talk to the shared store with their own
connections and do the recon kickoff with their own HTTP client, rather than
reaching into ``orchestrator.main``'s runtime globals — those belong to the
public app's event loop, and this server runs in its own thread with its own
loop. The small amount of duplicated SQL (the engagement + per-agent seed) is
the price of that isolation; the pipeline shape still comes from
``shared.pipeline`` so the two cannot disagree about the chain.

Cancellation is cooperative: ``stop_engagement`` marks the engagement (and its
not-yet-finished stages) cancelled, and the orchestrator's driven advancement
refuses to launch the next stage once an engagement is no longer ``running``. A
stage already executing runs to completion; its result is simply not advanced.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any
from uuid import UUID, uuid4

import httpx
import psycopg

from mcp.server.mcpserver import MCPServer

from shared import pipeline, trace
from shared.auth import bearer_headers, load_own_token
from shared.db import audit, get_conn
from shared.models import ChainHandoff, EngagementSpec, Scope, TimeWindow
from shared.tls import client_ssl_context

from orchestrator.guardrails_entry import (
    GuardrailsEntryBlocked,
    check_engagement_spec,
)

log = logging.getLogger("orchestrator.mcp_control")

CHAIN = list(pipeline.CHAIN)
ARTIFACT_CHARS = 8000  # cap a returned artifact so it never floods the chat model

control = MCPServer(
    name="apts-orchestrator-control",
    instructions=("Control APTS engagements: describe capabilities, create an "
                  "engagement, check status, stop it, and read agent artifacts. "
                  "The user never talks to an agent directly — only through here."),
)


# --------------------------------------------------------------------------- #
# Small store helpers (own connections; safe from this server's own loop)
# --------------------------------------------------------------------------- #

def _uuid(value: str) -> UUID | None:
    try:
        return UUID(str(value))
    except (ValueError, TypeError):
        return None


def _create_engagement_row(engagement_id: UUID, spec: EngagementSpec) -> None:
    """Insert the engagement and seed one pending row per stage.

    Mirrors ``orchestrator.main._create_engagement_row`` on purpose (see module
    docstring); kept in lockstep by both using ``shared.pipeline.CHAIN``."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO engagements (id, target_url, scope, time_window, status)
               VALUES (%s, %s, %s::jsonb, %s::jsonb, 'running')""",
            (str(engagement_id), spec.target_url,
             psycopg.types.json.Json(spec.scope.model_dump()),
             psycopg.types.json.Json(spec.time_window.model_dump()
                                     if spec.time_window else {})),
        )
        for agent in CHAIN:
            cur.execute(
                """INSERT INTO engagement_state (engagement_id, agent, status)
                   VALUES (%s, %s, 'pending')""",
                (str(engagement_id), agent),
            )


def _status(engagement_id: UUID) -> dict[str, Any] | None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT target_url, status, created_at, completed_at "
            "FROM engagements WHERE id = %s", (str(engagement_id),))
        row = cur.fetchone()
        if not row:
            return None
        target_url, status, created_at, completed_at = row
        cur.execute(
            "SELECT agent, status, retry_count, last_error "
            "FROM engagement_state WHERE engagement_id = %s", (str(engagement_id),))
        per_agent = {a: {"status": s, "retry_count": rc, "last_error": err}
                     for a, s, rc, err in cur.fetchall()}
    # Present the stages in pipeline order, and name the one running now.
    ordered = {a: per_agent.get(a, {"status": "pending"}) for a in CHAIN}
    current = next((a for a in CHAIN
                    if ordered[a]["status"] in ("started", "running")), None)
    return {"engagement_id": str(engagement_id), "target_url": target_url,
            "status": status, "current_agent": current, "per_agent": ordered,
            "created_at": str(created_at) if created_at else None,
            "completed_at": str(completed_at) if completed_at else None}


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #

async def apts_capabilities() -> dict[str, Any]:
    """Explain what APTS is and what it needs to start an engagement.

    Call this to answer "what can you do?" and to know which parameters to
    collect from the user before creating an engagement."""
    return {
        "summary": ("APTS is an AI-agentic penetration-testing pipeline for web "
                    "targets. You (the orchestrator) are the only interface: the "
                    "user talks to you, and you drive the agents."),
        "pipeline": [
            {"stage": "recon", "does": "crawl the target and map the attack surface"},
            {"stage": "vuln", "does": "hypothesise concrete, testable weaknesses"},
            {"stage": "mitre", "does": "map each weakness to MITRE ATT&CK techniques"},
            {"stage": "exploit", "does": "prove or disprove each weakness on the live target"},
            {"stage": "script", "does": "write and sandbox-test a PoC for each confirmed weakness"},
            {"stage": "adviser", "does": "produce the grouped, impact-ranked client report"},
        ],
        "required_to_start": {
            "target_url": "the target's base URL, e.g. http://juice-shop:3000/",
            "domains": "in-scope host(s); must cover the target host",
        },
        "optional": {
            "allow_paths": "path prefixes to include",
            "deny_paths": "path prefixes to exclude",
            "time_window": "starts_at / ends_at ISO timestamps",
            "categories": "test categories to emphasise (advisory)",
        },
        "actions": ["create_engagement", "engagement_status", "stop_engagement",
                    "list_artifacts", "get_artifact"],
    }


async def create_engagement(
    target_url: str,
    domains: list[str],
    allow_paths: list[str] | None = None,
    deny_paths: list[str] | None = None,
    starts_at: str | None = None,
    ends_at: str | None = None,
    categories: list[str] | None = None,
) -> dict[str, Any]:
    """Validate the parameters, create the engagement, and start the pipeline.

    Only call this once you have a target_url and at least one in-scope domain
    that covers the target host. Returns the new engagement_id, or an "error"
    explaining what the entry guardrails rejected so you can ask the user to fix
    it.

    Args:
        target_url: Target base URL, e.g. "http://juice-shop:3000/".
        domains: In-scope hosts; must cover the target host.
        allow_paths: Optional path-prefix allowlist.
        deny_paths: Optional path-prefix denylist.
        starts_at: Optional ISO-8601 start of the permitted window.
        ends_at: Optional ISO-8601 end of the permitted window.
        categories: Optional test categories to emphasise (advisory only).
    """
    time_window = None
    if starts_at or ends_at:
        try:
            time_window = TimeWindow(starts_at=starts_at, ends_at=ends_at)
        except Exception as exc:  # noqa: BLE001 — bad timestamp from the model
            return {"error": f"invalid time_window: {exc}"}
    spec = EngagementSpec(
        target_url=target_url,
        scope=Scope(domains=domains or [], allow_paths=allow_paths or [],
                    deny_paths=deny_paths or []),
        time_window=time_window)

    try:
        spec = check_engagement_spec(spec)
    except GuardrailsEntryBlocked as exc:
        audit("orchestrator", "entry_rejected", detail={"reason": str(exc)})
        return {"error": f"guardrails rejected the engagement: {exc}"}

    engagement_id = uuid4()
    _create_engagement_row(engagement_id, spec)
    audit("orchestrator", "engagement_created",
          engagement_id=str(engagement_id), detail={"target_url": spec.target_url})
    trace.record_for(engagement_id, "orchestrator", "engagement_requested", {
        "target_url": spec.target_url,
        "scope": spec.scope.model_dump(mode="json"),
        "chain": CHAIN, "categories": categories or []})

    directive = ("Map the attack surface of the target: crawl it, record every "
                 "in-scope request, and triage which are worth testing.")
    if categories:
        directive += " Emphasise these test categories: " + ", ".join(categories) + "."
    handoff = ChainHandoff(
        engagement_id=engagement_id, from_component="orchestrator",
        target_url=spec.target_url, scope=spec.scope,
        time_window=spec.time_window, results={}, directive=directive)

    try:
        token = load_own_token()
        async with httpx.AsyncClient(
                verify=client_ssl_context(),
                timeout=httpx.Timeout(30.0, connect=5.0)) as client:
            resp = await client.post(
                "https://agent-recon:8443/run",
                content=handoff.model_dump_json(),
                headers=bearer_headers(token))
            resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 — surface the kickoff failure to the user
        trace.record_for(engagement_id, "orchestrator", "kickoff_failed",
                         {"agent": "recon", "error": str(exc)})
        return {"engagement_id": str(engagement_id), "status": "created",
                "error": f"engagement created but recon kickoff failed: {exc}"}

    trace.record_for(engagement_id, "orchestrator", "kickoff", {"agent": "recon"})
    return {"engagement_id": str(engagement_id), "status": "running",
            "message": "Engagement started; recon is running."}


async def engagement_status(engagement_id: str) -> dict[str, Any]:
    """Report the current status of an engagement and each stage.

    Returns the overall status, which stage is running now (current_agent), and a
    per-agent map of pending/running/completed/failed/skipped/cancelled."""
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    status = _status(eid)
    return status or {"error": f"no such engagement: {engagement_id}"}


async def stop_engagement(engagement_id: str) -> dict[str, Any]:
    """Cancel an engagement. Cooperative: the running stage finishes but the
    pipeline advances no further, and remaining stages are marked cancelled."""
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE engagements SET status='cancelled', completed_at=NOW() "
            "WHERE id=%s AND status='running' RETURNING id", (str(eid),))
        if cur.fetchone() is None:
            cur.execute("SELECT status FROM engagements WHERE id=%s", (str(eid),))
            row = cur.fetchone()
            if row is None:
                return {"error": f"no such engagement: {engagement_id}"}
            return {"engagement_id": str(eid), "status": row[0],
                    "message": f"engagement was already {row[0]}; nothing to stop"}
        cur.execute(
            "UPDATE engagement_state SET status='cancelled', updated_at=NOW() "
            "WHERE engagement_id=%s AND status IN ('pending','started','running')",
            (str(eid),))
    audit("orchestrator", "engagement_cancelled", engagement_id=str(eid))
    trace.record_for(eid, "orchestrator", "engagement_cancelled", {})
    return {"engagement_id": str(eid), "status": "cancelled",
            "message": "Engagement cancelled; no further stages will run."}


async def list_artifacts(engagement_id: str) -> dict[str, Any]:
    """List which stages have produced an artifact, newest first, with sizes."""
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT agent, char_length(payload::text), written_at "
            "FROM agent_results WHERE engagement_id=%s ORDER BY written_at",
            (str(eid),))
        rows = cur.fetchall()
    return {"engagement_id": str(eid),
            "artifacts": [{"agent": a, "size_chars": n, "written_at": str(w)}
                          for a, n, w in rows]}


async def get_artifact(engagement_id: str, agent: str) -> dict[str, Any]:
    """Fetch one stage's artifact for an engagement.

    Returns a short ``summary`` (member counts) plus the artifact itself, capped
    so a large result (e.g. exploit evidence) does not flood the conversation;
    ``truncated`` says whether the cap was hit.

    Args:
        engagement_id: The engagement's id.
        agent: The stage to read — one of recon, vuln, mitre, exploit, script, adviser.
    """
    eid = _uuid(engagement_id)
    if eid is None:
        return {"error": f"not a valid engagement id: {engagement_id!r}"}
    if agent not in CHAIN:
        return {"error": f"unknown stage {agent!r}; expected one of {CHAIN}"}
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT payload FROM agent_results WHERE engagement_id=%s AND agent=%s",
            (str(eid), agent))
        row = cur.fetchone()
    if row is None:
        return {"error": f"{agent} has produced no artifact yet for this engagement"}
    payload = row[0]
    summary = ", ".join(f"{len(v)} {k}" for k, v in payload.items()
                        if isinstance(v, (list, dict)) and v) or "empty artifact"
    text = json.dumps(payload, default=str)
    truncated = len(text) > ARTIFACT_CHARS
    # Full JSON object when it fits; otherwise a capped JSON string (the caller
    # gets the head of the artifact plus truncated=True rather than a huge blob).
    artifact: Any = payload if not truncated else text[:ARTIFACT_CHARS]
    return {"engagement_id": str(eid), "agent": agent, "summary": summary,
            "truncated": truncated, "artifact": artifact}


# --------------------------------------------------------------------------- #
# Registration + entry point (run in a daemon thread from orchestrator.main)
# --------------------------------------------------------------------------- #

def _register() -> list[str]:
    tools = {
        "apts_capabilities": ("Explain what APTS can do and which parameters an "
                              "engagement needs."),
        "create_engagement": ("Validate parameters, create the engagement, and "
                              "start the recon stage."),
        "engagement_status": "Report overall + per-stage status of an engagement.",
        "stop_engagement": "Cancel an engagement (cooperative stop).",
        "list_artifacts": "List which stages have produced an artifact.",
        "get_artifact": "Fetch one stage's artifact (summary + capped body).",
    }
    fns = {"apts_capabilities": apts_capabilities,
           "create_engagement": create_engagement,
           "engagement_status": engagement_status,
           "stop_engagement": stop_engagement,
           "list_artifacts": list_artifacts,
           "get_artifact": get_artifact}
    for name, desc in tools.items():
        control.tool(description=desc)(fns[name])
    return list(tools)


_registered = _register()


def serve(port: int | None = None) -> None:
    """Run the control MCP server (streamable-HTTP). Called in a daemon thread."""
    port = port or int(os.environ.get("APTS_CONTROL_MCP_PORT", "9100"))
    log.info("orchestrator control MCP server tools: %s", ", ".join(_registered))
    control.run(transport="streamable-http", host="0.0.0.0", port=port)
