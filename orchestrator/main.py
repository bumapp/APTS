"""Orchestrator service.

Runs two servers side-by-side:

* the **public** HTTPS server on port 8443 receives ``POST /progress`` updates
  from every agent and exposes read-only ``GET /engagements/<id>`` for status
  checks.  Every request is bearer-token authenticated against the DB.

* the **admin** HTTP server on port 8080 is bound to the container's loopback
  interface only.  It backs the operator CLI: ``POST /engagements/start`` to
  kick off a run and ``GET /engagements/<id>`` to inspect one.  Because the
  admin socket is reachable only from inside this container, no token is
  required for it.

Retry logic.
  When an agent posts ``status="failed"`` the orchestrator increments the
  retry counter for that agent and — if it is under the limit — re-launches it
  with the *previous* agent's stored output pulled from the database.
  Per §2.2.4, critical agents (recon, vuln) stop the whole engagement after
  three failed attempts. Minor agents (mitre, script, adviser) let the chain
  continue with whatever partial results are already stored. Exploitation is
  minor-but-special: a failure doesn't stop the run, but the Adviser must
  mark the report "weaknesses found but not confirmed."
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

import httpx
import psycopg
import uvicorn
from fastapi import Depends, FastAPI, HTTPException

from shared import logging_config, pipeline, trace
from shared.auth import Caller, bearer_headers, load_own_token, require_auth
from shared.db import audit, get_conn
from shared.models import (
    ChainHandoff,
    EngagementSpec,
    EngagementStatus,
    ProgressAck,
    ProgressUpdate,
    StartEngagementResponse,
)
from shared.tls import client_ssl_context, uvicorn_ssl_kwargs

from orchestrator.guardrails_entry import (
    GuardrailsEntryBlocked,
    check_engagement_spec,
)

logging_config.configure("orchestrator")
log = logging.getLogger("orchestrator")

# Stage order, criticality, and retry budget all live in shared.pipeline so the
# orchestrator and the agents cannot disagree about the shape of the chain.
CHAIN = list(pipeline.CHAIN)
CRITICAL_AGENTS = pipeline.CRITICAL_AGENTS
MAX_RETRIES = pipeline.MAX_RETRIES

# When on, the orchestrator drives the pipeline: agents report ``done`` and the
# orchestrator decides the next stage and dispatches it with a generated
# directive. Must match the agents' APTS_ORCHESTRATOR_DRIVEN, or the chain either
# stalls (agents wait, orchestrator idle) or double-runs (both advance). Off
# restores the original agent self-chaining. Default on.
ORCHESTRATOR_DRIVEN = os.environ.get("APTS_ORCHESTRATOR_DRIVEN", "1") == "1"

# One-line brief for each stage, used to compose the directive handed to it.
_STAGE_JOB = {
    "vuln": "Assess each recon request and hypothesise concrete, testable web "
            "weaknesses — pursue anything imaginable.",
    "mitre": "Map each weakness to the MITRE ATT&CK technique(s) it corresponds to.",
    "exploit": "Prove or disprove each weakness against the live target using "
               "your tools; confirm only on a real tool signal.",
    "script": "Write and sandbox-test a proof-of-concept script for each "
              "confirmed weakness.",
    "adviser": "Produce the client report: group duplicates, keep only proven "
               "findings, and rank by impact.",
}

# We hold the orchestrator's own token in memory once, at startup.
_OWN_TOKEN: str | None = None

# One shared HTTP client — TLS context configured once, reused across all
# outbound calls.
_client: httpx.AsyncClient | None = None


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _OWN_TOKEN, _client
    _OWN_TOKEN = load_own_token()
    _client = httpx.AsyncClient(
        verify=client_ssl_context(),
        timeout=httpx.Timeout(30.0, connect=5.0),
    )
    log.info("orchestrator ready (chain=%s)", CHAIN)
    audit("orchestrator", "startup")
    try:
        yield
    finally:
        await _client.aclose()
        audit("orchestrator", "shutdown")


app = FastAPI(title="APTS Orchestrator", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Public HTTPS API (port 8443, token-authenticated)
# --------------------------------------------------------------------------- #

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/progress", response_model=ProgressAck)
async def progress(update: ProgressUpdate, caller: Caller = Depends(require_auth)):
    """Every agent posts its progress here.

    The caller must be the exact agent it claims to be reporting on — a valid
    token for one agent must not be able to post status updates (including
    a fake "adviser done") on behalf of another agent.
    """
    expected_component = f"agent-{update.agent}"
    if caller.component != expected_component:
        raise HTTPException(
            403,
            f"{caller.component!r} may not post progress as {update.agent!r}",
        )

    _record_progress(update)

    # If an agent explicitly reports failure, decide whether to retry it.
    if update.status == "failed":
        await _handle_agent_failure(update)

    # A stage finished cleanly. In orchestrator-driven mode this is our cue to
    # decide the next stage and dispatch it; in agent-driven mode the agent has
    # already handed off, so we only note terminal completion.
    if update.status == "done":
        if ORCHESTRATOR_DRIVEN and pipeline.next_agent(update.agent) is not None:
            await _advance_after(update)

    # If the Adviser reports done, the engagement is complete.
    if update.agent == "adviser" and update.status == "done":
        _mark_engagement_complete(update.engagement_id)

    return ProgressAck()


@app.get("/engagements/{engagement_id}", response_model=EngagementStatus)
def read_engagement(engagement_id: UUID, caller: Caller = Depends(require_auth)) -> EngagementStatus:
    return _read_status(engagement_id)


# --------------------------------------------------------------------------- #
# Admin HTTP API (port 8080, loopback-only; used by orchestrator/cli.py)
# --------------------------------------------------------------------------- #

admin = FastAPI(title="APTS Orchestrator (admin)")


@admin.get("/health")
def admin_health() -> dict[str, str]:
    return {"status": "ok"}


@admin.post("/engagements/start", response_model=StartEngagementResponse)
async def admin_start(spec: EngagementSpec) -> StartEngagementResponse:
    """Called by the operator CLI to kick off an engagement."""
    try:
        spec = check_engagement_spec(spec)
    except GuardrailsEntryBlocked as exc:
        audit("orchestrator", "entry_rejected", detail={"reason": str(exc)})
        raise HTTPException(400, f"guardrails entry: {exc}")

    engagement_id = uuid4()
    _create_engagement_row(engagement_id, spec)
    audit("orchestrator", "engagement_created",
          engagement_id=str(engagement_id), detail={"target_url": spec.target_url})

    # The first row of the flow file: the request, exactly as accepted. Recorded
    # after the engagement row exists, because agent_trace has a foreign key to
    # it. A spec rejected at the entry checkpoint never gets an engagement ID and
    # so has no trace — that rejection lives in audit_log alone.
    trace.record_for(engagement_id, "orchestrator", "engagement_requested", {
        "target_url": spec.target_url,
        "scope": spec.scope.model_dump(mode="json"),
        "time_window": spec.time_window.model_dump(mode="json") if spec.time_window else {},
        "chain": CHAIN,
    })

    handoff = ChainHandoff(
        engagement_id=engagement_id,
        from_component="orchestrator",
        target_url=spec.target_url,
        scope=spec.scope,
        time_window=spec.time_window,
        results={},
        directive=("Map the attack surface of the target: crawl it, record every "
                   "in-scope request, and triage which are worth testing."),
    )

    await _kickoff_agent("recon", handoff)
    return StartEngagementResponse(engagement_id=engagement_id, status="running")


@admin.get("/engagements/{engagement_id}", response_model=EngagementStatus)
def admin_read(engagement_id: UUID) -> EngagementStatus:
    return _read_status(engagement_id)


# --------------------------------------------------------------------------- #
# DB helpers
# --------------------------------------------------------------------------- #

def _create_engagement_row(engagement_id: UUID, spec: EngagementSpec) -> None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO engagements (id, target_url, scope, time_window, status)
               VALUES (%s, %s, %s::jsonb, %s::jsonb, 'running')""",
            (str(engagement_id), spec.target_url,
             psycopg.types.json.Json(spec.scope.model_dump()),
             psycopg.types.json.Json(spec.time_window.model_dump() if spec.time_window else {})),
        )
        # Seed the per-agent state rows so retries have something to increment
        for agent in CHAIN:
            cur.execute(
                """INSERT INTO engagement_state (engagement_id, agent, status)
                   VALUES (%s, %s, 'pending')""",
                (str(engagement_id), agent),
            )


def _record_progress(update: ProgressUpdate) -> None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE engagement_state SET status = %s, updated_at = NOW(),
               last_error = CASE WHEN %s = 'failed' THEN %s ELSE last_error END
               WHERE engagement_id = %s AND agent = %s""",
            (update.status, update.status, update.message,
             str(update.engagement_id), update.agent),
        )
    audit("orchestrator", "progress_received",
          engagement_id=str(update.engagement_id),
          detail={"agent": update.agent, "status": update.status, "message": update.message})


def _mark_engagement_complete(engagement_id: UUID) -> None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE engagements SET status = 'complete', completed_at = NOW()
               WHERE id = %s""",
            (str(engagement_id),),
        )
    log.info("engagement %s complete", engagement_id)
    audit("orchestrator", "engagement_complete", engagement_id=str(engagement_id))
    trace.record_for(engagement_id, "orchestrator", "engagement_complete")


def _read_status(engagement_id: UUID) -> EngagementStatus:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT target_url, status, created_at, completed_at FROM engagements WHERE id = %s",
            (str(engagement_id),),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "no such engagement")
        target_url, status, started_at, completed_at = row

        cur.execute(
            """SELECT agent, status, retry_count, last_error
               FROM engagement_state WHERE engagement_id = %s""",
            (str(engagement_id),),
        )
        per_agent = {
            agent: {"status": st, "retry_count": rc, "last_error": err}
            for agent, st, rc, err in cur.fetchall()
        }

    return EngagementStatus(
        engagement_id=engagement_id, target_url=target_url, status=status,
        per_agent=per_agent, started_at=started_at, completed_at=completed_at,
    )


# --------------------------------------------------------------------------- #
# Retry logic (§2.2.4)
# --------------------------------------------------------------------------- #

async def _handle_agent_failure(update: ProgressUpdate) -> None:
    agent = update.agent
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE engagement_state SET retry_count = retry_count + 1
               WHERE engagement_id = %s AND agent = %s
               RETURNING retry_count""",
            (str(update.engagement_id), agent),
        )
        (retry_count,) = cur.fetchone()

    if retry_count > MAX_RETRIES:
        log.error("%s exhausted retries (%d) for engagement %s",
                  agent, MAX_RETRIES, update.engagement_id)
        audit("orchestrator", "retries_exhausted",
              engagement_id=str(update.engagement_id),
              detail={"agent": agent, "retry_count": retry_count})
        if agent in CRITICAL_AGENTS:
            _mark_engagement_failed(update.engagement_id, reason=f"{agent} failed 3 times")
        return

    # Re-launch this agent with the *previous* stage's stored output
    prev_agent = _previous_agent(agent)
    payload = _load_prev_output(update.engagement_id, prev_agent)

    handoff = ChainHandoff(
        engagement_id=update.engagement_id,
        from_component="orchestrator",
        target_url=payload["target_url"],
        scope=payload["scope"],
        time_window=payload.get("time_window"),
        results=payload.get("results", {}),
        directive=_directive_for(agent, prev_agent or "orchestrator",
                                 payload.get("results", {})),
    )
    log.info("retry #%d for agent %s (engagement %s)", retry_count, agent, update.engagement_id)
    audit("orchestrator", "retry_launched",
          engagement_id=str(update.engagement_id),
          detail={"agent": agent, "attempt": retry_count})
    trace.record_for(update.engagement_id, "orchestrator", "retry_launched",
                     {"agent": agent, "attempt": retry_count,
                      "reason": update.message,
                      "replayed_from": prev_agent or "(engagement spec)"})
    await _kickoff_agent(agent, handoff)


def _previous_agent(agent: str) -> str | None:
    return pipeline.previous_agent(agent)


# --------------------------------------------------------------------------- #
# Orchestrator-driven advancement
# --------------------------------------------------------------------------- #

def _engagement_status(engagement_id: UUID) -> str | None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT status FROM engagements WHERE id = %s",
                    (str(engagement_id),))
        row = cur.fetchone()
    return row[0] if row else None


def _summarise_payload(payload: dict[str, Any]) -> str:
    """A short line about what a stage produced — counts its list/dict members."""
    if not isinstance(payload, dict):
        return "a result"
    parts = [f"{len(v)} {k}" for k, v in payload.items()
             if isinstance(v, (list, dict)) and v]
    return ", ".join(parts[:5]) or "a result"


def _directive_for(successor: str, prev_agent: str, prev_payload: dict) -> str:
    """Compose the next stage's start prompt from the finished stage's output.

    Deterministic template today; the Composer will replace this with an
    LLM-generated directive later, flowing through the same field."""
    return (f"The {prev_agent} stage produced: {_summarise_payload(prev_payload)}. "
            f"{_STAGE_JOB.get(successor, 'Continue the pipeline.')}")


async def _advance_after(update: ProgressUpdate) -> None:
    """A stage reported ``done``; dispatch the next stage with a directive."""
    agent = update.agent
    successor = pipeline.next_agent(agent)
    if successor is None:
        return  # terminal stage; completion is handled by the caller

    # Do not advance an engagement the operator stopped or that already ended.
    status = _engagement_status(update.engagement_id)
    if status != "running":
        log.info("not advancing %s -> %s: engagement %s is %s",
                 agent, successor, update.engagement_id, status)
        return

    payload = _load_prev_output(update.engagement_id, agent)
    results = payload.get("results", {}) or {}
    directive = _directive_for(successor, agent, results)
    handoff = ChainHandoff(
        engagement_id=update.engagement_id,
        from_component="orchestrator",
        target_url=payload["target_url"],
        scope=payload["scope"],
        time_window=payload.get("time_window"),
        results=results,
        directive=directive,
    )
    log.info("advancing %s -> %s (engagement %s)", agent, successor,
             update.engagement_id)
    trace.record_for(update.engagement_id, "orchestrator", "advance",
                     {"from": agent, "to": successor, "directive": directive})
    await _kickoff_agent(successor, handoff)


def _load_prev_output(engagement_id: UUID, prev_agent: str | None) -> dict[str, Any]:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT target_url, scope, time_window FROM engagements WHERE id = %s",
            (str(engagement_id),),
        )
        target_url, scope, time_window = cur.fetchone()
        payload: dict[str, Any] = {
            "target_url": target_url,
            "scope": scope,
            "time_window": time_window,
            "results": {},
        }
        if prev_agent is not None:
            cur.execute(
                "SELECT payload FROM agent_results WHERE engagement_id = %s AND agent = %s",
                (str(engagement_id), prev_agent),
            )
            row = cur.fetchone()
            if row is not None:
                payload["results"] = row[0]
    return payload


def _mark_engagement_failed(engagement_id: UUID, reason: str) -> None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE engagements SET status = 'failed', completed_at = NOW()
               WHERE id = %s""",
            (str(engagement_id),),
        )
    log.error("engagement %s failed: %s", engagement_id, reason)
    audit("orchestrator", "engagement_failed",
          engagement_id=str(engagement_id), detail={"reason": reason})
    trace.record_for(engagement_id, "orchestrator", "engagement_failed",
                     {"reason": reason})


# --------------------------------------------------------------------------- #
# Kickoff HTTP call
# --------------------------------------------------------------------------- #

async def _kickoff_agent(agent: str, handoff: ChainHandoff) -> None:
    assert _client is not None
    assert _OWN_TOKEN is not None
    url = f"https://agent-{agent}:8443/run"
    try:
        resp = await _client.post(
            url,
            content=handoff.model_dump_json(),
            headers=bearer_headers(_OWN_TOKEN),
        )
        resp.raise_for_status()
        trace.record_for(handoff.engagement_id, "orchestrator", "kickoff",
                         {"agent": agent, "url": url})
    except Exception as exc:
        log.error("failed to kick off %s: %s", agent, exc)
        audit("orchestrator", "kickoff_failed",
              engagement_id=str(handoff.engagement_id),
              detail={"agent": agent, "error": str(exc)})
        trace.record_for(handoff.engagement_id, "orchestrator", "kickoff_failed",
                         {"agent": agent, "url": url, "error": str(exc)})
        # We don't retry the kickoff itself here; the failure will surface when
        # the agent's status stays 'pending'.  Stall detection is a TODO.
        raise


# --------------------------------------------------------------------------- #
# Entry point (runs both servers)
# --------------------------------------------------------------------------- #

def _run_public() -> None:
    uvicorn.run(
        "orchestrator.main:app",
        host="0.0.0.0", port=8443,
        log_config=None,
        **uvicorn_ssl_kwargs(),
    )


def _run_admin() -> None:
    uvicorn.run(
        "orchestrator.main:admin",
        host="127.0.0.1", port=8080,
        log_config=None,
    )


if __name__ == "__main__":
    # Run the servers in the same process using a small threading harness:
    # the admin API, the native-MCP control server (the Composer's interface),
    # and the public API on the main thread.
    import threading
    threading.Thread(target=_run_admin, name="admin", daemon=True).start()

    from orchestrator import mcp_control
    threading.Thread(target=mcp_control.serve, name="control-mcp", daemon=True).start()

    from orchestrator import composer
    threading.Thread(target=composer.serve, name="composer", daemon=True).start()

    _run_public()
