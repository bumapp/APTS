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
  Per §2.2.4, critical agents (recon, vuln, exploit) stop the whole engagement
  after three failed attempts; minor agents (mitre, script, adviser) let the
  chain continue with whatever partial results are already stored.
"""
from __future__ import annotations

import asyncio
import logging
import os
import ssl
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import psycopg
import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from shared import logging_config
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

CHAIN = ["recon", "vuln", "mitre", "exploit", "script", "adviser"]
CRITICAL_AGENTS = {"recon", "vuln", "exploit"}
MAX_RETRIES = 3

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
    """Every agent posts its progress here."""
    # Optional: caller.component should match an agent-* identity
    if not caller.component.startswith("agent-"):
        raise HTTPException(403, f"{caller.component!r} may not post progress")

    _record_progress(update)

    # If an agent explicitly reports failure, decide whether to retry it.
    if update.status == "failed":
        await _handle_agent_failure(update)

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

    handoff = ChainHandoff(
        engagement_id=engagement_id,
        from_component="orchestrator",
        target_url=spec.target_url,
        scope=spec.scope,
        time_window=spec.time_window,
        results={},
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
    )
    log.info("retry #%d for agent %s (engagement %s)", retry_count, agent, update.engagement_id)
    audit("orchestrator", "retry_launched",
          engagement_id=str(update.engagement_id),
          detail={"agent": agent, "attempt": retry_count})
    await _kickoff_agent(agent, handoff)


def _previous_agent(agent: str) -> str | None:
    idx = CHAIN.index(agent)
    return CHAIN[idx - 1] if idx > 0 else None


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
    except Exception as exc:
        log.error("failed to kick off %s: %s", agent, exc)
        audit("orchestrator", "kickoff_failed",
              engagement_id=str(handoff.engagement_id),
              detail={"agent": agent, "error": str(exc)})
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
    # Run both servers in the same process using a small threading harness.
    import threading
    t = threading.Thread(target=_run_admin, name="admin", daemon=True)
    t.start()
    _run_public()
