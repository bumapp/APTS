"""Working agent service.

One image, six containers.  The container's ``AGENT_NAME`` environment variable
selects which agent this instance behaves as (``recon``, ``vuln``, ``mitre``,
``exploit``, ``script``, ``adviser``).

The service exposes exactly one working endpoint and one health probe:

* ``POST /run`` — receive a :class:`ChainHandoff`, acknowledge immediately,
  then run the agent's work in a background task.  The background task:

  1. posts ``progress = started`` to the orchestrator,
  2. calls :func:`agent.stub_work.do_stub_work` (this is what the model call
     will replace),
  3. writes the result to the ``agent_results`` table,
  4. pushes the same result to the next agent in the chain (unless this is
     the Adviser),
  5. posts ``progress = done`` to the orchestrator.

Every outbound HTTP call is TLS + bearer token.
"""
from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from uuid import UUID

import httpx
import psycopg
import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException

from shared import logging_config
from shared.auth import Caller, bearer_headers, load_own_token, require_auth
from shared.db import audit, get_conn
from shared.models import ChainHandoff, HandoffAck, ProgressUpdate
from shared.tls import client_ssl_context, uvicorn_ssl_kwargs

from agent.stub_work import do_stub_work, maybe_fail

AGENT_NAME = os.environ.get("AGENT_NAME")
if not AGENT_NAME:
    raise RuntimeError("AGENT_NAME environment variable is required")

logging_config.configure(f"agent-{AGENT_NAME}")
log = logging.getLogger(f"agent.{AGENT_NAME}")

CHAIN = ["recon", "vuln", "mitre", "exploit", "script", "adviser"]
if AGENT_NAME not in CHAIN:
    raise RuntimeError(f"unknown AGENT_NAME {AGENT_NAME!r} (must be one of {CHAIN})")

NEXT_AGENT: str | None = (
    CHAIN[CHAIN.index(AGENT_NAME) + 1] if CHAIN.index(AGENT_NAME) < len(CHAIN) - 1 else None
)

ORCHESTRATOR_URL = "https://orchestrator:8443"
FAILURE_RATE = float(os.environ.get("APTS_STUB_FAILURE_RATE", "0"))

_OWN_TOKEN: str | None = None
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
    log.info("agent %s ready (next=%s)", AGENT_NAME, NEXT_AGENT)
    audit(f"agent-{AGENT_NAME}", "startup")
    try:
        yield
    finally:
        await _client.aclose()
        audit(f"agent-{AGENT_NAME}", "shutdown")


app = FastAPI(title=f"APTS Agent — {AGENT_NAME}", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "agent": AGENT_NAME}


def _allowed_callers() -> set[str]:
    """Who is permitted to POST /run on this agent.

    * Recon accepts kickoffs from the orchestrator and retries from the orchestrator.
    * Every other agent accepts the push from its predecessor in the chain.
    * The orchestrator can also call any agent directly, for retries.
    """
    if AGENT_NAME == "recon":
        return {"orchestrator"}
    idx = CHAIN.index(AGENT_NAME)
    predecessor = CHAIN[idx - 1]
    return {f"agent-{predecessor}", "orchestrator"}


@app.post("/run", response_model=HandoffAck)
async def run(handoff: ChainHandoff,
              background: BackgroundTasks,
              caller: Caller = Depends(require_auth)) -> HandoffAck:
    allowed = _allowed_callers()
    if caller.component not in allowed:
        raise HTTPException(403, f"{caller.component!r} may not call /run on {AGENT_NAME}")

    log.info("received handoff for engagement %s from %s",
             handoff.engagement_id, caller.component)
    audit(f"agent-{AGENT_NAME}", "handoff_received",
          engagement_id=str(handoff.engagement_id),
          detail={"from": caller.component})

    background.add_task(_perform_work, handoff)
    return HandoffAck(engagement_id=handoff.engagement_id,
                      accepted_by=f"agent-{AGENT_NAME}",
                      started_at=datetime.utcnow())


# --------------------------------------------------------------------------- #
# Background work: the actual chain step
# --------------------------------------------------------------------------- #

async def _perform_work(handoff: ChainHandoff) -> None:
    engagement_id = handoff.engagement_id
    try:
        await _post_progress(engagement_id, "started", "beginning work")
        await maybe_fail(FAILURE_RATE)
        result = await do_stub_work(AGENT_NAME, handoff.model_dump(mode="json"))
        _write_result(engagement_id, result)

        if NEXT_AGENT is not None:
            await _push_to_next(engagement_id, handoff, result)

        await _post_progress(engagement_id, "done", "work complete",
                             detail={"has_result": True})
    except Exception as exc:
        log.exception("work failed: %s", exc)
        await _post_progress(engagement_id, "failed", str(exc))


def _write_result(engagement_id: UUID, payload: dict[str, Any]) -> None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO agent_results (engagement_id, agent, payload)
               VALUES (%s, %s, %s::jsonb)
               ON CONFLICT (engagement_id, agent)
               DO UPDATE SET payload = EXCLUDED.payload, written_at = NOW()""",
            (str(engagement_id), AGENT_NAME, psycopg.types.json.Json(payload)),
        )
    audit(f"agent-{AGENT_NAME}", "result_written", engagement_id=str(engagement_id))


async def _push_to_next(engagement_id: UUID, incoming: ChainHandoff,
                        result: dict[str, Any]) -> None:
    assert NEXT_AGENT is not None
    assert _client is not None
    assert _OWN_TOKEN is not None
    next_handoff = ChainHandoff(
        engagement_id=engagement_id,
        from_component=f"agent-{AGENT_NAME}",
        target_url=incoming.target_url,
        scope=incoming.scope,
        time_window=incoming.time_window,
        results=result,
    )
    url = f"https://agent-{NEXT_AGENT}:8443/run"
    resp = await _client.post(url, content=next_handoff.model_dump_json(),
                              headers=bearer_headers(_OWN_TOKEN))
    resp.raise_for_status()
    log.info("pushed result to %s", NEXT_AGENT)
    audit(f"agent-{AGENT_NAME}", "pushed_to_next",
          engagement_id=str(engagement_id), detail={"next": NEXT_AGENT})


async def _post_progress(engagement_id: UUID, status: str, message: str = "",
                         detail: dict | None = None) -> None:
    assert _client is not None
    assert _OWN_TOKEN is not None
    update = ProgressUpdate(engagement_id=engagement_id, agent=AGENT_NAME,
                            status=status, message=message, detail=detail or {})
    try:
        resp = await _client.post(
            f"{ORCHESTRATOR_URL}/progress",
            content=update.model_dump_json(),
            headers=bearer_headers(_OWN_TOKEN),
        )
        resp.raise_for_status()
    except Exception as exc:
        log.error("progress post failed (%s): %s", status, exc)


# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    uvicorn.run(
        "agent.main:app",
        host="0.0.0.0", port=8443,
        log_config=None,
        **uvicorn_ssl_kwargs(),
    )
