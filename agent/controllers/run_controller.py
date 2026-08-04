"""The agent's HTTP surface: a health probe and the stage trigger."""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request

from shared.auth import Caller, require_auth
from shared.models import ChainHandoff, HandoffAck
from shared.pipeline import previous_agent

from agent.config import AGENT_NAME, COMPONENT
from agent.providers.run_provider import RunProvider

log = logging.getLogger("agent.controllers.run")

router = APIRouter()


def get_run_provider(request: Request) -> RunProvider:
    return request.app.state.run_provider


def allowed_callers() -> set[str]:
    """Who may trigger this stage.

    The orchestrator, always — it owns kickoff and every retry. Plus this
    stage's immediate predecessor, which pushes the artifact directly.

    That predecessor allowance is what PRD §4.1 actually forbids: it lets a
    result reach the next stage without passing the orchestrator, so the
    output-schema Guardrails checkpoint never sees it. Closing it means routing
    handoffs through the store, which is a change to the orchestrator, not to
    this line.
    """
    predecessor = previous_agent(AGENT_NAME)
    callers = {"orchestrator"}
    if predecessor is not None:
        callers.add(f"agent-{predecessor}")
    return callers


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "agent": AGENT_NAME}


@router.post("/run", response_model=HandoffAck)
async def run(handoff: ChainHandoff, background: BackgroundTasks,
              caller: Caller = Depends(require_auth),
              provider: RunProvider = Depends(get_run_provider)) -> HandoffAck:
    """Accept a stage handoff and run it in the background.

    Acknowledges immediately rather than holding the connection open for the
    length of the stage — a real Recon sweep runs for minutes, and the caller
    tracks progress through the orchestrator, not through this response.
    """
    if caller.component not in allowed_callers():
        raise HTTPException(
            403, f"{caller.component!r} may not call /run on {AGENT_NAME}")

    log.info("received handoff for engagement %s from %s",
             handoff.engagement_id, caller.component)

    background.add_task(provider.run, handoff)
    return HandoffAck(engagement_id=handoff.engagement_id,
                      accepted_by=COMPONENT,
                      started_at=datetime.utcnow())
