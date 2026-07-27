"""Sandboxed-shell stub.

Runs in its own hardened container with:
  * no host network,
  * read-only root filesystem,
  * no capabilities,
  * a hard memory + PID limit.

**This is a stub** — it does not actually execute the incoming command.  When
the modelling phase begins, replace :func:`_execute` with a real, constrained
command executor (subprocess + resource limits + syscall filter).  Keeping the
skeleton non-executing avoids the risk of an untested prompt from an agent
running an unintended command.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, HTTPException

from shared import logging_config
from shared.auth import Caller, load_own_token, require_auth
from shared.db import audit
from shared.models import SandboxExecRequest, SandboxExecResult
from shared.tls import uvicorn_ssl_kwargs

logging_config.configure("sandbox")
log = logging.getLogger("sandbox")


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_own_token()  # fail fast at startup if the token file isn't mounted
    log.info("sandbox stub ready")
    audit("sandbox", "startup")
    yield


app = FastAPI(title="APTS Sandbox (stub)", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/exec", response_model=SandboxExecResult)
async def exec_command(req: SandboxExecRequest,
                       caller: Caller = Depends(require_auth)) -> SandboxExecResult:
    if caller.component != "mcp-tools":
        raise HTTPException(403,
            f"{caller.component!r} may not call the sandbox directly")

    log.info("would execute: %r", req.command)
    audit("sandbox", "exec_stubbed",
          engagement_id=str(req.engagement_id),
          detail={"command": req.command[:200]})

    return SandboxExecResult(
        ok=True, exit_code=0,
        stdout=f"[skeleton] would have run: {req.command}\n",
        stderr="",
    )


if __name__ == "__main__":
    uvicorn.run(
        "sandbox.main:app",
        host="0.0.0.0", port=8443,
        log_config=None,
        **uvicorn_ssl_kwargs(),
    )
