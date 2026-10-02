"""Sandboxed script/command executor.

Runs in its own hardened container (docker-compose):
  * read-only root filesystem, a small ``/tmp`` tmpfs the only writable place,
  * no capabilities (``cap_drop: ALL``) and ``no-new-privileges``,
  * a hard memory + PID limit,
  * on the engagement networks only — ``apts-target`` (the internal, no-internet
    target net) plus ``apts-net`` for the audit DB. This is the isolation
    boundary the design reserves for running agent-written code.

This is the real executor the skeleton anticipated ("replace :func:`_execute`
when the modelling phase begins"). It runs one program per request:

  * **script mode** — ``language`` (python/bash) + ``source`` + ``args``: the
    source is written under ``/tmp`` and run with the interpreter; or
  * **command mode** — a raw ``command`` string run under ``bash -c`` (kept for
    the legacy mcp-tools SandboxService).

Every run is bounded by a wall-clock timeout and its output is capped. It is
still only reachable by the two components that drive tools — mcp-tools (the
REST facade) and mcp-native (the native MCP sandbox tool the Script agent uses).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, HTTPException

from shared import logging_config
from shared.auth import Caller, load_own_token, require_auth
from shared.db import audit
from shared.models import SandboxExecRequest, SandboxExecResult
from shared.tls import uvicorn_ssl_kwargs

logging_config.configure("sandbox")
log = logging.getLogger("sandbox")

# Only the tool-runners may drive the sandbox. mcp-native was added so the
# native MCP sandbox tool (the Script agent's proving loop) can reach it.
ALLOWED_CALLERS = {"mcp-tools", "mcp-native"}

WORK_DIR = "/tmp"
OUTPUT_CAP = 16000            # per stream (stdout, stderr), characters
MAX_TIMEOUT = 60             # seconds — hard ceiling regardless of the request
INTERPRETER = {"python": "python3", "bash": "bash"}
SUFFIX = {"python": ".py", "bash": ".sh"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    load_own_token()  # fail fast at startup if the token file isn't mounted
    log.info("sandbox executor ready")
    audit("sandbox", "startup")
    yield


app = FastAPI(title="APTS Sandbox", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def _cap(text: str) -> str:
    return text if len(text) <= OUTPUT_CAP else text[:OUTPUT_CAP] + "\n...[output truncated]"


async def _run(argv: list[str], timeout: int) -> tuple[int, str, str, bool, int]:
    """Run one process under a wall-clock timeout. Returns
    (exit_code, stdout, stderr, timed_out, duration_ms)."""
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *argv, cwd=WORK_DIR,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        raw_out, raw_err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        timed_out = False
    except asyncio.TimeoutError:
        proc.kill()
        raw_out, raw_err = await proc.communicate()
        timed_out = True
    duration_ms = int((time.monotonic() - start) * 1000)
    out = raw_out.decode("utf-8", "replace")
    err = raw_err.decode("utf-8", "replace")
    if timed_out:
        err = (err + f"\n[sandbox] killed after {timeout}s wall-clock timeout").strip()
    code = proc.returncode if proc.returncode is not None else -1
    return code, _cap(out), _cap(err), timed_out, duration_ms


def _build_argv(req: SandboxExecRequest) -> list[str]:
    """Materialise the request into an argv, writing script source to /tmp."""
    if req.language:
        interp = INTERPRETER[req.language]
        path = Path(WORK_DIR) / f"poc_{os.getpid()}_{int(time.time()*1000)}{SUFFIX[req.language]}"
        path.write_text(req.source, encoding="utf-8")
        return [interp, str(path), *[str(a) for a in req.args]]
    return ["bash", "-c", req.command]


@app.post("/exec", response_model=SandboxExecResult)
async def exec_command(req: SandboxExecRequest,
                       caller: Caller = Depends(require_auth)) -> SandboxExecResult:
    if caller.component not in ALLOWED_CALLERS:
        raise HTTPException(403,
            f"{caller.component!r} may not call the sandbox directly")
    if not req.language and not req.command.strip():
        raise HTTPException(422, "provide either language+source or a command")

    timeout = max(1, min(int(req.timeout_seconds or 20), MAX_TIMEOUT))
    argv = _build_argv(req)
    log.info("exec (%s) by %s: %s", req.language or "command", caller.component,
             (req.source or req.command)[:120].replace("\n", " "))

    try:
        code, stdout, stderr, timed_out, duration_ms = await _run(argv, timeout)
    except OSError as exc:  # interpreter missing, spawn failure
        return SandboxExecResult(ok=False, exit_code=-1, stdout="",
                                 stderr=f"[sandbox] failed to start: {exc}")

    audit("sandbox", "exec",
          engagement_id=str(req.engagement_id),
          detail={"language": req.language or "command",
                  "exit_code": code, "timed_out": timed_out,
                  "program": (req.source or req.command)[:200]})

    return SandboxExecResult(
        ok=(code == 0 and not timed_out), exit_code=code,
        stdout=stdout, stderr=stderr,
        timed_out=timed_out, duration_ms=duration_ms)


if __name__ == "__main__":
    uvicorn.run(
        "sandbox.main:app",
        host="0.0.0.0", port=8443,
        log_config=None,
        **uvicorn_ssl_kwargs(),
    )
