"""sandbox_run — write a script, run it in the hardened sandbox, read what it did.

This is the Script agent's one proving tool. The model sends a whole Python or
Bash program; it is executed in the locked-down sandbox container (read-only
root, no capabilities, memory/PID limits, a wall-clock timeout, reachable only
by the two tool-runners). The tool returns exit code, stdout, and stderr, plus a
short ``guidance`` line that tells the model what to do next — so a script that
errors is a prompt to debug and re-run, not a dead end.

The sandbox is on the internal engagement network, so a PoC can make real
requests to the target (e.g. http://juice-shop:3000/); it has no route to the
internet from that side. mcp-native authenticates to the sandbox with its own
bearer token and verifies the sandbox's TLS cert against the trust bundle.
"""
from __future__ import annotations

import os
from typing import Any
from uuid import uuid4

import httpx

from shared.models import SandboxExecRequest
from shared.tls import client_ssl_context

SANDBOX_URL = os.environ.get("APTS_SANDBOX_URL", "https://sandbox:8443").rstrip("/")


def _own_token() -> str:
    """This container's bearer token from its mounted secret. Inlined (not from
    shared.auth) because that module pulls in FastAPI, which the mcp-native image
    does not install."""
    path = os.environ.get("APTS_TOKEN_FILE", "/run/secrets/token")
    with open(path, encoding="utf-8") as fh:
        token = fh.read().strip()
    if not token:
        raise OSError(f"token file {path!r} is empty")
    return token


def _guidance(result: dict) -> str:
    """One coaching line: what the model should do with this run."""
    if result.get("timed_out"):
        return ("The script hit the time limit — it likely hangs or waits on "
                "something. Add a timeout to any network call, print progress, "
                "and run it again.")
    if not result.get("ok"):
        stderr = (result.get("stderr") or "").strip()
        last = stderr.splitlines()[-1] if stderr else f"exit code {result.get('exit_code')}"
        return (f"The script FAILED: {last}. Read the full stderr above, fix the "
                f"cause in the source, and call sandbox_run again with the "
                f"corrected script. Do not give up on a fixable error.")
    if not (result.get("stdout") or "").strip():
        return ("The script ran cleanly but printed nothing, so it does not yet "
                "PROVE anything. Add prints that show the vulnerability firing "
                "(the injected value reflected, the row leaked, the auth bypass) "
                "and run it again.")
    return ("The script ran and produced output. If that output clearly "
            "demonstrates the weakness, you are done — reply without a tool call. "
            "If it is ambiguous, strengthen the proof and run once more.")


async def sandbox_run(
    language: str,
    source: str,
    args: list[str] | None = None,
    timeout_seconds: int = 20,
) -> dict[str, Any]:
    """Run a Python or Bash script in the isolated sandbox and return its output.

    Use this to WRITE and TEST a proof-of-concept script for a confirmed
    weakness: send the whole program, read the result, and if it errors or does
    not clearly prove the flaw, fix the source and call this again.

    Args:
        language: "python" (has the ``requests`` and ``httpx`` libraries) or
            "bash" (has ``curl``). The script runs from /tmp.
        source: The complete script to run. Read the target base URL from
            argv[1] if you pass one in ``args``; otherwise hardcode the in-scope
            target (e.g. http://juice-shop:3000).
        args: Optional command-line arguments passed to the script as argv[1:].
        timeout_seconds: Wall-clock limit (1-60). The run is killed past it.
    """
    lang = (language or "").lower().strip()
    if lang not in ("python", "bash"):
        return {"error": f"language must be 'python' or 'bash', got {language!r}",
                "guidance": "Call sandbox_run again with language 'python' or 'bash'."}
    if not (source or "").strip():
        return {"error": "source is empty",
                "guidance": "Write the full script in 'source' and call again."}

    payload = SandboxExecRequest(
        engagement_id=uuid4(), language=lang, source=source,
        args=[str(a) for a in (args or [])],
        timeout_seconds=int(timeout_seconds or 20))

    try:
        token = _own_token()
    except OSError as exc:
        return {"error": f"sandbox auth unavailable: {exc}",
                "guidance": "The sandbox tool is misconfigured; report this and stop."}

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(verify=client_ssl_context(),
                                     timeout=float(payload.timeout_seconds) + 15) as client:
            resp = await client.post(f"{SANDBOX_URL}/exec",
                                     content=payload.model_dump_json(),
                                     headers=headers)
            resp.raise_for_status()
            result = resp.json()
    except httpx.HTTPError as exc:
        body = getattr(getattr(exc, "response", None), "text", "") or ""
        return {"error": f"sandbox call failed: {exc} {body[:300]}",
                "guidance": "The sandbox could not be reached; report this and stop."}

    result["language"] = lang
    result["guidance"] = _guidance(result)
    return result


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Run a Python or Bash script in an isolated, locked-down sandbox and get "
        "back its exit code, stdout, and stderr. Use it to WRITE and TEST a "
        "proof-of-concept: send the whole script, read the result, and if it "
        "errors or does not clearly prove the weakness, fix the source and call "
        "again. The sandbox can reach the in-scope target (e.g. "
        "http://juice-shop:3000) but not the internet. Python has requests and "
        "httpx; Bash has curl."
    ))(sandbox_run)
    return ["sandbox_run"]
