"""Placeholder for each agent's actual work.

Every agent's ``run`` background task will call :func:`do_stub_work` — it
sleeps briefly and returns a canned result shaped like what the real model
would produce.  When the modelling phase begins, only this file changes; the
transport, DB write, and chain handoff logic in ``agent/main.py`` stay put.

The important thing here is that the *shape* of the returned dict matches
what the next agent in the chain expects to receive.
"""
from __future__ import annotations

import asyncio
import logging
import random
from typing import Any

log = logging.getLogger("agent.stub_work")

# How long each agent pretends to work (seconds).  Kept short so end-to-end
# runs finish in ~30s during skeleton testing.
_STUB_DELAY = {
    "recon":   4,
    "vuln":    3,
    "mitre":   2,
    "exploit": 5,
    "script":  3,
    "adviser": 2,
}


async def do_stub_work(agent: str, incoming: dict[str, Any]) -> dict[str, Any]:
    """Return a canned result shaped like the real agent would produce."""
    delay = _STUB_DELAY.get(agent, 3)
    log.info("stub work for %s starting (delay=%ds)", agent, delay)
    await asyncio.sleep(delay)

    if agent == "recon":
        return {
            "recon_map": {
                "pages": ["/", "/login", "/api/users"],
                "technologies": ["nginx", "postgresql"],
                "forms":  [{"page": "/login", "fields": ["username", "password"]}],
            }
        }
    if agent == "vuln":
        return {
            "weaknesses": [
                {"id": "W-001", "page": "/login", "kind": "reflected-xss", "cvss": 6.1},
                {"id": "W-002", "page": "/api/users", "kind": "sql-injection", "cvss": 8.8},
            ]
        }
    if agent == "mitre":
        return {
            "attack_mapping": {
                "W-001": {"technique": "T1059.007", "goal": "execution"},
                "W-002": {"technique": "T1190",     "goal": "initial-access"},
            }
        }
    if agent == "exploit":
        return {
            "exploitation_evidence": [
                {"weakness_id": "W-001", "confirmed": True,
                 "request":  "GET /login?q=<script>...", "response": "reflected"},
                {"weakness_id": "W-002", "confirmed": False, "reason": "WAF blocked"},
            ]
        }
    if agent == "script":
        return {
            "scripts": [
                {"weakness_id": "W-001",
                 "script": "#!/usr/bin/env python3\n# reproduces reflected XSS\n..."}
            ]
        }
    if agent == "adviser":
        return {
            "report": {
                "summary": "1 confirmed weakness of high severity; 1 candidate blocked by WAF.",
                "findings": 2, "confirmed": 1, "recommendations": [
                    "Add output encoding on /login",
                    "Continue investigation on /api/users",
                ],
            }
        }
    return {"note": f"unknown agent {agent!r}"}


async def maybe_fail(probability: float = 0.0) -> None:
    """Sprinkle synthetic failures into the run for testing the retry path."""
    if probability > 0 and random.random() < probability:
        raise RuntimeError("synthetic failure (APTS_STUB_FAILURE_RATE)")
