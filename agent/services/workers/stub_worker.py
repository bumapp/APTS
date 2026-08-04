"""Canned artifacts for the five stages that have no model yet.

Each returns a result of roughly the right shape so the pipeline runs end to
end. They are placeholders and are labelled as such at runtime — an artifact
carrying ``"stub": true`` must never be mistaken for a real finding in a report.

As each stage gets a real implementation it moves out of this file into its own
worker module, the way ``mitre_worker`` already has.
"""
from __future__ import annotations

import asyncio
import logging
import random
from typing import Any

from agent.services.workers.base import WorkContext

log = logging.getLogger("agent.workers.stub")

# How long each stage pretends to work, so an end-to-end run is observable
# rather than instantaneous.
_DELAY = {"recon": 4, "vuln": 3, "mitre": 2, "exploit": 5, "script": 3, "adviser": 2}

_CANNED: dict[str, dict[str, Any]] = {
    "recon": {
        "recon_map": {
            "pages": ["/", "/login", "/api/users"],
            "technologies": ["nginx", "postgresql"],
            "forms": [{"page": "/login", "fields": ["username", "password"]}],
        }
    },
    "vuln": {
        "weaknesses": [
            {"id": "W-001", "page": "/login", "kind": "reflected-xss", "cvss": 6.1},
            {"id": "W-002", "page": "/api/users", "kind": "sql-injection", "cvss": 8.8},
        ]
    },
    "exploit": {
        "exploitation_evidence": [
            {"weakness_id": "W-001", "confirmed": True,
             "request": "GET /login?q=<script>...", "response": "reflected"},
            {"weakness_id": "W-002", "confirmed": False, "reason": "WAF blocked"},
        ]
    },
    "script": {
        "scripts": [
            {"weakness_id": "W-001",
             "script": "#!/usr/bin/env python3\n# reproduces reflected XSS\n..."}
        ]
    },
    "adviser": {
        "report": {
            "summary": "1 confirmed weakness of high severity; 1 candidate blocked by WAF.",
            "findings": 2, "confirmed": 1,
            "recommendations": ["Add output encoding on /login",
                                "Continue investigation on /api/users"],
        }
    },
}


class StubWorker:
    """Returns a canned artifact for one stage."""

    def __init__(self, agent: str) -> None:
        self._agent = agent

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        delay = _DELAY.get(self._agent, 3)
        log.info("stub work for %s (delay=%ds)", self._agent, delay)
        await asyncio.sleep(delay)
        result = dict(_CANNED.get(self._agent, {"note": f"unknown agent {self._agent!r}"}))
        result["stub"] = True
        return result


async def maybe_fail(probability: float = 0.0) -> None:
    """Inject a synthetic failure, for exercising the orchestrator's retry path."""
    if probability > 0 and random.random() < probability:
        raise RuntimeError("synthetic failure (config/stub_failure_rate)")
