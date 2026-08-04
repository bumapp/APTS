"""Settings for an agent container.

One image runs all six agents; ``AGENT_NAME`` selects the role. Everything that
differs between a laptop and a deployment is read here, so nothing else in the
package touches ``os.environ``.
"""
from __future__ import annotations

import os

from shared.pipeline import CHAIN

AGENT_NAME = os.environ.get("AGENT_NAME", "")
if not AGENT_NAME:
    raise RuntimeError("AGENT_NAME environment variable is required")
if AGENT_NAME not in CHAIN:
    raise RuntimeError(f"unknown AGENT_NAME {AGENT_NAME!r} (must be one of {list(CHAIN)})")

COMPONENT = f"agent-{AGENT_NAME}"

ORCHESTRATOR_URL = os.environ.get("APTS_ORCHESTRATOR_URL", "https://orchestrator:8443")

HTTP_TIMEOUT_SECONDS = float(os.environ.get("APTS_HTTP_TIMEOUT", "30"))
HTTP_CONNECT_TIMEOUT_SECONDS = float(os.environ.get("APTS_HTTP_CONNECT_TIMEOUT", "5"))

LISTEN_HOST = os.environ.get("APTS_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("APTS_LISTEN_PORT", "8443"))

CONFIG_DIR = os.environ.get("APTS_CONFIG_DIR", "/etc/apts/config")


def stub_failure_rate() -> float:
    """Probability an agent injects a synthetic failure, for retry testing.

    Falls back to 0 when the file is missing or malformed — a production run
    must never fail at random because a config file did not parse.
    """
    try:
        with open(f"{CONFIG_DIR}/stub_failure_rate", "r", encoding="utf-8") as fh:
            return float(fh.read().strip() or "0")
    except (FileNotFoundError, OSError, ValueError):
        return 0.0
