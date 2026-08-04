"""Settings for the MCP-tools container.

Values that differ between a laptop and a deployment live here rather than
inline, so nothing else in the package reads ``os.environ`` directly and the
whole configuration surface is one file long.
"""
from __future__ import annotations

import os

# Where the sandbox executor listens.  Overridable mainly so the service can be
# pointed at a local stub during development.
SANDBOX_URL = os.environ.get("APTS_SANDBOX_URL", "https://sandbox:8443")

# Outbound HTTP budget for calls this container makes (currently only the
# sandbox hop).  Deliberately short: a hung sandbox must not pin an agent's
# request open until the agent's own timeout fires.
HTTP_TIMEOUT_SECONDS = float(os.environ.get("APTS_HTTP_TIMEOUT", "15"))
HTTP_CONNECT_TIMEOUT_SECONDS = float(os.environ.get("APTS_HTTP_CONNECT_TIMEOUT", "5"))

# How many engagement scopes to keep in memory.  Scope is immutable for an
# engagement's lifetime, so caching is safe; the cap only bounds memory across
# many concurrent engagements.
SCOPE_CACHE_SIZE = int(os.environ.get("APTS_SCOPE_CACHE_SIZE", "256"))

LISTEN_HOST = os.environ.get("APTS_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("APTS_LISTEN_PORT", "8443"))
