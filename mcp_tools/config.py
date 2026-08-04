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

# --------------------------------------------------------------------------- #
# Limits on requests to the engagement target
#
# Every one of these exists to bound something that is unbounded by default.
# Uncapped tool output is the most common way an agent pipeline exhausts its
# context window mid-engagement; an uncapped crawl is also how a "scan" becomes
# something the target's owner would fairly call a denial-of-service attempt.
# --------------------------------------------------------------------------- #

# Per-request timeout when talking to the target. Shorter than the internal
# service timeout: a hung target must not pin an agent's request open.
TARGET_TIMEOUT_SECONDS = float(os.environ.get("APTS_TARGET_TIMEOUT", "10"))

# Bytes of a response body returned to an agent by the http tool.
HTTP_BODY_LIMIT = int(os.environ.get("APTS_HTTP_BODY_LIMIT", "200000"))

# Crawl ceilings. Arguments may lower these but never raise them.
CRAWL_MAX_PAGES = int(os.environ.get("APTS_CRAWL_MAX_PAGES", "40"))
CRAWL_MAX_DEPTH = int(os.environ.get("APTS_CRAWL_MAX_DEPTH", "3"))
CRAWL_MAX_SECONDS = float(os.environ.get("APTS_CRAWL_MAX_SECONDS", "120"))
CRAWL_BODY_LIMIT = int(os.environ.get("APTS_CRAWL_BODY_LIMIT", "500000"))

# JS bundle mining. Bundles are large and there can be many; both are capped.
CRAWL_MAX_SCRIPTS = int(os.environ.get("APTS_CRAWL_MAX_SCRIPTS", "12"))
CRAWL_SCRIPT_LIMIT = int(os.environ.get("APTS_CRAWL_SCRIPT_LIMIT", "3000000"))
