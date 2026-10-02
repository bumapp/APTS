"""Loop-wide constants shared by every agentic worker.

These come from the validated boot-time settings (``shared/settings.py``), not raw
``os.environ`` — one typed source that fails fast on a bad value. Per-worker
tunables (step/token caps, tool allowlists, prompts) live in each worker's own
``constants.py``; only the values every loop needs live here.
"""
from __future__ import annotations

from shared import settings

# The native MCP server (tools) every worker connects to.
MCP_URL = settings.load().loop.mcp_url

# Bounds the running conversation a worker hands the model (see
# ``agentic.compacting_hook``).
CONTEXT_BUDGET_CHARS = settings.load().loop.context_chars
