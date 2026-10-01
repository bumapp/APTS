"""Tunables, tool allowlist, and system prompt for the recon loop."""
from __future__ import annotations

import os
from shared import prompts

MAX_TOKENS = int(os.environ.get("APTS_RECON_MAX_TOKENS", "800"))

RANK_SYSTEM = """\
You are a web recon analyst triaging observed HTTP requests for an authorised
penetration test. For the page below you are given the requests the browser
fired. Rate EACH request for how worth testing it is — do not drop any, rate all:
- high:   carries user input into app logic — a login/search/API call with
          params or a body, an ID in the path, anything reaching a backend
          query, command, or template. If a request lists ANY query or body
          parameter, rate it high — even a parameter whose observed value is
          empty still takes user input and is worth testing.
- medium: an app/API call with NO parameters at all, still worth a look.
- low:    static assets, analytics, polling/transport, health checks — little to test.

Reply with ONLY JSON, no prose:
{"rankings":[{"i":<index>,"interest":"high|medium|low","reason":"<one short line>"}]}
Rate every index you are given, exactly once.
"""

# Served through the prompt registry (Langfuse-backed, in-repo default fallback).
RECON_SYSTEM_PROMPT_ID = "recon.rank"
prompts.register(RECON_SYSTEM_PROMPT_ID, RANK_SYSTEM)
