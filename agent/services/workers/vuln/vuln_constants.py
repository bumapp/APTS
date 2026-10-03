"""Tunables, tool allowlist, and system prompt for the vuln loop."""
from __future__ import annotations

import os
from shared import prompts
from shared import settings

# --- loop configuration (env-tunable) ------------------------------------- #
MAX_STEPS = 100  # big static cap for testing; tune for prod
# Bumped from 900: qwen on Bedrock was running out mid-answer and emitting
# "Sorry, need more steps to process this request." instead of HYPOTHESIS blocks.
MAX_TOKENS = int(os.environ.get("APTS_VULN_MAX_TOKENS", "1500"))
# `or "2"` (not a get-default): compose can pass this var present-but-empty, and
# os.environ.get would then return "" -> int("") ValueError, crash-looping the agent.
REFLECT_ROUNDS = int(os.environ.get("APTS_VULN_REFLECT_ROUNDS") or "2")
SKIP_NOISE = os.environ.get("APTS_VULN_SKIP_NOISE", "1") not in ("0", "false", "")
# From the validated boot-time settings (shared/settings.py), not raw env.
PROMPT_BUDGET_CHARS = settings.load().loop.prompt_chars
_NOISE = {"stylesheet", "image", "font", "media"}

# A create_react_agent step is one node visit; a full model→tools cycle is two.
# Give the graph room for MAX_STEPS model turns plus the terminating turn.
RECURSION_LIMIT = 2 * MAX_STEPS + 2

# How many recon requests to assess concurrently. Vuln hits only the read-only
# knowledge base (no target traffic), so it is bounded by the model endpoint, not
# the target — it can run wider than exploit. Tune with APTS_VULN_CONCURRENCY.
CONCURRENCY = int(os.environ.get("APTS_VULN_CONCURRENCY", "5"))

# The vuln agent proposes; it does not probe. It is handed ONLY the knowledge-base
# tools — never sqlmap/http_request — both because that is its job and to keep the
# prompt small.
AGENT_TOOLS = {"hacktricks_overview", "hacktricks_article"}

SYSTEM_PROMPT = """\
You are a web application vulnerability analyst. You are shown ONE HTTP request
that reconnaissance observed. Your job: decide which vulnerability classes are
worth testing against THIS request, and write concrete, testable hypotheses.

You have a HackTricks knowledge base as tools:
- The technique menu (slug + title for every class) is given to you below.
- hacktricks_article(slug) returns that technique's worked examples and payloads.

How to work:
- Look at the request's method, path, parameters, body, and content type. Reason
  about where user input enters and how the server might mishandle it.
- ONE HYPOTHESIS PER VULNERABILITY CLASS PER INPUT. The SAME parameter often reaches
  MORE THAN ONE sink — e.g. a search/query parameter put into a SQL query AND
  reflected into the HTML is BOTH SQL injection AND reflected XSS; a login field
  can be BOTH a SQLi auth-bypass AND credential issues. Emit a SEPARATE hypothesis
  for EACH class that plausibly applies — never collapse two classes into one block.
  Each hypothesis is proved independently downstream, so a class you merge or omit
  is a class that never gets tested. Cover at least injection (SQL/NoSQL/command),
  XSS, and broken access control / IDOR wherever each could apply to this request.
  REFLECTED/DOM XSS applies to any parameter whose value the app echoes back or the
  UI displays — a search/query term, a name, a message — EVEN WHEN this endpoint
  returns JSON: a SPA renders that value back into the page, so the XSS fires in the
  browser, not the API response. Always add an XSS hypothesis for such displayed inputs.
- Choose the techniques that plausibly apply. For a technique you want examples
  for, call hacktricks_article(slug) using a slug from the menu, and let the
  examples sharpen your hypothesis. Fetch only what helps; do not fetch all of them.
- Call ONE tool at a time. Never fetch the same article twice.
- Speculate freely. A plausible idea you are not sure about is worth stating —
  imagine anything an attacker might try here, even long shots. Something later
  proves it or kills it; your job is to surface the candidates.
- You MUST produce at least one hypothesis even if no article matches — reason
  from first principles.

When done, reply WITHOUT calling a tool. Output one block per hypothesis, each
exactly in this shape (keep it to one line each):
  HYPOTHESIS: <vuln class> — <where> (param `<param>`, <METHOD> <path>)
  WHY: <one sentence: why this input could reach that sink>
Emit one block per applicable class per input (at least one). An input that could
be both injectable and reflected gets TWO blocks — one SQLi, one XSS.
"""

REFLECT_PROMPT_TMPL = """\
You proposed these hypotheses for THIS request:
{current}

Think again. Are there OTHER distinct, testable hypotheses worth adding — a
different vulnerability class, a different parameter, or an attack angle you have
not covered yet? Speculative long shots are welcome; someone else proves or kills
them later.
- If yes: output ONLY the NEW HYPOTHESIS blocks (same HYPOTHESIS: / WHY: format).
  Do not repeat any listed above.
- If nothing worth adding: reply with exactly DONE.
"""

# The vuln system prompt is served through the prompt registry (Langfuse-backed,
# falling back to the original in-repo text) so it can be versioned and linked to
# traces instead of being frozen in code. See shared/prompts.py.
VULN_SYSTEM_PROMPT_ID = "vuln.system"
prompts.register(VULN_SYSTEM_PROMPT_ID, SYSTEM_PROMPT)
