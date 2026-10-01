"""Tunables, tool allowlist, and system prompt for the vuln loop."""
from __future__ import annotations

import os
from shared import prompts
from shared import settings

# --- loop configuration (env-tunable) ------------------------------------- #
MAX_STEPS = int(os.environ.get("APTS_VULN_MAX_STEPS", "6"))
MAX_TOKENS = int(os.environ.get("APTS_VULN_MAX_TOKENS", "900"))
REFLECT_ROUNDS = int(os.environ.get("APTS_VULN_REFLECT_ROUNDS", "1"))
SKIP_NOISE = os.environ.get("APTS_VULN_SKIP_NOISE", "1") not in ("0", "false", "")
# From the validated boot-time settings (shared/settings.py), not raw env.
PROMPT_BUDGET_CHARS = settings.load().loop.prompt_chars
_NOISE = {"stylesheet", "image", "font", "media"}

# A create_react_agent step is one node visit; a full model→tools cycle is two.
# Give the graph room for MAX_STEPS model turns plus the terminating turn.
RECURSION_LIMIT = 2 * MAX_STEPS + 2

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
Give as many HYPOTHESIS blocks as you think are worth testing (at least one).
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
