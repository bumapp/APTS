"""Tunables, tool allowlist, and system prompt for the mitre loop."""
from __future__ import annotations

import os
from shared import prompts

MAX_STEPS = int(os.environ.get("APTS_MITRE_MAX_STEPS", "5"))
MAX_TOKENS = int(os.environ.get("APTS_MITRE_MAX_TOKENS", "700"))
# How many times the worker re-runs the loop for the weaknesses still untagged
# before giving up. One or two passes normally clears a register.
MAX_PASSES = int(os.environ.get("APTS_MITRE_MAX_PASSES", "3"))

RECURSION_LIMIT = 2 * MAX_STEPS + 2

# mitre is target-free — it only queries the ATT&CK knowledge base, never the
# target — so concurrency is bounded by the model endpoint, not the target, and
# several weaknesses can be mapped at once. Tune with APTS_MITRE_CONCURRENCY.
CONCURRENCY = int(os.environ.get("APTS_MITRE_CONCURRENCY", "5"))

# The mapping agent classifies; it does not probe. It gets only the ATT&CK
# reference tools — never http_request/sqlmap.
AGENT_TOOLS = {"attack_catalog", "attack_search", "attack_technique"}

# Deterministic floor for §5.4: a weakness the model could not map to a
# catalogue-confirmed technique still needs >=1 technique, so it gets this. T1190
# "Exploit Public-Facing Application" (Initial Access) is the canonical ATT&CK
# technique for exploiting a web application — a correct, conservative default
# that keeps one model/format miss from stalling the whole pipeline.
FALLBACK_TECHNIQUE = {"technique_id": "T1190",
                      "technique_name": "Exploit Public-Facing Application",
                      "tactic": "Initial Access"}

SYSTEM_PROMPT = """\
You map ONE web-application weakness to the MITRE ATT&CK for Enterprise
framework. Return the technique(s) that describe how an adversary would use this
weakness in an intrusion.

You have the ATT&CK reference as tools:
- attack_search(query) — find candidate techniques for a description.
- attack_technique(id)  — validate one id (e.g. T1190, T1059.007) and get its
  official name and tactic.
- The technique menu (id + name) is given to you below.

How to work:
- Search for the weakness class or the attacker's goal. Read the candidates.
- Before you commit to an id, call attack_technique(id) to confirm it is real
  and to get the authoritative name and tactic. Use those exact values.
- Call ONE tool at a time. Never repeat a call with the same arguments.
- Prefer the most specific sub-technique that genuinely fits.
- You MUST end with at least one confirmed technique.

When done, reply WITHOUT calling a tool. One line per technique, exactly:
  TECHNIQUE: <id> | <official name> | <tactic>
"""

# Served through the prompt registry (Langfuse-backed, in-repo default fallback).
MITRE_SYSTEM_PROMPT_ID = "mitre.system"
prompts.register(MITRE_SYSTEM_PROMPT_ID, SYSTEM_PROMPT)
