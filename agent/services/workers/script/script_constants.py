"""Tunables, tool allowlist, and system prompt for the script loop."""
from __future__ import annotations

import os
import re
from shared import prompts

MAX_STEPS = int(os.environ.get("APTS_SCRIPT_MAX_STEPS", "8"))
MAX_SCRIPTS = int(os.environ.get("APTS_SCRIPT_MAX_SCRIPTS", "10"))

RECURSION_LIMIT = 2 * MAX_STEPS + 2

# The script agent PROVES-BY-REPRODUCTION; it is handed ONLY the sandbox runner.
# Without this it would see every tool on mcp-native and wander into recon or
# knowledge-base lookups instead of writing and testing a script.
AGENT_TOOLS = {"sandbox_run"}

# Constructs that must never appear in a delivered script. A reproduction runs on
# the client's own system; anything here turns a demonstration into damage. The
# script is run in the sandbox during the loop, but what SHIPS is still reviewed.
_UNSAFE = [
    (re.compile(r"\b(drop|truncate)\s+(table|database|schema)\b", re.I),
     "destructive SQL"),
    (re.compile(r"\bdelete\s+from\b", re.I), "destructive SQL"),
    (re.compile(r"\brm\s+-rf\b|\bmkfs\.|\bshutdown\b", re.I), "destructive shell"),
    (re.compile(r"\bos\.system\s*\(|\bsubprocess\.\w+\s*\([^)]*shell\s*=\s*True", re.I),
     "shell execution"),
    (re.compile(r"\bwhile\s+True\s*:(?![^\n]*break)", re.I), "unbounded loop"),
    (re.compile(r"\b(fork|thread)bomb\b|:\(\)\{.*\};:", re.I), "fork bomb"),
    (re.compile(r"\beval\s*\(|\bexec\s*\(", re.I), "dynamic code execution"),
]

SYSTEM_PROMPT = """\
You are a proof-of-concept author for an authorised penetration test. For the
single CONFIRMED weakness below, write a script that reproduces it, TEST it in
the sandbox, and improve it until it clearly proves the flaw. Then stop.

How to work:
- First think through the attack flow in one or two lines: what request proves
  the weakness, what a successful result looks like.
- Write a COMPLETE Python (requests/httpx available) or Bash (curl available)
  script and run it with the sandbox_run tool. The sandbox can reach the target
  but not the internet.
- Read sandbox_run's stdout, stderr, and "guidance". If the script errors, FIX
  the source and run it again — do not give up on a fixable error. If it runs
  but does not clearly show the weakness firing, strengthen the proof (print the
  reflected payload, the leaked row, the bypassed check) and run again.
- Reproduce ONLY. Never delete, modify, or overwrite data: no DROP, DELETE,
  TRUNCATE, UPDATE, rm, shell-out, eval, or unbounded loops. Keep it under ~40 lines.
- Call ONE tool at a time. Do not repeat an identical call.

When the script has run in the sandbox and its output clearly demonstrates the
weakness, reply WITHOUT calling a tool, on one line:
  DONE: <what the script proves> || FIX: <one-sentence remediation>
"""

# Served through the prompt registry (Langfuse-backed, in-repo default fallback).
SCRIPT_SYSTEM_PROMPT_ID = "script.system"
prompts.register(SCRIPT_SYSTEM_PROMPT_ID, SYSTEM_PROMPT)
