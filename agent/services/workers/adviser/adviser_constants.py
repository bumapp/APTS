"""Tunables, tool allowlist, and system prompt for the adviser loop."""
from __future__ import annotations

import os
from shared import prompts

MAX_STEPS = int(os.environ.get("APTS_ADVISER_MAX_STEPS", "2"))
MAX_TOKENS = int(os.environ.get("APTS_ADVISER_MAX_TOKENS", "2000"))

# Vulnerability class -> (canonical label, default severity). Used to normalise
# titles for grouping and to seed / fall back on severity. Order matters: more
# specific keys first. This is a *reporting* judgement, not a CVSS vector.
_CLASS_RULES = [
    ("nosql", "NoSQL Injection", "critical"),
    ("sql inj", "SQL Injection", "critical"),
    ("command inj", "Command Injection", "critical"),
    ("remote code", "Remote Code Execution", "critical"),
    ("rce", "Remote Code Execution", "critical"),
    ("template inj", "Server-Side Template Injection", "critical"),
    ("ssti", "Server-Side Template Injection", "critical"),
    ("deserial", "Insecure Deserialization", "critical"),
    ("authentication bypass", "Authentication Bypass", "critical"),
    ("login bypass", "Authentication Bypass", "critical"),
    ("account takeover", "Account Takeover", "critical"),
    ("privilege escal", "Privilege Escalation", "high"),
    ("ldap inj", "LDAP Injection", "high"),
    ("mass assign", "Mass Assignment", "high"),
    ("prototype pollution", "Prototype Pollution", "high"),
    ("idor", "IDOR (Broken Access Control)", "high"),
    ("broken access", "Broken Access Control", "high"),
    ("ssrf", "SSRF", "high"),
    ("xxe", "XXE", "high"),
    ("path travers", "Path Traversal / File Inclusion", "high"),
    ("file inclus", "Path Traversal / File Inclusion", "high"),
    ("stored xss", "Stored XSS", "high"),
    ("xss", "Cross-Site Scripting", "high"),
    ("cors", "CORS Misconfiguration", "medium"),
    ("csrf", "CSRF", "medium"),
    ("open redirect", "Open Redirect", "medium"),
    ("information disclosure", "Information Disclosure", "medium"),
    ("info disclos", "Information Disclosure", "medium"),
    ("verbose", "Information Disclosure", "medium"),
    ("version", "Version Disclosure", "low"),
    ("captcha", "CAPTCHA Bypass", "low"),
    ("websocket", "WebSocket Misconfiguration", "medium"),
]
_SEVERITY_SCORE = {"critical": 9.5, "high": 7.5, "medium": 5.0,
                   "low": 2.5, "informational": 1.0}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

SYSTEM_PROMPT = """\
You are writing the FINDINGS section of a penetration-test report. You are given
CONFIRMED, pre-grouped items — each is what was PROVEN on one asset, with the
hypotheses it came from and what the exploit actually demonstrated.

MERGE DUPLICATES — this is important. Different items are often the SAME
underlying vulnerability, reached from different hypotheses or with overlapping
evidence (e.g. 'Account Takeover', 'LDAP Injection' and 'SQL Injection' that all
prove the same SQL injection on the same login endpoint). When two or more items
are the same real issue — same proof, same injection point, same evidence — MERGE
them into ONE finding and list ALL their keys in "keys". Judge sameness by the
"proved"/"evidence" text, not by the hypothesis names.

For each finding:
- assign a severity: critical | high | medium | low, by real-world impact;
- write ONE sentence of concrete business impact;
- write a specific, actionable remediation for that asset and class (never
  "validate input");
- give an effort to fix: low | medium | high.
Then ORDER the findings most-impactful first.

Reply with ONLY JSON, no prose:
{"findings":[{"keys":["<exact group key>", ...],"title":"<short finding title>",
  "severity":"critical|high|medium|low","impact":"<one sentence>",
  "recommendation":"<two or three sentences>","effort":"low|medium|high"}],
 "narrative":"<3-5 sentences for a CISO: risk posture, what to fix first, and how
              much confidence these proven results warrant>"}
Every group key given must appear in exactly one finding's "keys". Do not invent
findings or keys.
"""

# Served through the prompt registry (Langfuse-backed, in-repo default fallback).
ADVISER_SYSTEM_PROMPT_ID = "adviser.system"
prompts.register(ADVISER_SYSTEM_PROMPT_ID, SYSTEM_PROMPT)
