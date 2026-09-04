"""Attack Script Builder — the agentic PoC loop, in the agent (PRD §5.6).

This *is* the script agent: a genuine tool-driving loop. For each weakness
Exploitation actually PROVED, the model plans an attack flow, writes a Python or
Bash proof-of-concept, and runs it in the hardened sandbox via the ``sandbox_run``
MCP tool — reading stdout/stderr, fixing what breaks, and improving the script
until it clearly demonstrates the flaw, then stops. The product is an
``AttackPlaybook`` of reviewed, sandbox-tested scripts.

A script is written only for a confirmed weakness. A "reproduction" of something
that was never reproduced is a guess with syntax highlighting, and it would reach
the client looking exactly like one somebody ran successfully. The script that
ships is the exact source the sandbox last ran clean — not something the model
merely claimed works — and it still passes the static safety check before it is
delivered (§5.6): a script that trips the denylist is discarded and counted,
because silently rewriting an attack script is a good way to ship one that no
longer does what it claims.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx
from mcp import Client

from shared.llm import LlmClient
from shared.models import AttackPlaybook, AttackScript

from agent.services.workers import agentic
from agent.services.workers.base import WorkContext

log = logging.getLogger("agent.workers.script")

MAX_STEPS = int(os.environ.get("APTS_SCRIPT_MAX_STEPS", "8"))
MAX_SCRIPTS = int(os.environ.get("APTS_SCRIPT_MAX_SCRIPTS", "10"))

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


def safety_check(source: str) -> tuple[bool, str]:
    """Return ``(passed, notes)`` for one script."""
    hits = [label for pattern, label in _UNSAFE if pattern.search(source)]
    if hits:
        return False, "rejected: " + ", ".join(sorted(set(hits)))
    return True, "passed static safety check (pattern denylist)"


def _observation(result: dict, tried: dict[str, str], steps_left: int) -> str:
    """Compact, coaching feedback wrapped around a sandbox run."""
    keep = {k: result.get(k) for k in
            ("ok", "exit_code", "timed_out", "guidance") if k in result}
    if isinstance(result.get("stdout"), str):
        keep["stdout"] = result["stdout"][-1200:]
    if isinstance(result.get("stderr"), str) and result["stderr"].strip():
        keep["stderr"] = result["stderr"][-1200:]
    if "error" in result:
        keep["error"] = result["error"]
    tried_lines = "; ".join(tried.values()) or "(none yet)"
    return (f"SANDBOX RESULT:\n{json.dumps(keep, default=str)[:1800]}\n---\n"
            f"PROGRESS: {steps_left} step(s) left. Runs so far: {tried_lines}\n"
            f"Fix any error and run again, or give your DONE line if it proves the flaw.")


async def _run_weakness(client, llm, openai_tools, task: str
                        ) -> tuple[str, str, str, str]:
    """Drive the model through one weakness.

    Returns (verdict, language, source, remediation): ``source`` is the exact
    script the sandbox last ran CLEAN (falling back to the last script run at
    all), so what ships is what actually executed, not a claim.
    """
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": task}]
    tried: dict[str, str] = {}
    best = {"language": "python", "source": ""}   # last clean run
    last = {"language": "python", "source": ""}   # last run of any kind

    for step in range(MAX_STEPS):
        messages = agentic.compact(messages, tried)
        try:
            msg = await agentic.chat(llm, messages, tools=openai_tools)
        except httpx.HTTPError as exc:
            return (f"INCONCLUSIVE — model call failed at step {step} "
                    f"({type(exc).__name__}: {agentic.err_body(exc)[:200]})",
                    best["language"], best["source"] or last["source"], "")
        messages.append(msg)

        calls = msg.get("tool_calls")
        if not calls:
            verdict = (msg.get("content") or "").strip() or "(no verdict)"
            remediation = ""
            if "||" in verdict and "FIX:" in verdict.upper():
                head, _, tail = verdict.partition("||")
                remediation = re.sub(r"(?i)^\s*fix:\s*", "", tail).strip()
                verdict = head.strip()
            return verdict, best["language"], best["source"] or last["source"], remediation

        steps_left = MAX_STEPS - step - 1
        for call in calls:
            name = call["function"]["name"]
            try:
                args = json.loads(call["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            key = agentic.sig(name, args)
            if key in tried:
                messages.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": ("You already ran this exact script. "
                                             "Change it or give your DONE line.")})
                continue
            result = await client.call_tool(name, args)
            payload = result.structured_content or {
                "content": [getattr(b, "text", str(b)) for b in result.content]}
            if name == "sandbox_run" and isinstance(args.get("source"), str):
                last = {"language": args.get("language", "python"),
                        "source": args["source"]}
                if isinstance(payload, dict) and payload.get("ok"):
                    best = dict(last)
            tried[key] = (f"{args.get('language', name)} run -> "
                          f"ok={payload.get('ok') if isinstance(payload, dict) else '?'}")
            messages.append({"role": "tool", "tool_call_id": call["id"],
                             "content": _observation(payload, tried, steps_left)})

    return ("INCONCLUSIVE — hit the step limit without a clean proof",
            best["language"], best["source"] or last["source"], "")


class ScriptWorker:
    """The script agent: the write-test-improve PoC loop over confirmed weaknesses."""

    def __init__(self, llm: LlmClient, results) -> None:
        self._llm = llm  # unused: the loop drives the AWS model itself
        self._results = results

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        evidence = ctx.upstream if "attempts" in ctx.upstream else (
            self._results.load(ctx.engagement_id, "exploit") or {})
        confirmed = [a for a in evidence.get("attempts", []) if a.get("confirmed")]
        if not confirmed:
            log.info("nothing was confirmed; the playbook is empty by design")
            return AttackPlaybook().model_dump(mode="json")

        register = self._results.load(ctx.engagement_id, "vuln") or {}
        attack_map = self._results.load(ctx.engagement_id, "mitre") or {}
        by_id = {w["id"]: w for w in register.get("weaknesses", []) if w.get("id")}
        mappings = attack_map.get("mappings", {})

        scripts: list[AttackScript] = []
        rejected = 0

        async with Client(agentic.MCP_URL) as client, \
                httpx.AsyncClient(timeout=agentic.LLM_TIMEOUT) as llm:
            tools = [t for t in (await client.list_tools()).tools
                     if t.name in AGENT_TOOLS]
            openai_tools = agentic.mcp_tools_to_openai(tools)
            pre = agentic.directive_block(ctx.directive)

            for attempt in confirmed[:MAX_SCRIPTS]:
                wid = attempt.get("weakness_id", "W-?")
                weakness = by_id.get(wid, {})
                task = pre + self._task(attempt, weakness)
                try:
                    verdict, language, source, remediation = await _run_weakness(
                        client, llm, openai_tools, task)
                except Exception as exc:  # noqa: BLE001 — one bad item must not stop the stage
                    log.warning("script loop for %s errored: %s", wid, exc)
                    rejected += 1
                    continue

                if not source.strip():
                    log.info("script %s: no runnable script produced", wid)
                    rejected += 1
                    continue
                passed, notes = safety_check(source)
                if not passed:
                    log.warning("script for %s %s", wid, notes)
                    rejected += 1
                    continue

                scripts.append(AttackScript(
                    weakness_id=wid,
                    language=language if language in ("python", "bash") else "python",
                    source=source,
                    description=verdict[:400],
                    technique_ids=[t["technique_id"] for t in mappings.get(wid, [])],
                    remediation_pointer=remediation[:400],
                    safety_checked=True,
                    safety_notes=notes))
                log.info("script %s: %d-line %s PoC, sandbox-tested", wid,
                         source.count("\n") + 1, language)

        playbook = AttackPlaybook(scripts=scripts, rejected=rejected)
        log.info("playbook: %d scripts shipped, %d rejected", len(scripts), rejected)
        return playbook.model_dump(mode="json")

    @staticmethod
    def _task(attempt: dict, weakness: dict) -> str:
        """The proven weakness and its evidence, as the loop's opening turn."""
        ev = attempt.get("evidence") or {}
        lines = [
            f"CONFIRMED weakness {attempt.get('weakness_id', 'W-?')}: "
            f"{weakness.get('title', 'weakness')}",
            f"Asset/endpoint: {weakness.get('asset', '?')}",
            f"Proving signal: {attempt.get('detection', '')}",
            f"How it was proven: {attempt.get('reason', '')}",
        ]
        if ev.get("request"):
            lines.append(f"Confirmed request: {str(ev['request'])[:600]}")
        if ev.get("response"):
            lines.append(f"Observed response: {str(ev['response'])[:600]}")
        lines.append("\nWrite and sandbox-test a PoC that reproduces this.")
        return "\n".join(lines)
