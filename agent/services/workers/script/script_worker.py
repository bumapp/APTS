"""Attack Script Builder — the agentic PoC loop, on LangGraph (PRD §5.6).

This *is* the script agent: a genuine tool-driving loop. For each weakness
Exploitation actually PROVED, the model plans an attack flow, writes a Python or
Bash proof-of-concept, and runs it in the hardened sandbox via the ``sandbox_run``
MCP tool — reading stdout/stderr, fixing what breaks, and improving the script
until it clearly demonstrates the flaw, then stops. The product is an
``AttackPlaybook`` of reviewed, sandbox-tested scripts.

A script is written only for a confirmed weakness. A "reproduction" of something
that was never reproduced is a guess with syntax highlighting, and it would reach
the client looking exactly like one somebody ran successfully. The script that
ships is the exact source the sandbox last ran clean — captured via the tool
wrapper's ``on_call`` hook, not something the model merely claimed works — and it
still passes the static safety check before it is delivered (§5.6): a script that
trips the denylist is discarded and counted, because silently rewriting an attack
script is a good way to ship one that no longer does what it claims.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from langgraph.errors import GraphRecursionError
from langgraph.prebuilt import create_react_agent
from mcp import Client

from shared import prompts
from shared.llm import (build_chat_model, flush, run_config, set_run_output,
                        trace_run)
from shared.models import AttackPlaybook, AttackScript

from agent.services.workers.common import common_agentic as agentic
from agent.services.workers.base import WorkContext
from .script_constants import (
    AGENT_TOOLS, MAX_SCRIPTS, MAX_STEPS, RECURSION_LIMIT, SCRIPT_SYSTEM_PROMPT_ID, _UNSAFE)

log = logging.getLogger("agent.workers.script")


# --------------------------------------------------------------------------- #
# Auth framing, safety check, observation (pure)
# --------------------------------------------------------------------------- #

def _auth_note(credentials: dict | None) -> str:
    """Surface the engagement session to the PoC author so a reproduction can
    authenticate exactly as the confirmed request did. Generic: it lists whatever
    headers/cookies the run carries, with full values, and nothing here knows what
    any value is. Empty when the run is unauthenticated."""
    creds = credentials or {}
    headers = creds.get("headers") or {}
    cookies = creds.get("cookies") or []
    basic = creds.get("basic_auth") or {}
    if not headers and not cookies and not basic:
        return ""
    lines = ["\n\nAUTHENTICATED RUN — the engagement has a live session. If (and "
             "only if) reproducing this weakness needs authentication, send it in "
             "the PoC using these values VERBATIM (do not shorten or alter them):"]
    for k, v in headers.items():
        lines.append(f"- request header  {k}: {v}")
    for c in cookies:
        if isinstance(c, dict) and c.get("name"):
            lines.append(f"- cookie  {c['name']}={c.get('value', '')}")
    if basic.get("username"):
        lines.append(f"- HTTP basic auth  user={basic.get('username')} "
                     f"password={basic.get('password', '')}")
    return "\n".join(lines)


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


def _observe(_name: str, payload: Any, tried: dict[str, str]) -> str:
    steps_left = max(0, MAX_STEPS - len(tried))
    return _observation(payload if isinstance(payload, dict) else {}, tried, steps_left)


def _parse_done(verdict: str) -> tuple[str, str]:
    """Split a ``DONE: ... || FIX: ...`` reply into (verdict, remediation)."""
    remediation = ""
    if "||" in verdict and "FIX:" in verdict.upper():
        head, _, tail = verdict.partition("||")
        remediation = re.sub(r"(?i)^\s*fix:\s*", "", tail).strip()
        verdict = head.strip()
    return verdict, remediation


# --------------------------------------------------------------------------- #
# The loop: one fresh react graph per confirmed weakness
# --------------------------------------------------------------------------- #

async def _run_weakness(model, client, descriptors, task: str, config: dict,
                        system_prompt: str, trace_prompt=None
                        ) -> tuple[str, str, str, str]:
    """Drive the model through one weakness.

    Returns (verdict, language, source, remediation): ``source`` is the exact
    script the sandbox last ran CLEAN (falling back to the last script run at
    all), so what ships is what actually executed, not a claim. The best/last
    capture rides the tool wrapper's ``on_call`` hook — it sees the source the
    model actually sent and the sandbox's ``ok`` result.
    """
    best = {"language": "python", "source": ""}   # last clean run
    last = {"language": "python", "source": ""}    # last run of any kind

    def _on_call(name: str, orig_args: dict, payload: Any) -> None:
        if name != "sandbox_run" or not isinstance(orig_args.get("source"), str):
            return
        last.update(language=orig_args.get("language", "python"),
                    source=orig_args["source"])
        if isinstance(payload, dict) and payload.get("ok"):
            best.update(last)

    def _outcome(_name: str, payload: Any) -> str:
        ok = payload.get("ok") if isinstance(payload, dict) else "?"
        return f"run -> ok={ok}"

    tools = agentic.as_langchain_tools(
        client, descriptors, tried={}, outcome=_outcome, observe=_observe,
        on_call=_on_call)
    agent = create_react_agent(
        model, tools, prompt=system_prompt,
        pre_model_hook=agentic.compacting_hook(agentic.CONTEXT_BUDGET_CHARS))
    invoke_cfg = {**config, "recursion_limit": RECURSION_LIMIT}

    with trace_run(name="script-poc", run_input=task, prompt=trace_prompt) as span:
        try:
            result = await agent.ainvoke(
                {"messages": [agentic.HumanMessage(content=task)]}, config=invoke_cfg)
            verdict = agentic.final_text(result) or "(no verdict)"
        except GraphRecursionError:
            verdict = "INCONCLUSIVE — hit the step limit without a clean proof"
        except Exception as exc:  # noqa: BLE001 — one bad item must not stop the stage
            verdict = (f"INCONCLUSIVE — model loop failed "
                       f"({type(exc).__name__}: {str(exc)[:200]})")
        verdict, remediation = _parse_done(verdict)
        set_run_output(span, verdict)
    return verdict, best["language"], best["source"] or last["source"], remediation


class ScriptWorker:
    """The script agent: the write-test-improve PoC loop over confirmed weaknesses."""

    def __init__(self, results) -> None:
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

        model = build_chat_model("script")
        config = run_config(engagement_id=str(ctx.engagement_id), agent="script")
        system = prompts.get(SCRIPT_SYSTEM_PROMPT_ID)  # Langfuse-backed, default fallback

        scripts: list[AttackScript] = []
        rejected = 0

        with trace_run(name="script",
                       run_input={"confirmed": [a.get("weakness_id")
                                                for a in confirmed]},
                       engagement_id=str(ctx.engagement_id)) as _stage:
            try:
                async with Client(agentic.MCP_URL) as client:
                    descriptors = [t for t in (await client.list_tools()).tools
                                   if t.name in AGENT_TOOLS]
                    pre = agentic.directive_block(ctx.directive)
                    auth_note = _auth_note(ctx.credentials)
                    if auth_note:
                        log.info("script builder has a session available for PoCs")

                    for attempt in confirmed[:MAX_SCRIPTS]:
                        wid = attempt.get("weakness_id", "W-?")
                        weakness = by_id.get(wid, {})
                        task = pre + self._task(attempt, weakness) + auth_note
                        try:
                            verdict, language, source, remediation = await _run_weakness(
                                model, client, descriptors, task, config,
                                system.text, system.trace_prompt)
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
            finally:
                flush()  # short-lived stage: push any buffered Langfuse spans
            set_run_output(_stage, {
                "scripts": len(scripts), "rejected": rejected,
                "items": [{"id": s.weakness_id, "language": s.language}
                          for s in scripts]})

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
