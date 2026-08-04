"""Attack Script Builder — formalises what was proved (PRD §5.6).

Writes a reproduction script for each **confirmed** weakness, and only those.
A script for an unproven weakness is a guess with syntax highlighting, and it
would reach the client looking exactly like one somebody ran successfully.
Exploitation already recorded the request that worked; this stage turns that
into something a developer can execute against their own environment.

Every script passes a static safety check before it ships (§5.6 acceptance
criterion). The check is conservative and rejects rather than edits: a script
that trips it is discarded and counted, because silently rewriting an
attack script is a good way to ship one that no longer does what it claims.

The safety check here is a pattern denylist, not a real static analyser. Wiring
``bandit`` through the ``lint_script`` MCP tool is the proper form and is not
done yet — so this catches obvious destructive constructs and nothing subtler.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from shared.llm import LlmClient, LlmError
from shared.models import AttackPlaybook, AttackScript

from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("agent.workers.script")

MAX_SCRIPTS = 10

# Constructs that must never appear in a delivered script. A reproduction runs
# on the client's own system; anything here turns a demonstration into damage.
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
You write short, safe reproduction scripts for CONFIRMED web application
weaknesses, for the client's engineers to run against their own environment.

Reply with ONLY JSON:
{"scripts": [{"weakness_id": "W-001",
              "language": "python",
              "source": "<complete runnable script>",
              "description": "<what it demonstrates>",
              "remediation_pointer": "<the fix, one or two sentences>"}]}

Rules:
- Reproduce ONLY. Never delete, modify, or overwrite data. No DROP, DELETE,
  TRUNCATE, UPDATE, rm, shell execution, eval, or unbounded loops.
- Python using the `requests` library, or bash using `curl`.
- Take the target base URL from argv[1] so it is not hardcoded.
- Print clearly whether the weakness reproduced.
- Use the exact request that was already confirmed to work.
- One script per confirmed weakness. Keep each under 40 lines.
"""


def safety_check(source: str) -> tuple[bool, str]:
    """Return ``(passed, notes)`` for one script."""
    hits = [label for pattern, label in _UNSAFE if pattern.search(source)]
    if hits:
        return False, "rejected: " + ", ".join(sorted(set(hits)))
    return True, "passed static safety check (pattern denylist)"


class ScriptWorker:
    """Turns confirmed exploitation into a reviewed Attack Playbook."""

    def __init__(self, llm: LlmClient, results) -> None:
        self._llm = llm
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

        proposed = await self._propose(confirmed, by_id)
        scripts, rejected = self._review(proposed, by_id, attack_map)

        playbook = AttackPlaybook(scripts=scripts, rejected=rejected)
        log.info("playbook: %d scripts shipped, %d rejected by safety check",
                 len(scripts), rejected)
        return playbook.model_dump(mode="json")

    # ----------------------------------------------------------------- #

    async def _propose(self, confirmed: list[dict], by_id: dict) -> list[dict]:
        lines = []
        for attempt in confirmed[:MAX_SCRIPTS]:
            weakness = by_id.get(attempt["weakness_id"], {})
            lines.append(
                f"{attempt['weakness_id']}: {weakness.get('title', 'weakness')} "
                f"on {weakness.get('asset', '?')}\n"
                f"  confirmed request: {attempt.get('payload', '')}\n"
                f"  proving signal:    {attempt.get('detection', '')}")

        try:
            raw = await self._llm.complete_json(SYSTEM_PROMPT, "\n".join(lines))
        except LlmError as exc:
            raise WorkFailed(f"script generation failed: {exc}") from exc

        scripts = raw.get("scripts")
        if not isinstance(scripts, list):
            raise WorkFailed(
                f"model returned no 'scripts' list (got keys: {sorted(raw)})")
        return scripts

    @staticmethod
    def _review(proposed: list[dict], by_id: dict,
                attack_map: dict) -> tuple[list[AttackScript], int]:
        mappings = attack_map.get("mappings", {})
        scripts: list[AttackScript] = []
        rejected = 0

        for item in proposed[:MAX_SCRIPTS]:
            weakness_id = str(item.get("weakness_id") or "")
            if weakness_id not in by_id:
                log.warning("dropping script for unknown weakness %r", weakness_id)
                rejected += 1
                continue

            source = str(item.get("source") or "")
            if not source.strip():
                rejected += 1
                continue

            passed, notes = safety_check(source)
            if not passed:
                log.warning("script for %s %s", weakness_id, notes)
                rejected += 1
                continue

            language = item.get("language")
            scripts.append(AttackScript(
                weakness_id=weakness_id,
                language=language if language in ("python", "bash") else "python",
                source=source,
                description=str(item.get("description") or "")[:400],
                technique_ids=[t["technique_id"]
                               for t in mappings.get(weakness_id, [])],
                remediation_pointer=str(item.get("remediation_pointer") or "")[:400],
                safety_checked=True,
                safety_notes=notes,
            ))

        return scripts, rejected
