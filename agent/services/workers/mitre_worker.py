"""MITRE ATT&CK mapping — the agentic loop, in the agent (PRD §5.4).

Takes the Vulnerability Register and tags every weakness with ATT&CK Tactics and
Techniques. Like the recon/vuln/exploit stages this is a genuine tool-driving
loop that lives in the agent directory (shared plumbing in ``agentic``): for each
weakness the model drives the ATT&CK reference tools on mcp-native —
``attack_search`` for candidates, ``attack_technique`` to validate one id — and
the worker keeps only the ids the catalogue confirmed.

Two layers of checking:

* **The tool is the trust boundary.** ``_validate`` calls ``attack_technique``
  for every id the model proposed and discards any the catalogue does not know,
  substituting the authoritative name and tactic. A hallucinated id does not
  survive — "model judges, code decides".
* :class:`AttackMap` is the final schema gate: §5.4 requires every finding carry
  at least one technique.

**Stop condition.** The worker runs the per-weakness loop over the still-untagged
weaknesses up to ``APTS_MITRE_MAX_PASSES`` times, stopping when nothing is left;
a pass that tags nothing new routes into the orchestrator's retry instead of
burning passes.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx
from mcp import Client
from pydantic import ValidationError

from shared.llm import LlmClient
from shared.models import AttackMap

from agent.services.workers import agentic
from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("agent.workers.mitre")

MAX_STEPS = int(os.environ.get("APTS_MITRE_MAX_STEPS", "5"))
MAX_TOKENS = int(os.environ.get("APTS_MITRE_MAX_TOKENS", "700"))
# How many times the worker re-runs the loop for the weaknesses still untagged
# before giving up. One or two passes normally clears a register.
MAX_PASSES = int(os.environ.get("APTS_MITRE_MAX_PASSES", "3"))

# The mapping agent classifies; it does not probe. It gets only the ATT&CK
# reference tools — never http_request/sqlmap.
AGENT_TOOLS = {"attack_catalog", "attack_search", "attack_technique"}

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


# --------------------------------------------------------------------------- #
# The loop: one fresh conversation per weakness
# --------------------------------------------------------------------------- #

def _render_menu(techniques: list[dict]) -> str:
    """Technique menu injected per conversation — ``id name`` pairs, newline-joined."""
    return "\n".join(f"{t.get('technique_id', t.get('id'))}  {t.get('name', '')}"
                     for t in techniques)


def _describe_weakness(weakness: dict[str, Any]) -> str:
    """Compact, model-facing description — only the fields that inform a choice."""
    wid = weakness.get("id") or weakness.get("weakness_id") or "?"
    kind = weakness.get("title") or weakness.get("kind") or "unspecified weakness"
    where = weakness.get("asset") or weakness.get("page") or "unknown location"
    rationale = weakness.get("rationale") or ""
    text = f"Weakness {wid}: {kind}\nLocation: {where}"
    if rationale:
        text += f"\nWhy suspected: {rationale[:300]}"
    return text


_TAG_RE = re.compile(
    r"TECHNIQUE:\s*(T\d{4}(?:\.\d{3})?)\s*\|\s*([^|]+?)\s*\|\s*([^|\n]+)",
    re.IGNORECASE)


def _parse_tags(text: str) -> list[dict[str, str]]:
    """Pull ``TECHNIQUE: id | name | tactic`` lines from the model's reply."""
    tags: list[dict[str, str]] = []
    for m in _TAG_RE.finditer(text or ""):
        tags.append({"technique_id": m.group(1).upper(),
                     "technique_name": m.group(2).strip(),
                     "tactic": m.group(3).strip()})
    if not tags:
        for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", text or ""):
            tags.append({"technique_id": m.group(0).upper(),
                         "technique_name": "", "tactic": ""})
    seen: set[str] = set()
    return [t for t in tags if not (t["technique_id"] in seen
                                    or seen.add(t["technique_id"]))]


def _outcome(name: str, payload: dict) -> str:
    if not isinstance(payload, dict):
        return "ok"
    if name == "attack_technique":
        return (f"found {payload.get('technique_id')}" if payload.get("found")
                else f"miss {payload.get('technique_id')}")
    if name == "attack_search":
        return f"matches={payload.get('count')}"
    if name == "attack_catalog":
        return f"techniques={payload.get('count')}"
    return "ok"


def _observation(name: str, payload: dict, tried: dict[str, str],
                 steps_left: int) -> str:
    keep: dict = {}
    if isinstance(payload, dict):
        for k in ("found", "technique_id", "name", "tactics", "description",
                  "did_you_mean", "matches", "count", "guidance", "error", "reason"):
            if k in payload:
                keep[k] = payload[k]
    tried_lines = "; ".join(f"{s} -> {o}" for s, o in tried.items()) or "(none yet)"
    return (f"OBSERVATION from {name}:\n{json.dumps(keep, default=str)[:2500]}\n"
            f"---\nPROGRESS: {steps_left} step(s) left. "
            f"Already called (do NOT repeat): {tried_lines}\n"
            f"Validate an id with attack_technique, or write your TECHNIQUE line(s) now.")


async def _validate(client, tags: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep only ids the catalogue confirms; use its authoritative name and tactic."""
    confirmed: list[dict[str, str]] = []
    for tag in tags:
        tid = tag.get("technique_id", "")
        try:
            res = (await client.call_tool(
                "attack_technique", {"technique_id": tid})).structured_content or {}
        except Exception:  # noqa: BLE001 — a lookup fault must not tag a guess
            continue
        if not res.get("found"):
            continue
        tactics = res.get("tactics") or []
        confirmed.append({
            "technique_id": res.get("technique_id", tid),
            "technique_name": res.get("name", ""),
            "tactic": (tag.get("tactic") if tag.get("tactic") in tactics
                       else (tactics[0] if tactics else "")),
        })
    seen: set[str] = set()
    return [t for t in confirmed if not (t["technique_id"] in seen
                                         or seen.add(t["technique_id"]))]


async def _run_weakness(client, llm, openai_tools, menu: str,
                        weakness: dict[str, Any], directive: str = "") -> list[dict]:
    """Drive the model through one weakness; return only catalogue-confirmed tags."""
    user = (f"{directive}## Weakness to map\n{_describe_weakness(weakness)}\n\n"
            f"## ATT&CK technique menu (id  name)\n{menu}\n\n"
            f"Search, validate your pick(s) with attack_technique, then give "
            f"your TECHNIQUE line(s).")
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user}]
    tried: dict[str, str] = {}

    for step in range(MAX_STEPS):
        messages = agentic.compact(messages, tried)
        try:
            msg = await agentic.chat(llm, messages, tools=openai_tools,
                                     max_tokens=MAX_TOKENS)
        except httpx.HTTPError as exc:
            log.warning("mitre model call failed at step %d: %s :: %s", step, exc,
                        agentic.err_body(exc)[:300])
            return []
        messages.append(msg)

        calls = msg.get("tool_calls")
        if not calls:
            return await _validate(client, _parse_tags((msg.get("content") or "").strip()))

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
                                 "content": (f"You already ran this exact call: "
                                             f"{name} -> {tried[key]}. Change the "
                                             f"arguments or give your TECHNIQUE "
                                             f"line(s) now.")})
                continue
            out = await client.call_tool(name, args)
            payload = out.structured_content or {
                "content": [getattr(b, "text", str(b)) for b in out.content]}
            tried[key] = _outcome(name, payload)
            messages.append({"role": "tool", "tool_call_id": call["id"],
                             "content": _observation(name, payload, tried, steps_left)})

    # Step limit hit mid-tool-use: one last no-tool turn for the verdict.
    messages.append({"role": "user", "content": (
        "Step limit reached. Do not call tools. Write your TECHNIQUE line(s) now "
        "from what your tools already confirmed, at least one.")})
    try:
        msg = await agentic.chat(llm, messages, max_tokens=MAX_TOKENS)
        raw = (msg.get("content") or "").strip()
    except httpx.HTTPError:
        raw = ""
    return await _validate(client, _parse_tags(raw))


class MitreWorker:
    """The MITRE agent: the ATT&CK-mapping loop, rendered as an AttackMap."""

    def __init__(self, llm: LlmClient) -> None:
        self._llm = llm  # unused: the loop drives the AWS model itself

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        weaknesses = ctx.upstream.get("weaknesses") or []
        if not weaknesses:
            log.info("no weaknesses upstream; emitting empty ATT&CK map")
            return AttackMap().model_dump(mode="json")

        by_id = {w.get("id") or w.get("weakness_id"): w for w in weaknesses}
        by_id.pop(None, None)
        known_ids = set(by_id)
        mapped: dict[str, list[dict[str, Any]]] = {}
        remaining = set(known_ids)

        try:
            async with Client(agentic.MCP_URL) as client, \
                    httpx.AsyncClient(timeout=agentic.LLM_TIMEOUT) as llm:
                tools = [t for t in (await client.list_tools()).tools
                         if t.name in AGENT_TOOLS]
                if not tools:
                    raise WorkFailed(
                        "mcp-native exposes none of the ATT&CK tools "
                        f"{sorted(AGENT_TOOLS)} — is attack_tool registered?")
                openai_tools = agentic.mcp_tools_to_openai(tools)
                catalog = (await client.call_tool(
                    "attack_catalog", {})).structured_content
                menu = _render_menu((catalog or {}).get("techniques", []))

                pre = agentic.directive_block(ctx.directive)
                for attempt in range(1, MAX_PASSES + 1):
                    progressed = False
                    for wid in sorted(remaining):
                        tags = await _run_weakness(
                            client, llm, openai_tools, menu, by_id[wid], pre)
                        if tags:
                            mapped[wid] = tags
                            remaining.discard(wid)
                            progressed = True
                    if not remaining:
                        log.info("all %d weaknesses tagged after %d pass(es)",
                                 len(known_ids), attempt)
                        break
                    if not progressed:
                        raise WorkFailed(
                            f"mapping loop confirmed no ATT&CK technique on pass "
                            f"{attempt} for: {', '.join(sorted(remaining))}")
                    log.info("pass %d: %d tagged, %d still to map", attempt,
                             len(known_ids) - len(remaining), len(remaining))
                else:
                    raise WorkFailed(
                        f"weaknesses left untagged after {MAX_PASSES} passes, "
                        f"which §5.4 forbids: {', '.join(sorted(remaining))}")
        except WorkFailed:
            raise
        except Exception as exc:  # noqa: BLE001 — retryable stage failure
            raise WorkFailed(
                f"mitre loop failed: {type(exc).__name__}: {exc}") from exc

        try:
            artifact = AttackMap(mappings=mapped)
        except ValidationError as exc:
            raise WorkFailed(
                f"ATT&CK map failed schema validation: "
                f"{json.dumps(exc.errors()[:3], default=str)[:300]}") from exc
        log.info("tagged %d weaknesses with ATT&CK techniques", len(artifact.mappings))
        return artifact.model_dump(mode="json")
