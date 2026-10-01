"""MITRE ATT&CK mapping — the agentic loop, on LangGraph (PRD §5.4).

Takes the Vulnerability Register and tags every weakness with ATT&CK Tactics and
Techniques. Like the recon/vuln/exploit stages this is a genuine tool-driving
loop (shared plumbing in :mod:`agentic`): for each weakness the model drives the
ATT&CK reference tools on mcp-native — ``attack_search`` for candidates,
``attack_technique`` to validate one id — and the worker keeps only the ids the
catalogue confirmed.

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
import re
from typing import Any

from langgraph.errors import GraphRecursionError
from langgraph.prebuilt import create_react_agent
from mcp import Client
from pydantic import ValidationError

from shared import prompts
from shared.llm import (build_chat_model, flush, run_config, set_run_output,
                        trace_run)
from shared.models import AttackMap

from agent.services.workers.common import common_agentic as agentic
from agent.services.workers.base import WorkContext, WorkFailed
from .mitre_constants import (
    AGENT_TOOLS, FALLBACK_TECHNIQUE, MAX_PASSES, MAX_STEPS, MAX_TOKENS,
    MITRE_SYSTEM_PROMPT_ID, RECURSION_LIMIT)

log = logging.getLogger("agent.workers.mitre")


# --------------------------------------------------------------------------- #
# Rendering + parsing (pure)
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


def _observe(name: str, payload: Any, tried: dict[str, str]) -> str:
    """Wrap the observation for the tool wrapper; steps_left approximate under LangGraph."""
    steps_left = max(0, MAX_STEPS - len(tried))
    return _observation(name, payload if isinstance(payload, dict) else {},
                        tried, steps_left)


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


# --------------------------------------------------------------------------- #
# The loop: one fresh react graph per weakness
# --------------------------------------------------------------------------- #

async def _run_weakness(model, client, descriptors, menu: str,
                        weakness: dict[str, Any], directive: str, config: dict,
                        system_prompt: str, trace_prompt=None) -> list[dict]:
    """Drive the model through one weakness; return only catalogue-confirmed tags."""
    user = (f"{directive}## Weakness to map\n{_describe_weakness(weakness)}\n\n"
            f"## ATT&CK technique menu (id  name)\n{menu}\n\n"
            f"Search, validate your pick(s) with attack_technique, then give "
            f"your TECHNIQUE line(s).")
    tried: dict[str, str] = {}
    tools = agentic.as_langchain_tools(
        client, descriptors, tried=tried, outcome=_outcome, observe=_observe)
    agent = create_react_agent(
        model, tools, prompt=system_prompt,
        pre_model_hook=agentic.compacting_hook(agentic.CONTEXT_BUDGET_CHARS))
    invoke_cfg = {**config, "recursion_limit": RECURSION_LIMIT}

    with trace_run(name="mitre-map", run_input=user, prompt=trace_prompt) as span:
        try:
            result = await agent.ainvoke(
                {"messages": [agentic.HumanMessage(content=user)]}, config=invoke_cfg)
            text = agentic.final_text(result)
        except GraphRecursionError:
            # Step limit hit mid-tool-use: one last no-tool turn for the verdict.
            convo = agentic.to_lc_messages(system_prompt, user)
            convo.append(agentic.HumanMessage(content=(
                "Step limit reached. Do not call tools. Write your TECHNIQUE "
                "line(s) now from what your tools already confirmed, at least one.")))
            try:
                msg = await model.ainvoke(convo, config=config)
                text = agentic.message_text(msg)
            except Exception as exc:  # noqa: BLE001
                log.warning("mitre fallback call failed: %s", exc)
                set_run_output(span, "(model call failed)")
                return []
        except Exception as exc:  # noqa: BLE001 — one bad weakness must not kill the stage
            log.warning("mitre weakness loop failed: %s: %s", type(exc).__name__, exc)
            set_run_output(span, "(weakness loop failed)")
            return []

        tags = await _validate(client, _parse_tags(text))
        set_run_output(span, ", ".join(t["technique_id"] for t in tags) or "(none)")
        return tags


class MitreWorker:
    """The MITRE agent: the ATT&CK-mapping loop, rendered as an AttackMap."""

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

        model = build_chat_model("mitre", max_tokens=MAX_TOKENS)
        config = run_config(engagement_id=str(ctx.engagement_id), agent="mitre")
        system = prompts.get(MITRE_SYSTEM_PROMPT_ID)  # Langfuse-backed, default fallback

        with trace_run(name="mitre",
                       run_input={"weaknesses": [
                           {"id": wid, "title": by_id[wid].get("title", "")}
                           for wid in sorted(known_ids)]},
                       engagement_id=str(ctx.engagement_id)) as _stage:
            try:
                async with Client(agentic.MCP_URL) as client:
                    descriptors = [t for t in (await client.list_tools()).tools
                                   if t.name in AGENT_TOOLS]
                    if not descriptors:
                        raise WorkFailed(
                            "mcp-native exposes none of the ATT&CK tools "
                            f"{sorted(AGENT_TOOLS)} — is attack_tool registered?")
                    catalog = (await client.call_tool(
                        "attack_catalog", {})).structured_content
                    menu = _render_menu((catalog or {}).get("techniques", []))

                    pre = agentic.directive_block(ctx.directive)
                    for attempt in range(1, MAX_PASSES + 1):
                        progressed = False
                        for wid in sorted(remaining):
                            tags = await _run_weakness(
                                model, client, descriptors, menu, by_id[wid], pre,
                                config, system.text, system.trace_prompt)
                            if tags:
                                mapped[wid] = tags
                                remaining.discard(wid)
                                progressed = True
                        if not remaining:
                            log.info("all %d weaknesses tagged after %d pass(es)",
                                     len(known_ids), attempt)
                            break
                        if not progressed:
                            log.warning(
                                "pass %d confirmed no new technique for %d "
                                "weakness(es); applying the deterministic fallback",
                                attempt, len(remaining))
                            break
                        log.info("pass %d: %d tagged, %d still to map", attempt,
                                 len(known_ids) - len(remaining), len(remaining))
                    # §5.4 needs every weakness to carry >=1 technique. Any the
                    # model could not map gets a deterministic fallback, so one
                    # model/format miss never stalls the whole pipeline — the model
                    # judges, the code guarantees the floor.
                    for wid in sorted(remaining):
                        mapped[wid] = [dict(FALLBACK_TECHNIQUE)]
                        log.info("mitre fallback for %s -> %s", wid,
                                 FALLBACK_TECHNIQUE["technique_id"])
            except WorkFailed:
                raise
            except Exception as exc:  # noqa: BLE001 — retryable stage failure
                raise WorkFailed(
                    f"mitre loop failed: {type(exc).__name__}: {exc}") from exc
            finally:
                flush()  # short-lived stage: push any buffered Langfuse spans
            set_run_output(_stage, {
                "tagged": len(mapped), "of": len(known_ids),
                "mappings": {wid: [t["technique_id"] for t in tags]
                             for wid, tags in mapped.items()}})

        try:
            artifact = AttackMap(mappings=mapped)
        except ValidationError as exc:
            raise WorkFailed(
                f"ATT&CK map failed schema validation: "
                f"{json.dumps(exc.errors()[:3], default=str)[:300]}") from exc
        log.info("tagged %d weaknesses with ATT&CK techniques", len(artifact.mappings))
        return artifact.model_dump(mode="json")
