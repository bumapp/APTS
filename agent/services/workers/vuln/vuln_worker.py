"""Vulnerability Assessment — the agentic hypothesis loop, on LangGraph (PRD §5.3).

This *is* the vuln agent: a genuine tool-driving loop. Per recon request it shows
the model the request and the HackTricks technique menu, lets it fetch article
examples from the knowledge base, and has it propose testable **hypotheses** —
speculation welcome, since the Exploitation agent is what later proves or kills
each one. It runs one fresh, small conversation per request (each judged on its
own) with three guards: a prompt-load guard (trim the injected menu), a
context-compaction guard, and a progress guard (no repeat fetches); after the
model concludes, an optional reflection round asks whether more are worth adding.

Engine: a ``create_react_agent`` graph driving a LangChain chat model
(:func:`shared.llm.build_chat_model`), with the MCP tools wrapped as LangChain
tools over the repo's mcp-v2 ``Client`` (:func:`agentic.as_langchain_tools`);
every model + tool call is captured by the Langfuse callback when configured. The
hard step cap is the graph ``recursion_limit``.

Each hypothesis becomes a ``Weakness`` so the rest of the pipeline consumes the
same ``VulnerabilityRegister`` from the DB. No scoring or ranking happens here —
CVSS was removed from this stage — and nothing is ``confirmed``: that is
Exploitation's word. The Adviser assigns severity/impact later, over the
weaknesses Exploitation actually proved.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from langgraph.errors import GraphRecursionError
from langgraph.prebuilt import create_react_agent
from mcp import Client

from shared import prompts
from shared.llm import (build_chat_model, flush, run_config, set_run_output,
                        trace_run)
from shared.models import VulnerabilityRegister, Weakness

from agent.services.workers.common import common_agentic as agentic
from agent.services.workers.base import WorkContext, WorkFailed
from .vuln_constants import (
    AGENT_TOOLS, CONCURRENCY, MAX_STEPS, MAX_TOKENS, PROMPT_BUDGET_CHARS,
    RECURSION_LIMIT, REFLECT_PROMPT_TMPL, REFLECT_ROUNDS, SKIP_NOISE,
    VULN_SYSTEM_PROMPT_ID, _NOISE)

log = logging.getLogger("agent.workers.vuln")


# --------------------------------------------------------------------------- #
# Request + menu rendering, hypothesis parsing (pure)
# --------------------------------------------------------------------------- #

def _params_of(req: dict) -> list[str]:
    """Best-effort list of the parameter names a request carries.

    keep_blank_values so an empty value (e.g. a param present with no value) still counts —
    an input endpoint observed with an empty query must not look input-less."""
    params: list[str] = []
    params += [k for k, _ in parse_qsl(urlparse(req.get("url") or "").query,
                                       keep_blank_values=True)]
    body = req.get("post_data")
    if isinstance(body, str) and body.strip():
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                params += list(obj.keys())
        except json.JSONDecodeError:
            params += [k for k, _ in parse_qsl(body, keep_blank_values=True)]
    seen: set[str] = set()
    return [p for p in params if not (p in seen or seen.add(p))]


def _render_request(req: dict) -> str:
    """Compact, model-facing description of a single observed request."""
    params = _params_of(req)
    lines = [f"Method: {req.get('method')}", f"Path:   {req.get('path')}",
             f"URL:    {req.get('url')}"]
    if req.get("content_type"):
        lines.append(f"Content-Type: {req['content_type']}")
    lines.append(f"Parameters: {', '.join(params) if params else '(none seen)'}")
    body = req.get("post_data")
    if isinstance(body, str) and body.strip():
        lines.append(f"Body: {body[:500]}")
    return "\n".join(lines)


def _render_menu(techniques: list[dict]) -> str:
    """Technique menu injected per conversation — slugs only, comma-joined."""
    return ", ".join(t["slug"] for t in techniques)


def _fit_menu(menu: str, fixed_chars: int) -> str:
    """PROMPT-LOAD GUARD: trim the menu so the opening prompt stays in budget."""
    room = PROMPT_BUDGET_CHARS - fixed_chars
    if room <= 0 or len(menu) <= room:
        return menu
    kept, used = [], 0
    for slug in menu.split(", "):
        if used + len(slug) + 2 > room:
            break
        kept.append(slug)
        used += len(slug) + 2
    dropped = len(menu.split(", ")) - len(kept)
    return ", ".join(kept) + (f" … (+{dropped} more — call hacktricks_overview "
                              f"for the full list)")


def _outcome(payload: dict) -> str:
    if not isinstance(payload, dict):
        return "ok"
    if payload.get("found") is not None or "slug" in payload:
        return (f"found={payload.get('found')} slug={payload.get('slug')}")
    if "count" in payload:
        return f"techniques={payload.get('count')}"
    return "ok"


def _observation(name: str, payload: dict, tried: dict[str, str],
                 steps_left: int) -> str:
    keep: dict = {}
    if isinstance(payload, dict):
        for k in ("found", "slug", "title", "truncated", "did_you_mean",
                  "guidance", "count", "error"):
            if k in payload:
                keep[k] = payload[k]
        if isinstance(payload.get("content"), str):
            keep["content"] = payload["content"][:2500]
        if payload.get("techniques"):
            keep["techniques"] = [t["slug"] for t in payload["techniques"]]
    tried_lines = "; ".join(f"{s} -> {o}" for s, o in tried.items()) or "(none yet)"
    return (f"OBSERVATION from {name}:\n{json.dumps(keep, default=str)[:3000]}\n"
            f"---\nPROGRESS: {steps_left} step(s) left. "
            f"Already fetched (do NOT repeat): {tried_lines}\n"
            f"Fetch another technique if it helps, or write your HYPOTHESIS block(s) now.")


def _observe(name: str, payload: Any, tried: dict[str, str]) -> str:
    """Wrap the observation for the tool wrapper; steps_left is approximate under LangGraph."""
    steps_left = max(0, MAX_STEPS - len(tried))
    return _observation(name, payload if isinstance(payload, dict) else {},
                        tried, steps_left)


# Non-answers the model emits when it refuses or runs out of budget — these must
# NOT be captured as freeform "weaknesses" (they flooded the register as
# "(freeform) Sorry, need more steps to process this request." and starved the
# downstream proving stages of real hypotheses).
_JUNK_MARKERS = ("sorry", "need more steps", "cannot process", "unable to process",
                 "no hypothes", "step limit", "can't process", "i cannot process",
                 "no vulnerabilit")


def _is_junk_reply(text: str) -> bool:
    """True if the reply is a refusal / ran-out-of-steps non-answer, not a hypothesis."""
    t = text.strip().lower()
    return len(t) < 15 or any(j in t for j in _JUNK_MARKERS)


def _extract_hypotheses(text: str) -> list[str]:
    """Pull HYPOTHESIS/WHY blocks from the model's message, leniently."""
    blocks: list[str] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"\s*HYPOTHESIS:\s*(.+)$", line, re.IGNORECASE)
        if not m:
            continue
        why = ""
        if i + 1 < len(lines):
            wm = re.match(r"\s*WHY:\s*(.+)$", lines[i + 1], re.IGNORECASE)
            if wm:
                why = wm.group(1).strip()
        blocks.append(m.group(1).strip() + (f"\n   Hypothesis: {why}" if why else ""))
    # Freeform fallback ONLY for a substantive reply — never wrap a refusal /
    # "need more steps" non-answer as a (freeform) weakness.
    if not blocks and text.strip() and not _is_junk_reply(text):
        blocks.append("(freeform) " + text.strip().splitlines()[0]
                      + f"\n   Hypothesis: {text.strip()}")
    return blocks


def _norm_hyp(h: str) -> str:
    return re.sub(r"\s+", " ", h.splitlines()[0].lower()).strip()


def _merge_hyps(existing: list[str], new: list[str]) -> list[str]:
    seen = {_norm_hyp(h) for h in existing}
    added = []
    for h in new:
        key = _norm_hyp(h)
        if key and key not in seen:
            seen.add(key)
            added.append(h)
    return added


def _to_weakness(hypothesis: str, req: dict, idx: int) -> Weakness | None:
    """Render one hypothesis as a Weakness — a plain hypothesis, no CVSS scoring.

    The agentic vuln loop proposes; it does not score. The Weakness carries the
    title, the asset, and the model's reasoning, nothing more.
    """
    lines = hypothesis.splitlines()
    title = (lines[0].strip() or "unspecified weakness")[:200]
    rationale = ""
    for line in lines[1:]:
        if line.strip().lower().startswith("hypothesis:"):
            rationale = line.split(":", 1)[1].strip()[:500]
    # Carry the exact request forward so Exploitation needs no lookup tool.
    # source_page is the SPA/client route the browser was ON when this request
    # fired — for a reflected/DOM XSS proof that is the page where the value is
    # rendered (xss_prove's spa_page), which the API path alone can't give.
    origin = {k: req.get(k) for k in ("method", "path", "url", "content_type",
                                      "post_data", "source_page") if req.get(k)}
    origin["params"] = _params_of(req)
    try:
        return Weakness(
            id=f"W-{idx:03d}", title=title, asset=req.get("path") or "/",
            confidence="possible",
            rationale=rationale or hypothesis[:500], evidence=[],
            origin_request=origin)
    except Exception:  # noqa: BLE001 — a malformed item must not kill the stage
        log.warning("dropping unmappable hypothesis: %s", title)
        return None


# --------------------------------------------------------------------------- #
# The loop: one fresh conversation per request
# --------------------------------------------------------------------------- #

def _generic_probe(req: dict) -> list[str]:
    """Fallback 'hypothesis' when the model gives no usable one: carry the endpoint
    forward so exploit still probes it. The recorded request is the valuable seed —
    far more than the model's prose — so a high-interest endpoint is never dropped
    just because the vuln model stalled, refused, or errored."""
    params = ", ".join(_params_of(req)) or "no observed params"
    return [f"Untargeted probe — test {req.get('method', 'GET')} "
            f"{req.get('path', '/')} ({params}) for injection, XSS, and "
            f"broken access control"]


async def _reflect(model, messages: list, hypotheses: list[str], config: dict) -> list[str]:
    """Ask (without tools) whether more hypotheses are worth adding; merge them.

    The reflection turn deliberately uses the bare model, not the tool-bound
    agent, so it cannot wander back into fetching. Bounded by ``REFLECT_ROUNDS``.
    """
    convo = list(messages)
    for _ in range(REFLECT_ROUNDS):
        current = "\n".join(f"{i}. {h.splitlines()[0]}"
                            for i, h in enumerate(hypotheses, 1))
        convo.append(agentic.HumanMessage(
            content=REFLECT_PROMPT_TMPL.format(current=current)))
        try:
            reply_msg = await model.ainvoke(convo, config=config)
        except Exception:  # noqa: BLE001 — reflection is best-effort
            break
        reply = agentic.message_text(reply_msg)
        convo.append(agentic.AIMessage(content=reply))
        if reply.upper().replace(".", "").strip() == "DONE" or not reply:
            break
        added = _merge_hyps(hypotheses, _extract_hypotheses(reply))
        if not added:
            break
        hypotheses += added
        log.info("  reflection +%d hypothesis(es)", len(added))
    return hypotheses


async def _run_request(model, tools, tried: dict[str, str], menu: str, req: dict,
                       directive: str, config: dict, system_prompt: str,
                       trace_prompt=None) -> list[str]:
    """Drive the model through one request via a fresh react graph; return hypotheses."""
    tried.clear()  # the repeat-fetch guard is per-request, as in the original
    head = directive + "## Request under test\n" + _render_request(req) \
        + "\n\n## HackTricks technique menu (slugs)\n"
    tail = ("\n\nDecide what is worth testing here, fetch examples if useful, then "
            "give your HYPOTHESIS block(s).")
    fitted = _fit_menu(menu, len(system_prompt) + len(head) + len(tail))
    user = head + fitted + tail

    agent = create_react_agent(
        model, tools, prompt=system_prompt,
        # CONTEXT_BUDGET_CHARS bounds the *conversation*; PROMPT_BUDGET_CHARS
        # (used only by _fit_menu above) bounds the initial menu injection.
        pre_model_hook=agentic.compacting_hook(agentic.CONTEXT_BUDGET_CHARS))
    invoke_cfg = {**config, "recursion_limit": RECURSION_LIMIT}

    # One root span for the whole run (graph invoke + reflection) so it is a
    # single Langfuse trace rather than one-trace-per-model-call, linked to the
    # prompt version so a prompt regression is traceable.
    with trace_run(name="vuln-assess", run_input=user, prompt=trace_prompt) as span:
        try:
            result = await agent.ainvoke(
                {"messages": [agentic.HumanMessage(content=user)]}, config=invoke_cfg)
            text = agentic.final_text(result)
            final_messages = result.get("messages", [])
        except GraphRecursionError:
            # Step limit hit mid-tool-use: ask once, no tools — mirrors the original.
            log.info("vuln loop hit recursion limit; asking for hypotheses without tools")
            convo = agentic.to_lc_messages(system_prompt, user)
            convo.append(agentic.HumanMessage(content=(
                "Step limit reached. Do not call tools. Write your HYPOTHESIS "
                "block(s) now, at least one.")))
            try:
                msg = await model.ainvoke(convo, config=config)
                text = agentic.message_text(msg)
                final_messages = [*convo, agentic.AIMessage(content=text)]
            except Exception as exc:  # noqa: BLE001
                log.warning("vuln fallback call failed: %s", exc)
                set_run_output(span, "(model call failed)")
                return _generic_probe(req)
        except Exception as exc:  # noqa: BLE001 — one bad request must not kill the stage
            log.warning("vuln request loop failed: %s: %s", type(exc).__name__, exc)
            set_run_output(span, "(request loop failed)")
            return _generic_probe(req)

        hyps = _extract_hypotheses(text)
        if REFLECT_ROUNDS and hyps:
            hyps = await _reflect(model, final_messages, hyps, config)
        if not hyps:
            # No usable hypothesis — carry the endpoint forward so exploit probes it.
            hyps = _generic_probe(req)
        set_run_output(span, "\n".join(h.splitlines()[0] for h in hyps) or "(none)")
        return hyps


class VulnWorker:
    """The vulnerability agent: the hypothesis loop, rendered as a register."""

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        weaknesses: list[Weakness] = []
        model = build_chat_model("vuln", max_tokens=MAX_TOKENS)
        config = run_config(engagement_id=str(ctx.engagement_id), agent="vuln")
        system = prompts.get(VULN_SYSTEM_PROMPT_ID)  # Langfuse-backed, default fallback
        pre = agentic.directive_block(ctx.directive)
        with trace_run(name="vuln",
                       run_input=f"assess recon requests for {ctx.target_url}",
                       engagement_id=str(ctx.engagement_id)) as _stage:
            try:
                # One client just to fetch the shared, read-only inputs.
                async with Client(agentic.MCP_URL) as client:
                    overview = (await client.call_tool(
                        "hacktricks_overview", {})).structured_content
                    menu = _render_menu((overview or {}).get("techniques", []))
                    batch = (await client.call_tool(
                        "list_recorded_requests",
                        {"engagement_id": str(ctx.engagement_id)})).structured_content
                # No cap: recon already filtered to the high-interest requests.
                requests = [r for r in (batch or {}).get("requests", [])
                            if not (SKIP_NOISE and r.get("resource_type") in _NOISE)]
                log.info("vuln loop: assessing %d request(s) (<=%d in parallel): %s",
                         len(requests), CONCURRENCY,
                         ", ".join(r.get("path", "?") for r in requests))

                sem = asyncio.Semaphore(CONCURRENCY)

                async def _assess(req: dict) -> tuple[dict, list[str]]:
                    # Each request is independent: its own MCP session, repeat-call
                    # ledger and tools, so they run concurrently without racing.
                    async with sem:
                        try:
                            async with Client(agentic.MCP_URL) as rc:
                                descriptors = [t for t in (await rc.list_tools()).tools
                                               if t.name in AGENT_TOOLS]
                                tried: dict[str, str] = {}
                                tools = agentic.as_langchain_tools(
                                    rc, descriptors, tried=tried,
                                    outcome=lambda _name, payload: _outcome(payload),
                                    observe=_observe)
                                log.info("=== %s %s ===",
                                         req.get("method"), req.get("path"))
                                hyps = await _run_request(
                                    model, tools, tried, menu, req, pre, config,
                                    system.text, system.trace_prompt)
                                return req, hyps
                        except Exception as exc:  # noqa: BLE001 — one request must not kill the stage
                            log.warning("vuln request %s failed: %s",
                                        req.get("path"), exc)
                            return req, []

                results = await asyncio.gather(*(_assess(r) for r in requests))
                # Assemble in request order so weakness ids stay stable (W-001…).
                for req, hyps in results:
                    for hypothesis in hyps:
                        weakness = _to_weakness(hypothesis, req, len(weaknesses) + 1)
                        if weakness:
                            weaknesses.append(weakness)
            except Exception as exc:  # noqa: BLE001 — retryable stage failure
                raise WorkFailed(f"vuln loop failed: {type(exc).__name__}: {exc}") from exc
            finally:
                flush()  # short-lived stage: push any buffered Langfuse spans
            set_run_output(_stage, {
                "weaknesses": len(weaknesses),
                "items": [{"id": w.id, "title": w.title, "asset": w.asset}
                          for w in weaknesses]})

        register = VulnerabilityRegister(weaknesses=weaknesses)
        log.info("register: %d weaknesses from hypotheses", len(register.weaknesses))
        return register.model_dump(mode="json")
