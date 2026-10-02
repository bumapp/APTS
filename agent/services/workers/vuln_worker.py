"""Vulnerability Assessment — the agentic hypothesis loop, in the agent (PRD §5.3).

This *is* the vuln agent: a genuine tool-driving loop. Per recon request it shows
the model the request and the HackTricks technique menu, lets it fetch article
examples from the knowledge base, and has it propose testable **hypotheses** —
speculation welcome, since the Exploitation agent is what later proves or kills
each one. It runs one fresh, small conversation per request (each judged on its
own) with three guards: a prompt-load guard (trim the injected menu), a
context-compaction guard, and a progress guard (no repeat fetches); after the
model concludes, an optional reflection round asks whether more are worth adding.

Each hypothesis becomes a ``Weakness`` so the rest of the pipeline consumes the
same ``VulnerabilityRegister`` from the DB. No scoring or ranking happens here —
CVSS was removed from this stage — and nothing is ``confirmed``: that is
Exploitation's word. The Adviser assigns severity/impact later, over the
weaknesses Exploitation actually proved.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

import httpx
from mcp import Client

from shared.llm import LlmClient
from shared.models import VulnerabilityRegister, Weakness

from agent.services.workers import agentic
from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("agent.workers.vuln")

# --- loop configuration (env-tunable) ------------------------------------- #
MAX_STEPS = int(os.environ.get("APTS_VULN_MAX_STEPS", "6"))
MAX_TOKENS = int(os.environ.get("APTS_VULN_MAX_TOKENS", "900"))
REFLECT_ROUNDS = int(os.environ.get("APTS_VULN_REFLECT_ROUNDS", "1"))
FORCE_FETCH = os.environ.get("APTS_VULN_FORCE_FETCH", "0") not in ("0", "false", "")
SKIP_NOISE = os.environ.get("APTS_VULN_SKIP_NOISE", "1") not in ("0", "false", "")
PROMPT_BUDGET_CHARS = int(os.environ.get("APTS_LOOP_PROMPT_CHARS", "6000"))
_NOISE = {"stylesheet", "image", "font", "media"}

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



# --------------------------------------------------------------------------- #
# The loop: one fresh conversation per request
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
    if not blocks and text.strip():
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


async def _reflect(llm, messages: list[dict], hypotheses: list[str]) -> list[str]:
    """Ask whether more hypotheses are worth adding; merge new ones. Bounded."""
    for _ in range(REFLECT_ROUNDS):
        current = "\n".join(f"{i}. {h.splitlines()[0]}"
                            for i, h in enumerate(hypotheses, 1))
        messages.append({"role": "user",
                         "content": REFLECT_PROMPT_TMPL.format(current=current)})
        try:
            msg = await agentic.chat(llm, messages, max_tokens=MAX_TOKENS)
        except httpx.HTTPError:
            break
        reply = (msg.get("content") or "").strip()
        messages.append({"role": "assistant", "content": reply})
        if reply.upper().replace(".", "").strip() == "DONE" or not reply:
            break
        added = _merge_hyps(hypotheses, _extract_hypotheses(reply))
        if not added:
            break
        hypotheses += added
        log.info("  reflection +%d hypothesis(es)", len(added))
    return hypotheses


async def _run_request(client, llm, openai_tools, menu: str, req: dict,
                       directive: str = "") -> list[str]:
    """Drive the model through one request and return its hypotheses."""
    head = directive + "## Request under test\n" + _render_request(req) \
        + "\n\n## HackTricks technique menu (slugs)\n"
    tail = ("\n\nDecide what is worth testing here, fetch examples if useful, then "
            "give your HYPOTHESIS block(s).")
    menu = _fit_menu(menu, len(SYSTEM_PROMPT) + len(head) + len(tail))
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": head + menu + tail}]
    tried: dict[str, str] = {}

    for step in range(MAX_STEPS):
        messages = agentic.compact(messages, tried)
        choice: Any = "auto"
        if FORCE_FETCH and step == 0:
            choice = {"type": "function", "function": {"name": "hacktricks_article"}}
        try:
            msg = await agentic.chat(llm, messages, tools=openai_tools,
                                     tool_choice=choice, max_tokens=MAX_TOKENS)
        except httpx.HTTPError as exc:
            log.warning("vuln model call failed at step %d: %s :: %s", step, exc,
                        agentic.err_body(exc)[:300])
            return []
        messages.append(msg)

        calls = msg.get("tool_calls")
        if not calls:
            hyps = _extract_hypotheses((msg.get("content") or "").strip())
            return await _reflect(llm, messages, hyps) if (REFLECT_ROUNDS and hyps) else hyps

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
                                 "content": (f"You already fetched this: {name} -> "
                                             f"{tried[key]}. Fetch a different "
                                             f"technique or write your HYPOTHESIS "
                                             f"block(s) now.")})
                continue
            out = await client.call_tool(name, args)
            payload = out.structured_content or {
                "content": [getattr(b, "text", str(b)) for b in out.content]}
            tried[key] = _outcome(payload)
            messages.append({"role": "tool", "tool_call_id": call["id"],
                             "content": _observation(name, payload, tried, steps_left)})

    # Step limit hit mid-tool-use: ask once, no tools.
    messages.append({"role": "user", "content": (
        "Step limit reached. Do not call tools. Write your HYPOTHESIS block(s) now, "
        "at least one.")})
    try:
        msg = await agentic.chat(llm, messages, max_tokens=MAX_TOKENS)
        raw = (msg.get("content") or "").strip()
        messages.append({"role": "assistant", "content": raw})
    except httpx.HTTPError:
        raw = ""
    hyps = _extract_hypotheses(raw)
    return await _reflect(llm, messages, hyps) if (REFLECT_ROUNDS and hyps) else hyps


# --------------------------------------------------------------------------- #
# Register assembly
# --------------------------------------------------------------------------- #

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
    origin = {k: req.get(k) for k in ("method", "path", "url", "content_type",
                                      "post_data") if req.get(k)}
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


def _req_signature(r: dict) -> tuple:
    """Shape of a request for dedup: (method, path, sorted param-names) — NOT the exact
    URL, so repeated transport/polling calls (socket.io ?t=&sid= change each time) share
    one signature and collapse to a single representative."""
    path = r.get("path") or urlparse(r.get("url", "")).path or "/"
    return (r.get("method", "GET"), path, tuple(sorted(_params_of(r))))


def _group_for_vuln(requests: list[dict]) -> list[dict]:
    """Deterministic PLUMBING (no judgement): collapse requests with the same
    (method, path, param-set) to one representative — killing repeated transport/dup
    calls — then order them grouped by the page that fired them. Nothing is scored,
    importance-ranked, or dropped on a vulnerability judgement; only exact-shape
    duplicates are merged (lossless: the representative keeps the shape)."""
    seen: set = set()
    reps: list[dict] = []
    for r in requests:
        sig = _req_signature(r)
        if sig in seen:
            continue
        seen.add(sig)
        reps.append(r)
    reps.sort(key=lambda r: (r.get("source_page") or "", r.get("path") or ""))
    return reps


def _finding_to_weakness(f: dict, idx: int) -> Weakness | None:
    """Render a recon FINDING (not a recorded request) as a Weakness hypothesis, so
    behavioural/discovery findings — hidden params, file-upload inputs, auth forms,
    unlinked endpoints — are proven by Exploitation, not just request-derived ones."""
    title = (str(f.get("finding") or "recon finding").strip())[:180]
    where = str(f.get("where") or "/").strip()
    cat = str(f.get("category") or "other")
    try:
        path = urlparse(where).path or where
    except Exception:  # noqa: BLE001
        path = where
    # Attach the RAW captured request recon matched to this finding as evidence, so the
    # exploit stage proves against the real request; fall back to a bare GET on `where`.
    req = f.get("request") if isinstance(f.get("request"), dict) else None
    if req:
        origin = {k: req.get(k) for k in ("method", "path", "url", "content_type",
                                          "post_data", "params") if req.get(k)}
        origin.setdefault("path", path)
    else:
        origin = {"method": "GET", "path": path, "url": where}
    try:
        return Weakness(
            id=f"W-{idx:03d}", title=f"{title} [{cat}]", asset=path,
            confidence="possible", evidence=[],
            rationale=(str(f.get("reason") or title))[:500], origin_request=origin)
    except Exception:  # noqa: BLE001
        log.warning("dropping unmappable finding: %s", title)
        return None


class VulnWorker:
    """The vulnerability agent: the hypothesis loop, rendered as a register."""

    def __init__(self, llm: LlmClient, results=None) -> None:
        self._llm = llm  # unused: the loop drives the AWS model itself
        self._results = results  # to load recon's AssetMap (findings) from the store

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        weaknesses: list[Weakness] = []
        try:
            async with Client(agentic.MCP_URL) as client, \
                    httpx.AsyncClient(timeout=agentic.LLM_TIMEOUT) as llm:
                tools = [t for t in (await client.list_tools()).tools
                         if t.name in AGENT_TOOLS]
                openai_tools = agentic.mcp_tools_to_openai(tools)
                overview = (await client.call_tool(
                    "hacktricks_overview", {})).structured_content
                menu = _render_menu((overview or {}).get("techniques", []))
                batch = (await client.call_tool(
                    "list_recorded_requests",
                    {"engagement_id": str(ctx.engagement_id)})).structured_content
                # No cap: recon already filtered to the high-interest requests,
                # so assess all of them (a proof run, not a bounded sample).
                requests = [r for r in (batch or {}).get("requests", [])
                            if not (SKIP_NOISE and r.get("resource_type") in _NOISE)]
                # Deterministic plumbing: collapse duplicate/transport requests to one
                # representative each and order them grouped by page (no judgement).
                before = len(requests)
                requests = _group_for_vuln(requests)
                log.info("vuln loop: %d request(s) after dedup/grouping (from %d): %s",
                         len(requests), before,
                         ", ".join(f"{r.get('method')} {r.get('path','?')}" for r in requests))

                pre = agentic.directive_block(ctx.directive)
                for req in requests:
                    log.info("=== %s %s ===", req.get("method"), req.get("path"))
                    hyps = await _run_request(client, llm, openai_tools, menu, req, pre)
                    for hypothesis in hyps:
                        weakness = _to_weakness(hypothesis, req, len(weaknesses) + 1)
                        if weakness:
                            weaknesses.append(weakness)
        except Exception as exc:  # noqa: BLE001 — retryable stage failure
            raise WorkFailed(f"vuln loop failed: {type(exc).__name__}: {exc}") from exc

        # Fold recon's graded FINDINGS (handed over in the AssetMap) into the register —
        # high/medium only, de-duped against request-derived weaknesses by (title, asset).
        req_weaknesses = len(weaknesses)
        seen = {(w.title, w.asset) for w in weaknesses}
        # recon's AssetMap: from the store (driven mode), falling back to ctx.upstream.
        recon_asset = {}
        if self._results is not None:
            try:
                recon_asset = self._results.load(ctx.engagement_id, "recon") or {}
            except Exception:  # noqa: BLE001
                recon_asset = {}
        findings = recon_asset.get("findings") or (ctx.upstream or {}).get("findings") or []
        for f in findings if isinstance(findings, list) else []:
            if not isinstance(f, dict) or str(f.get("grade", "")).lower() not in ("high", "medium"):
                continue
            w = _finding_to_weakness(f, len(weaknesses) + 1)
            if w and (w.title, w.asset) not in seen:
                seen.add((w.title, w.asset))
                weaknesses.append(w)

        register = VulnerabilityRegister(weaknesses=weaknesses)
        log.info("register: %d weaknesses (%d from requests, %d from recon findings)",
                 len(register.weaknesses), req_weaknesses,
                 len(register.weaknesses) - req_weaknesses)
        return register.model_dump(mode="json")
