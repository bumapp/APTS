"""An AI reasoning loop that acts as the Vulnerability (hypothesis) agent.

Where the exploit loop *proves* a vulnerability, this loop *proposes* them. It is
the same kind of genuine agentic loop — the local model drives MCP tools — but
its job is analysis, not exploitation, and its tools are the knowledge base:

    * hacktricks_overview  — the technique menu (every slug + title)
    * hacktricks_article   — one technique's worked examples/payloads, by slug

Design, per the methodology being modelled:

* **Recon output, minus the firehose.** The loop takes the *batch* of requests
  recon observed (via ``list_recorded_requests``) and runs **one fresh, small
  conversation per request** — each request is judged on its own, independent of
  the others. Small per-item context matters a lot for a slow local model.
* **The model chooses techniques.** It is shown the HackTricks overview (the
  technique menu) and decides which classes are worth testing against *this*
  request. For a technique it wants examples for, it fetches the article.
* **A hypothesis every time.** Even with no matching article, the model must
  still commit to at least one testable hypothesis. Speculation is encouraged —
  a plausible-but-probably-wrong idea is a valid thing to surface here; the
  exploit loop is what later proves or kills it.

The output is aggregated into the exact ``## Suspected vulnerabilities`` block
the exploit loop consumes, so this loop feeds straight into that one.

Run (with the mcp-native service and the llama service up):
    python -m mcp_native.vuln_loop                 # latest recon scan
    APTS_VULN_MAX_REQUESTS=3 python -m mcp_native.vuln_loop
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlparse

import httpx
from mcp import Client

MCP_URL = os.environ.get("APTS_MCP_URL", "http://localhost:9000/mcp")
LLM_URL = os.environ.get("APTS_LOOP_LLM_URL", "http://localhost:18080/v1/chat/completions")
LLM_MODEL = os.environ.get("APTS_LOOP_LLM_MODEL", "qwen3-8b")
MAX_STEPS = int(os.environ.get("APTS_VULN_MAX_STEPS", "6"))
LLM_TIMEOUT = float(os.environ.get("APTS_LOOP_LLM_TIMEOUT", "900"))
MAX_REQUESTS = int(os.environ.get("APTS_VULN_MAX_REQUESTS", "8"))
# Cap generation so a call can't run away on the slow CPU model — enough room for
# a few hypothesis blocks or one tool call.
MAX_TOKENS = int(os.environ.get("APTS_VULN_MAX_TOKENS", "700"))
SKIP_NOISE = os.environ.get("APTS_VULN_SKIP_NOISE", "1") not in ("0", "false", "")
# Force the model to consult the knowledge base at least once (step 0) before it
# is allowed to conclude — so the fetch->examples->hypothesis flow actually runs
# rather than the model jumping straight to a guess. Set to 0 for max speed.
FORCE_FETCH = os.environ.get("APTS_VULN_FORCE_FETCH", "1") not in ("0", "false", "")
# Optional comma-separated path substrings to restrict the batch to (demo focus).
ONLY = [s for s in os.environ.get("APTS_VULN_ONLY", "").split(",") if s.strip()]
_CONTEXT_BUDGET_CHARS = int(os.environ.get("APTS_LOOP_CONTEXT_CHARS", "16000"))
# Budget for the FIRST prompt (system + request + injected menu). The running
# conversation is guarded by _compact once tool results exist; this guards the
# opening turn, whose bulk is the injected technique menu.
_PROMPT_BUDGET_CHARS = int(os.environ.get("APTS_LOOP_PROMPT_CHARS", "6000"))

# Static assets carry essentially no server-side attack surface; skip them so the
# model spends its (slow) turns on real endpoints. Toggle with APTS_VULN_SKIP_NOISE=0.
_NOISE_RESOURCE_TYPES = {"stylesheet", "image", "font", "media"}

# The vulnerability agent proposes; it does not probe. It is handed ONLY the
# knowledge-base tools — never sqlmap/http_request — both because that is its job
# and because a lean tool list keeps the prompt (and CPU prefill) small.
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


def _params_of(req: dict) -> list[str]:
    """Best-effort list of the parameter names a request carries."""
    params: list[str] = []
    q = urlparse(req.get("url") or "").query
    params += [k for k, _ in parse_qsl(q)]
    body = req.get("post_data")
    if isinstance(body, str) and body.strip():
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                params += list(obj.keys())
        except json.JSONDecodeError:
            params += [k for k, _ in parse_qsl(body)]
    # de-dup, preserve order
    seen: set[str] = set()
    return [p for p in params if not (p in seen or seen.add(p))]


def _render_request(req: dict) -> str:
    """Compact, model-facing description of a single observed request."""
    params = _params_of(req)
    lines = [
        f"Method: {req.get('method')}",
        f"Path:   {req.get('path')}",
        f"URL:    {req.get('url')}",
    ]
    if req.get("content_type"):
        lines.append(f"Content-Type: {req['content_type']}")
    if req.get("resource_type"):
        lines.append(f"Resource-Type: {req['resource_type']}")
    lines.append(f"Parameters: {', '.join(params) if params else '(none seen)'}")
    body = req.get("post_data")
    if isinstance(body, str) and body.strip():
        lines.append(f"Body: {body[:500]}")
    return "\n".join(lines)


def _render_menu(techniques: list[dict]) -> str:
    """The technique menu injected into every per-request conversation.

    Slugs only, comma-joined: the slugs are self-describing (``sql-injection``,
    ``xss-cross-site-scripting``, …) and this is the full corpus, but dropping the
    titles roughly halves the injected size — which on a slow CPU model is the
    difference between a workable and an unworkable per-call latency.
    """
    return ", ".join(t["slug"] for t in techniques)


def mcp_tools_to_openai(tools) -> list[dict]:
    return [
        {"type": "function", "function": {
            "name": t.name,
            "description": t.description or "",
            "parameters": t.input_schema or {"type": "object", "properties": {}},
        }}
        for t in tools
    ]


def _sig(name: str, args: dict) -> str:
    return name + ":" + json.dumps(args, sort_keys=True, default=str)


def _outcome(name: str, payload: dict) -> str:
    if not isinstance(payload, dict):
        return "ok"
    if name == "hacktricks_article":
        return (f"found={payload.get('found')} slug={payload.get('slug')}"
                if payload.get("found")
                else f"miss slug={payload.get('slug')}")
    if name == "hacktricks_overview":
        return f"techniques={payload.get('count')}"
    return "ok"


def _observation(name: str, payload: dict, tried: dict[str, str],
                 steps_left: int) -> str:
    """Structured feedback wrapped around a tool result (article text, etc.)."""
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
    return (
        f"OBSERVATION from {name}:\n{json.dumps(keep, default=str)[:3000]}\n"
        f"---\nPROGRESS: {steps_left} step(s) left. "
        f"Already fetched (do NOT repeat): {tried_lines}\n"
        f"Fetch another technique if it helps, or write your HYPOTHESIS block(s) now."
    )


def _compact(messages: list[dict], tried: dict[str, str]) -> list[dict]:
    size = sum(len(str(m.get("content") or "")) for m in messages)
    if size <= _CONTEXT_BUDGET_CHARS or len(messages) <= 4:
        return messages
    system, user = messages[0], messages[1]
    tail = messages[-2:]
    progress = "PROGRESS SO FAR (compacted to save context):\n" + "\n".join(
        f"- {s} -> {o}" for s, o in tried.items())
    return [system, user, {"role": "user", "content": progress}, *tail]


def _fit_menu(menu: str, fixed_chars: int) -> str:
    """Trim the injected technique menu so the opening prompt stays in budget.

    The menu (110 comma-joined slugs) is the largest and most reducible part of
    the first turn. When ``fixed_chars`` (system + request + trailer) plus the
    menu would blow _PROMPT_BUDGET_CHARS, the menu is cut at a slug boundary and
    a note points the model at hacktricks_overview for the rest — the same
    "compact, don't drop" spirit as the context guard, applied before step 0.
    """
    room = _PROMPT_BUDGET_CHARS - fixed_chars
    if room <= 0 or len(menu) <= room:
        return menu
    slugs = menu.split(", ")
    kept, used = [], 0
    for s in slugs:
        if used + len(s) + 2 > room:
            break
        kept.append(s)
        used += len(s) + 2
    dropped = len(slugs) - len(kept)
    note = (f" … (+{dropped} more techniques — call hacktricks_overview for the "
            f"full list)")
    return ", ".join(kept) + note


def _extract_hypotheses(text: str) -> list[str]:
    """Pull hypothesis blocks out of the model's final message, leniently.

    Prefers the requested ``HYPOTHESIS:``/``WHY:`` shape; if the model wrote
    something else, the whole message is kept as one block so raw output is never
    lost.
    """
    blocks: list[str] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"\s*HYPOTHESIS:\s*(.+)$", line, re.IGNORECASE)
        if not m:
            continue
        title = m.group(1).strip()
        why = ""
        if i + 1 < len(lines):
            wm = re.match(r"\s*WHY:\s*(.+)$", lines[i + 1], re.IGNORECASE)
            if wm:
                why = wm.group(1).strip()
        blocks.append(title + (f"\n   Hypothesis: {why}" if why else ""))
    if not blocks:
        cleaned = text.strip()
        if cleaned:
            blocks.append("(freeform) " + cleaned.splitlines()[0]
                          + (f"\n   Hypothesis: {cleaned}" if cleaned else ""))
    return blocks


async def run_request(client, llm, openai_tools, menu: str,
                      req: dict) -> tuple[list[str], str, list[dict]]:
    """Drive the model through one request. Returns (hypotheses, raw, trail)."""
    head = "## Request under test\n" + _render_request(req) \
        + "\n\n## HackTricks technique menu (slugs)\n"
    tail = ("\n\nDecide what is worth testing here, fetch examples if useful, then "
            "give your HYPOTHESIS block(s).")
    # PROMPT-LOAD GUARD: keep the opening turn within budget by trimming the menu.
    fitted_menu = _fit_menu(menu, len(SYSTEM_PROMPT) + len(head) + len(tail))
    user = head + fitted_menu + tail
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]
    trail: list[dict] = []
    tried: dict[str, str] = {}

    for step in range(MAX_STEPS):
        messages = _compact(messages, tried)
        # Force an ARTICLE fetch on the first step so the agent reads worked
        # examples before it may conclude (left to "required" it picks the cheap
        # overview call); auto thereafter. Falls back to "required" if the server
        # rejects a named function choice.
        choice: Any = "auto"
        if FORCE_FETCH and step == 0:
            choice = {"type": "function",
                      "function": {"name": "hacktricks_article"}}
        try:
            resp = await llm.post(LLM_URL, json={
                "model": LLM_MODEL, "messages": messages,
                "tools": openai_tools, "tool_choice": choice,
                "stream": False, "max_tokens": MAX_TOKENS,
                "chat_template_kwargs": {"enable_thinking": False},
            })
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raw = f"(model call failed at step {step}: {type(exc).__name__}: {exc})"
            return [f"(no hypothesis — {raw})"], raw, trail
        msg = resp.json()["choices"][0]["message"]
        messages.append(msg)

        calls = msg.get("tool_calls")
        if not calls:
            raw = (msg.get("content") or "").strip()
            return _extract_hypotheses(raw), raw, trail

        steps_left = MAX_STEPS - step - 1
        for call in calls:
            name = call["function"]["name"]
            try:
                args = json.loads(call["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            sig = _sig(name, args)

            if sig in tried:
                print(f"    step {step}: {name}(...) REPEAT — nudging", flush=True)
                messages.append({
                    "role": "tool", "tool_call_id": call["id"],
                    "content": (f"You already fetched this: {name} -> {tried[sig]}. "
                                f"Fetch a different technique or write your "
                                f"HYPOTHESIS block(s) now."),
                })
                continue

            print(f"    step {step}: {name}({json.dumps(args)[:120]})", flush=True)
            out = await client.call_tool(name, args)
            payload = out.structured_content or {
                "content": [getattr(b, "text", str(b)) for b in out.content]}
            trail.append({"step": step, "tool": name, "request": args,
                          "response": payload})
            tried[sig] = _outcome(name, payload)
            messages.append({
                "role": "tool", "tool_call_id": call["id"],
                "content": _observation(name, payload, tried, steps_left),
            })

    # Hit the step limit mid-tool-use: ask once for the verdict with no tools.
    messages.append({"role": "user", "content": (
        "Step limit reached. Do not call tools. Write your HYPOTHESIS block(s) "
        "now from what you have, at least one.")})
    try:
        resp = await llm.post(LLM_URL, json={
            "model": LLM_MODEL, "messages": messages, "stream": False,
            "max_tokens": MAX_TOKENS,
            "chat_template_kwargs": {"enable_thinking": False}})
        resp.raise_for_status()
        raw = (resp.json()["choices"][0]["message"].get("content") or "").strip()
    except httpx.HTTPError:
        raw = ""
    return _extract_hypotheses(raw) or ["(no hypothesis produced)"], raw, trail


def _assemble_report(findings: list[dict], engagement_id: str | None) -> str:
    """Render all hypotheses as the exploit loop's `## Suspected vulnerabilities`."""
    out = [
        "Your job: PROVE or DISPROVE each item below using your tools, then stop.",
        "",
        "## Suspected vulnerabilities",
    ]
    n = 0
    for f in findings:
        for hyp in f["hypotheses"]:
            n += 1
            out.append(f"{n}. {hyp}")
    if n == 0:
        out.append("(none proposed)")
    out += ["", "## Known requests (fetch full details with the recon fetch tool)"]
    for f in findings:
        out.append(f"- {f['request']['method']} {f['request']['path']}")
    header = f"<!-- engagement {engagement_id}, {len(findings)} requests, "\
             f"{n} hypotheses -->\n"
    return header + "\n".join(out) + "\n"


async def main() -> str:
    async with Client(MCP_URL) as client, \
            httpx.AsyncClient(timeout=LLM_TIMEOUT) as llm:
        tools = [t for t in (await client.list_tools()).tools
                 if t.name in AGENT_TOOLS]
        openai_tools = mcp_tools_to_openai(tools)
        print("Vuln loop: model=%s, max_steps=%d" % (LLM_MODEL, MAX_STEPS))
        print("tools available to the agent:", [t.name for t in tools], "\n")

        overview = (await client.call_tool("hacktricks_overview", {})).structured_content
        techniques = (overview or {}).get("techniques", [])
        menu = _render_menu(techniques)
        print(f"HackTricks menu: {len(techniques)} techniques\n")

        batch = (await client.call_tool("list_recorded_requests", {})).structured_content
        requests = (batch or {}).get("requests", [])
        engagement_id = (batch or {}).get("engagement_id")
        if SKIP_NOISE:
            requests = [r for r in requests
                        if r.get("resource_type") not in _NOISE_RESOURCE_TYPES]
        if ONLY:
            requests = [r for r in requests
                        if any(s in (r.get("path") or "") for s in ONLY)]
        requests = requests[:MAX_REQUESTS]
        print(f"Batch: {len(requests)} request(s) from engagement {engagement_id}\n")

        findings: list[dict] = []
        for i, req in enumerate(requests, 1):
            print(f"=== [{i}/{len(requests)}] {req.get('method')} "
                  f"{req.get('path')} ===", flush=True)
            try:
                hypotheses, raw, trail = await run_request(
                    client, llm, openai_tools, menu, req)
            except Exception as exc:  # noqa: BLE001 — one bad item must not stop the run
                hypotheses, raw, trail = [f"(error — {type(exc).__name__}: {exc})"], "", []
            for h in hypotheses:
                print(f"    --> {h.splitlines()[0]}", flush=True)
            print(flush=True)
            findings.append({"request": req, "hypotheses": hypotheses,
                             "raw": raw, "trail": trail})

    report = _assemble_report(findings, engagement_id)
    out_dir = os.environ.get("APTS_VULN_OUTPUT_DIR", "reports")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    md_path = os.path.join(out_dir, f"vuln-hypotheses-{stamp}.md")
    json_path = os.path.join(out_dir, f"vuln-hypotheses-{stamp}.json")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(report)
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump({"generated_at": stamp, "model": LLM_MODEL,
                   "engagement_id": engagement_id, "findings": findings},
                  fh, indent=2, default=str)

    total = sum(len(f["hypotheses"]) for f in findings)
    print(f"\n{total} hypotheses across {len(findings)} requests.")
    print(f"Exploit-loop input written to {md_path}")
    print(f"Full reasoning trail written to {json_path}")
    # Returned so the pipeline (mcp_native.pipeline) can hand this straight to the
    # exploitation loop without a file round-trip.
    return report


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0)
    asyncio.run(main())
