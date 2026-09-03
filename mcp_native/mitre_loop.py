"""An AI reasoning loop that acts as the MITRE ATT&CK mapping agent.

Same shape as the vuln and exploit loops — the model drives native-MCP tools in
a genuine think -> call -> read -> decide cycle — but its job is classification:
tag each weakness in the Vulnerability Register with the ATT&CK (Enterprise)
technique(s) that describe how it would be used in an intrusion.

Its tools are the ATT&CK reference (``mcp_native.tools.attack_tool``):

    * attack_catalog   — the technique menu (id + name + tactics)
    * attack_search    — keyword search for candidate techniques
    * attack_technique — validate ONE id, get its official name + tactics

Design, matching the rest of the pipeline:

* **One weakness at a time.** Each weakness is its own small conversation, so
  the context stays short and a wrong turn on one does not bleed into the next.
* **The model chooses; the tool confirms.** The model proposes technique ids;
  :func:`run_weakness` then calls ``attack_technique`` for every id it proposed
  and keeps only the ones the catalogue confirms, substituting the tool's
  authoritative name and tactic. An id the model invented is dropped here, not
  passed on — the same "model judges, code decides" rule the CVSS scoring uses.
* **A tag every time.** §5.4 requires every register entry to carry at least one
  technique. A weakness the model cannot tag with a confirmed id comes back
  empty and the caller (the worker) re-runs it; see the worker for the
  stop-when-nothing-is-left outer loop.

Run (with the mcp-native service up), reading a register JSON on stdin or a path:
    python -m mcp_native.mitre_loop register.json
    echo '{"weaknesses":[...]}' | python -m mcp_native.mitre_loop
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from typing import Any

import httpx
from mcp import Client

MCP_URL = os.environ.get("APTS_MCP_URL", "http://localhost:9000/mcp")
LLM_URL = os.environ.get("APTS_LOOP_LLM_URL", "http://localhost:18080/v1/chat/completions")
LLM_MODEL = os.environ.get("APTS_LOOP_LLM_MODEL", "qwen3-8b")


def _loop_key() -> str:
    """Bearer token for a hosted endpoint; empty for local llama.cpp.

    Env first, then the mounted secret file (the same one ``shared.llm_aws``
    reads), so an in-container worker needs no extra configuration.
    """
    k = os.environ.get("APTS_LOOP_LLM_KEY")
    if k:
        return k
    try:
        with open(os.environ.get("APTS_LLM_KEY_FILE", "/run/secrets/llm_api_key")) as fh:
            return fh.read().strip()
    except OSError:
        return ""


LLM_KEY = _loop_key()
_HEADERS = {"Authorization": f"Bearer {LLM_KEY}"} if LLM_KEY else {}
# llama.cpp honours chat_template_kwargs to disable thinking; a hosted endpoint
# rejects unknown fields, so send it only when talking to local llama (no key).
_LLAMA_EXTRA = {} if LLM_KEY else {"chat_template_kwargs": {"enable_thinking": False}}
MAX_STEPS = int(os.environ.get("APTS_MITRE_MAX_STEPS", "5"))
LLM_TIMEOUT = float(os.environ.get("APTS_LOOP_LLM_TIMEOUT", "150"))
MAX_TOKENS = int(os.environ.get("APTS_MITRE_MAX_TOKENS", "700"))
_CONTEXT_BUDGET_CHARS = int(os.environ.get("APTS_LOOP_CONTEXT_CHARS", "16000"))

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


def mcp_tools_to_openai(tools) -> list[dict]:
    return [
        {"type": "function", "function": {
            "name": t.name,
            "description": t.description or "",
            "parameters": t.input_schema or {"type": "object", "properties": {}},
        }}
        for t in tools
    ]


def render_menu(techniques: list[dict]) -> str:
    """The technique menu injected into every per-weakness conversation.

    ``id name`` pairs, newline-joined. The curated catalogue is ~50 entries, so
    unlike the HackTricks menu this fits without trimming.
    """
    return "\n".join(f"{t.get('technique_id', t.get('id'))}  {t.get('name', '')}"
                     for t in techniques)


def describe_weakness(weakness: dict[str, Any]) -> str:
    """Compact, model-facing description of one weakness.

    Only the fields that inform a technique choice — id, class/title, location.
    Evidence blobs and request captures are withheld: they multiply token cost
    and are the part most likely to carry material that should not leave the
    deployment.
    """
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


def parse_tags(text: str) -> list[dict[str, str]]:
    """Pull ``TECHNIQUE: id | name | tactic`` lines from the model's reply.

    Lenient on spacing and case. A bare id with no name/tactic is still picked
    up (name/tactic left blank) so validation can fill them in from the tool.
    """
    tags: list[dict[str, str]] = []
    for m in _TAG_RE.finditer(text or ""):
        tags.append({"technique_id": m.group(1).upper(),
                     "technique_name": m.group(2).strip(),
                     "tactic": m.group(3).strip()})
    if not tags:
        for m in re.finditer(r"\bT\d{4}(?:\.\d{3})?\b", text or ""):
            tags.append({"technique_id": m.group(0).upper(),
                         "technique_name": "", "tactic": ""})
    # de-dup by id, keep first
    seen: set[str] = set()
    return [t for t in tags if not (t["technique_id"] in seen
                                    or seen.add(t["technique_id"]))]


def _sig(name: str, args: dict) -> str:
    return name + ":" + json.dumps(args, sort_keys=True, default=str)


def _observation(name: str, payload: dict, tried: dict[str, str],
                 steps_left: int) -> str:
    """Structured feedback wrapped around a tool result."""
    keep: dict = {}
    if isinstance(payload, dict):
        for k in ("found", "technique_id", "name", "tactics", "description",
                  "did_you_mean", "matches", "count", "guidance", "error",
                  "reason"):
            if k in payload:
                keep[k] = payload[k]
    tried_lines = "; ".join(f"{s} -> {o}" for s, o in tried.items()) or "(none yet)"
    return (
        f"OBSERVATION from {name}:\n{json.dumps(keep, default=str)[:2500]}\n"
        f"---\nPROGRESS: {steps_left} step(s) left. "
        f"Already called (do NOT repeat): {tried_lines}\n"
        f"Validate an id with attack_technique, or write your TECHNIQUE line(s) now."
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


async def _validate(client, tags: list[dict[str, str]]) -> list[dict[str, str]]:
    """Keep only technique ids the catalogue confirms; use its name and tactic.

    This is the trust boundary: whatever the model wrote, a tag survives only if
    ``attack_technique`` says the id is real, and its name/tactic are replaced
    with the authoritative ones (the model's are advisory).
    """
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
    # de-dup again (two proposed ids can normalise to the same confirmed one)
    seen: set[str] = set()
    return [t for t in confirmed if not (t["technique_id"] in seen
                                         or seen.add(t["technique_id"]))]


async def run_weakness(client, llm, openai_tools, menu: str,
                       weakness: dict[str, Any]) -> tuple[list[dict], str, list[dict]]:
    """Drive the model through one weakness. Returns (confirmed_tags, raw, trail).

    ``confirmed_tags`` is only ever ids the ``attack_technique`` tool verified;
    an empty list means the model could not land a real technique this run.
    """
    user = (f"## Weakness to map\n{describe_weakness(weakness)}\n\n"
            f"## ATT&CK technique menu (id  name)\n{menu}\n\n"
            f"Search, validate your pick(s) with attack_technique, then give "
            f"your TECHNIQUE line(s).")
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]
    trail: list[dict] = []
    tried: dict[str, str] = {}

    for step in range(MAX_STEPS):
        messages = _compact(messages, tried)
        try:
            resp = await llm.post(LLM_URL, headers=_HEADERS, json={
                "model": LLM_MODEL, "messages": messages,
                "tools": openai_tools, "tool_choice": "auto",
                "stream": False, "max_tokens": MAX_TOKENS, **_LLAMA_EXTRA,
            })
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            body = getattr(getattr(exc, "response", None), "text", "") or ""
            return [], (f"(model call failed at step {step}: {type(exc).__name__}: "
                        f"{exc} :: {body[:300]})"), trail
        msg = resp.json()["choices"][0]["message"]
        # Canonicalise tool-call arguments: hosted endpoints re-parse the string
        # and 400 on empty/malformed JSON.
        for _tc in (msg.get("tool_calls") or []):
            _fn = _tc.get("function") or {}
            _raw = (_fn.get("arguments") or "").strip()
            try:
                _fn["arguments"] = json.dumps(json.loads(_raw)) if _raw else "{}"
            except (json.JSONDecodeError, TypeError):
                _fn["arguments"] = "{}"
        messages.append(msg)

        calls = msg.get("tool_calls")
        if not calls:
            raw = (msg.get("content") or "").strip()
            tags = await _validate(client, parse_tags(raw))
            return tags, raw, trail

        steps_left = MAX_STEPS - step - 1
        for call in calls:
            name = call["function"]["name"]
            try:
                args = json.loads(call["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            sig = _sig(name, args)

            if sig in tried:
                messages.append({
                    "role": "tool", "tool_call_id": call["id"],
                    "content": (f"You already ran this exact call: {name} -> "
                                f"{tried[sig]}. Change the arguments or give "
                                f"your TECHNIQUE line(s) now."),
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

    # Hit the step limit mid-tool-use: one last no-tool turn for the verdict.
    messages.append({"role": "user", "content": (
        "Step limit reached. Do not call tools. Write your TECHNIQUE line(s) "
        "now from what your tools already confirmed, at least one.")})
    try:
        resp = await llm.post(LLM_URL, headers=_HEADERS, json={
            "model": LLM_MODEL, "messages": messages, "stream": False,
            "max_tokens": MAX_TOKENS, **_LLAMA_EXTRA})
        resp.raise_for_status()
        raw = (resp.json()["choices"][0]["message"].get("content") or "").strip()
    except httpx.HTTPError:
        raw = ""
    tags = await _validate(client, parse_tags(raw))
    return tags, raw, trail


async def map_register(weaknesses: list[dict[str, Any]]) -> dict[str, list[dict]]:
    """Map a whole register. Returns ``{weakness_id: [confirmed tags]}``.

    Standalone helper for CLI / ad-hoc use; the pipeline calls
    :func:`run_weakness` from the worker so it can drive its own outer loop.
    """
    mapped: dict[str, list[dict]] = {}
    async with Client(MCP_URL) as client, \
            httpx.AsyncClient(timeout=LLM_TIMEOUT) as llm:
        tools = [t for t in (await client.list_tools()).tools
                 if t.name in AGENT_TOOLS]
        openai_tools = mcp_tools_to_openai(tools)
        catalog = (await client.call_tool("attack_catalog", {})).structured_content
        menu = render_menu((catalog or {}).get("techniques", []))
        for w in weaknesses:
            wid = w.get("id") or w.get("weakness_id")
            if not wid:
                continue
            print(f"=== {wid}: {w.get('title') or w.get('kind')} ===", flush=True)
            tags, _raw, _trail = await run_weakness(
                client, llm, openai_tools, menu, w)
            for t in tags:
                print(f"    --> {t['technique_id']}  {t['technique_name']} "
                      f"({t['tactic']})", flush=True)
            mapped[wid] = tags
    return mapped


def main() -> None:
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = json.load(sys.stdin)
    weaknesses = data.get("weaknesses", data if isinstance(data, list) else [])
    mapped = asyncio.run(map_register(weaknesses))
    print("\n" + json.dumps({"mappings": mapped}, indent=2))


if __name__ == "__main__":
    main()
