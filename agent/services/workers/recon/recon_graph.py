"""Reconnaissance crawl-decision loop, as a LangGraph ``StateGraph``.

The new recon agent is agentic: instead of one blind 40-page crawl, a shallow
seed crawl (code) hands the model the landing page + the SPA's mined route table,
and the model then DECIDES which routes are worth crawling for a pen test —
crawling them one decision at a time until it has covered the interesting surface.

LangGraph owns *when* things run (state, the agent<->tools loop, the step cap);
plain Python owns *what* — the crawl tool, the de-dup guard (``skip_urls`` +
a normalized ``crawled`` set), and the observation coaching. The final
summarize-and-grade pass and the AssetMap assembly live in the worker, not here,
so the raw surface it accumulates stays code-owned and byte-intact.

Modes (``broad`` / ``focused``) are injected as a one-line preamble on the system
prompt so the same steer reaches every model turn of the loop (the worker injects
the same preamble into the grading pass too — the mode reaches all stages).
"""
from __future__ import annotations

import json
import os
from typing import Any, Awaitable, Callable, TypedDict
from urllib.parse import urlparse

from langgraph.graph import END, START, StateGraph

from agent.services.workers.common import common_agentic
from agent.services.workers.recon.recon_llm import compact as _compact

ModelCall = Callable[[list[dict]], Awaitable[dict]]
CallTool = Callable[[str, dict], Awaitable[dict]]

# Each agent loop crawl is SHALLOW + TARGETED: the code-driven seed already did
# the broad route mining, so a loop crawl maps ONE interesting route, not the
# whole site. Without this the model's first crawl (tool default max_pages=40)
# just re-does the blind sweep and the targeting buys nothing.
_ROUTE_MAX_PAGES = int(os.environ.get("APTS_RECON_ROUTE_MAX_PAGES", "4"))
_ROUTE_MAX_DEPTH = int(os.environ.get("APTS_RECON_ROUTE_MAX_DEPTH", "1"))


def normalize_url(url: str) -> str:
    """Canonical page identity for the de-dup guard.

    Lowercases host, drops default ports and a same-page fragment, strips a
    trailing slash — but KEEPS an SPA hash-route (``#/search``), because on a
    single-page app the hash IS the page, not a fragment to discard."""
    try:
        p = urlparse(url.strip())
    except Exception:  # noqa: BLE001
        return url.strip()
    host = (p.hostname or "").lower()
    port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    path = (p.path or "/").rstrip("/") or "/"
    frag = p.fragment
    tail = f"#{frag.rstrip('/') or '/'}" if frag.startswith("/") else ""  # keep hash-router routes
    query = f"?{p.query}" if p.query else ""
    return f"{p.scheme}://{host}{port}{path}{query}{tail}"


class ReconState(TypedDict, total=False):
    mode: str                 # "broad" | "focused"
    target: str
    domains: list[str]
    creds: dict[str, Any]
    messages: list[dict]
    tried: dict[str, str]     # repeat guard: crawl signature -> one-line outcome
    crawled: list[str]        # normalized page URLs already crawled (-> skip_urls)
    crawls: list[dict]        # raw crawl results, accumulated (code-owned, intact)
    enum: list[dict]          # katana/ffuf/arjun results, accumulated
    step: int
    verdict_text: str


def _crawl_digest(crawl: dict, before: set[str]) -> tuple[str, list[str]]:
    """Summarize one crawl result for the observation, and return the newly
    crawled page URLs. Coaching only — the raw result is kept verbatim elsewhere."""
    pages = [p.get("url", "") for p in crawl.get("pages", []) if p.get("url")]
    new_pages = [u for u in pages if normalize_url(u) not in before]
    mined = crawl.get("mined_routes", []) or []
    uncrawled = [m for m in mined if normalize_url(m) not in before
                 and normalize_url(m) not in {normalize_url(u) for u in pages}]
    forms = crawl.get("forms", []) or []
    obs = crawl.get("observed_requests", []) or []
    digest = {
        "crawled_pages": pages[:20],
        "forms_found": [{"page": urlparse(f.get("page", "")).path or "/",
                         "method": f.get("method"), "fields": [x.get("name") for x in f.get("fields", [])]}
                        for f in forms[:10]],
        "observed_requests": len(obs),
        "uncrawled_mined_routes": uncrawled[:40],
        "truncated": bool(crawl.get("truncated")),
    }
    return json.dumps(digest, default=str)[:2000], new_pages


def _enum_digest(name: str, result: dict) -> str:
    """Short, coaching summary of a katana/ffuf/arjun result for the observation."""
    if not isinstance(result, dict):
        return str(result)[:500]
    if result.get("error"):
        return json.dumps({"error": result["error"]})[:500]
    if name == "katana":
        return json.dumps({"endpoints_found": result.get("count"),
                           "sample": result.get("endpoints", [])[:15]}, default=str)[:1500]
    if name == "ffuf":
        return json.dumps({"hits": result.get("count"),
                           "found": [{"in": h.get("input"), "code": h.get("status"), "url": h.get("url")}
                                     for h in result.get("hits", [])[:20]]}, default=str)[:1800]
    if name == "arjun":
        return json.dumps({"parameters_found": result.get("parameters", [])}, default=str)[:800]
    return json.dumps(result, default=str)[:800]


def _enum_outcome(name: str, result: dict) -> str:
    if not isinstance(result, dict):
        return "ok"
    if result.get("error"):
        return f"error: {str(result['error'])[:60]}"
    if name == "katana":
        return f"{result.get('count', 0)} endpoints"
    if name == "ffuf":
        return f"{result.get('count', 0)} hits"
    if name == "arjun":
        return f"params: {','.join(result.get('parameters', [])) or 'none'}"
    return "ok"


def build_recon_graph(model_call: ModelCall, call_tool: CallTool, max_steps: int):
    """Compile the recon crawl-decision loop around a model driver + crawl tool."""

    async def agent(state: ReconState) -> dict:
        messages = _compact(state["messages"], state.get("tried", {}))
        try:
            msg = await model_call(messages)
        except Exception as exc:  # noqa: BLE001
            msg = {"role": "assistant",
                   "content": f"DONE — model call failed at step {state['step']} "
                              f"({type(exc).__name__}: {exc})"}
        return {"messages": messages + [msg], "step": state["step"] + 1}

    async def tools(state: ReconState) -> dict:
        msg = state["messages"][-1]
        tried = dict(state.get("tried", {}))
        crawled = list(state.get("crawled", []))
        crawls = list(state.get("crawls", []))
        enum = list(state.get("enum", []))
        crawled_set = {normalize_url(u) for u in crawled}
        steps_left = max_steps - state["step"]
        new_msgs: list[dict] = []
        _TOOLS = ("crawl", "crawl_v2", "katana", "ffuf", "arjun")
        _CRAWLERS = ("crawl", "crawl_v2")

        for call in msg.get("tool_calls") or []:
            name = call["function"]["name"]
            try:
                args = json.loads(call["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            if name not in _TOOLS:
                new_msgs.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": f"Unknown tool {name!r}; available: {', '.join(_TOOLS)}."})
                continue
            key = common_agentic.sig(name, args)
            if key in tried:
                new_msgs.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": (f"You already ran this exact call -> {tried[key]}. "
                                             f"Change the arguments or tool, or reply DONE.")})
                continue
            creds = state.get("creds") or {}

            if name in _CRAWLERS:
                seed = args.get("url", "")
                if seed and normalize_url(seed) in crawled_set:
                    new_msgs.append({"role": "tool", "tool_call_id": call["id"],
                                     "content": (f"Already crawled {seed}. Pick an uncrawled route, "
                                                 f"use ffuf/arjun/katana to find more, or reply DONE.")})
                    continue
                # de-dup guard + scope + shallow/targeted (seed already mined routes)
                args.setdefault("allow_domains", list(state.get("domains", []) or []))
                args["skip_urls"] = crawled
                if name == "crawl":
                    args["mine"] = False  # crawl_v2 has no route-mining to gate
                args["max_pages"] = min(int(args.get("max_pages", _ROUTE_MAX_PAGES) or _ROUTE_MAX_PAGES),
                                        _ROUTE_MAX_PAGES)
                args["max_depth"] = min(int(args.get("max_depth", _ROUTE_MAX_DEPTH) or _ROUTE_MAX_DEPTH),
                                        _ROUTE_MAX_DEPTH)
                for k in ("headers", "cookies", "basic_auth"):
                    if creds.get(k) and k not in args:
                        args[k] = creds[k]
                result = await call_tool(name, args)
                crawls.append(result)
                digest, new_pages = _crawl_digest(result, crawled_set)
                for u in new_pages:
                    nu = normalize_url(u)
                    if nu not in crawled_set:
                        crawled_set.add(nu)
                        crawled.append(u)
                tried[key] = (f"{len(new_pages)} new page(s), "
                              f"{len(result.get('observed_requests', []))} request(s)")
                new_msgs.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": (f"OBSERVATION from {name} of {seed}:\n{digest}\n---\n"
                                             f"PROGRESS: {steps_left} step(s) left. Crawled so far: "
                                             f"{len(crawled)} page(s). Crawl another route, run "
                                             f"ffuf/arjun/katana, or reply DONE.")})
            else:
                # katana / ffuf / arjun — enumeration: find UNLINKED paths/IDs and
                # HIDDEN parameters a crawler can't see. Args pass through as-is.
                result = await call_tool(name, args)
                enum.append({"tool": name, "args": args, "result": result})
                tried[key] = _enum_outcome(name, result)
                new_msgs.append({"role": "tool", "tool_call_id": call["id"],
                                 "content": (f"OBSERVATION from {name}:\n{_enum_digest(name, result)}\n---\n"
                                             f"PROGRESS: {steps_left} step(s) left. Act on a finding "
                                             f"(crawl a discovered path, note a param), run another tool, "
                                             f"or reply DONE.")})

        return {"messages": state["messages"] + new_msgs, "tried": tried,
                "crawled": crawled, "crawls": crawls, "enum": enum}

    def finalize(state: ReconState) -> dict:
        last = state["messages"][-1]
        text = (last.get("content") or "").strip() if not last.get("tool_calls") else \
            "DONE — hit the step limit"
        return {"verdict_text": text or "DONE"}

    def route(state: ReconState) -> str:
        last = state["messages"][-1]
        if last.get("tool_calls") and state["step"] < max_steps:
            return "tools"
        return "finalize"

    g = StateGraph(ReconState)
    g.add_node("agent", agent)
    g.add_node("tools", tools)
    g.add_node("finalize", finalize)
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", route, {"tools": "tools", "finalize": "finalize"})
    g.add_edge("tools", "agent")
    g.add_edge("finalize", END)
    return g.compile()
