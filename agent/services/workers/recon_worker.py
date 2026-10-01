"""Reconnaissance — an agentic, LangGraph-driven crawl.

The old recon ran one blind 40-page crawl then ranked what it found. This version
is agent-driven:

1. **Shallow seed (code).** A one-page crawl (``max_pages=1, max_depth=1``) loads
   the landing page and mines the SPA's client route table — handing the model the
   seed's requests plus the *hidden* routes (``#/login``, ``#/search`` …) with no
   deep crawl yet.
2. **The agent loop (LangGraph).** The model decides which routes are worth
   crawling for a pen test and crawls them one at a time (``recon_graph``), with a
   de-dup guard so no page is crawled twice. It stops when it has covered the
   security-relevant surface.
3. **Assemble + grade (code owns the raw surface).** Code merges every crawl's
   output into the ``AssetMap`` — endpoints, forms, and observed requests kept
   **byte-intact**; the model NEVER serializes a request. Then ONE model call
   writes a summary and grades the notable findings (additive metadata). The
   result is validated; a malformed surface raises ``WorkFailed`` (the orchestrator
   retries the stage).

**Modes** (``broad`` / ``focused``) are injected as a one-line preamble into every
prompt — the crawl-loop system prompt AND the grading prompt — so the steer reaches
all stages. ``broad`` favours coverage (keep the maybes); ``focused`` favours
precision (crawl only fruitful routes; drop low-value static/transport requests).
The mode never lets the raw security surface be dropped: forms and any request that
carries a parameter or body are always kept.
"""
from __future__ import annotations

import json
import logging
import os
from urllib.parse import parse_qsl, urlparse

import httpx
from mcp import Client

from shared.llm import LlmClient
from shared.models import (
    AssetMap, Endpoint, Form, FormField, ObservedRequest, Technology,
)

from agent.services.workers import agentic
from agent.services.workers.base import WorkContext, WorkFailed
from agent.services.workers.recon_graph import build_recon_graph, normalize_url

log = logging.getLogger("agent.workers.recon")

MAX_STEPS = int(os.environ.get("APTS_RECON_MAX_STEPS", "20"))
MAX_TOKENS = int(os.environ.get("APTS_RECON_MAX_TOKENS", "1200"))
DEFAULT_MODE = (os.environ.get("APTS_RECON_MODE", "broad") or "broad").lower()


def _mode_preamble(mode: str) -> str:
    """One-line mode steer, prepended to EVERY recon prompt (loop + grading)."""
    if mode == "focused":
        return ("MODE: FOCUSED — precision over coverage. Go only for fruitful "
                "surface: authentication, user input, APIs, admin/config, anything "
                "taking a parameter or a body. Skip purely static/marketing pages. "
                "Keep and grade only genuinely test-worthy things.\n\n")
    return ("MODE: BROAD — coverage over precision. Do not miss surface: when "
            "unsure whether a route is interesting, crawl it, and keep the maybes. "
            "Grade anything that might be worth testing, even if marginal.\n\n")


RECON_LOOP_SYSTEM = """\
You are a reconnaissance agent for an authorised penetration test. Your job is to
MAP the security-relevant attack surface — you do NOT exploit anything, you only
discover and map.

You are given the seed page and the app's MINED ROUTES (client routes found in the
JavaScript, not yet crawled). You have four tools:

- crawl(url): browser-crawl ONE route — follows links, submits forms, records the
  requests it fires. Use it to map LINKED / form-reachable surface (login, search,
  the APIs the UI calls). One route at a time; the guard refuses re-crawling.
- katana(url): fast crawler that also parses JS for endpoints — use for a quick deep
  endpoint sweep or to cross-check what crawl found.
- ffuf(url, wordlist): fuzz for UNLINKED paths and enumerable IDs a crawler can
  NEVER see. Put the FUZZ keyword in the url. Choose `wordlist` by purpose:
  'common'/'big'/'raft-dirs'/'raft-files' = directories/files, 'api' = API routes,
  'ids' = numeric ID enumeration (e.g. an IDOR endpoint:
  url="<base>/api/<thing>/FUZZ" wordlist="ids"), 'lfi' = path-traversal, 'params' =
  parameter-name fuzzing.
- arjun(url): discover HIDDEN parameters an endpoint accepts (a query/body param not
  shown in the UI) — the concrete injection points the later stages test.

How to work:
- First crawl the interesting mined routes (forms, user input, APIs, admin/user).
- Then go BEYOND the UI deliberately — a crawler only sees what is LINKED:
  * ffuf path discovery at the root (wordlist 'common' or 'api', optionally
    recursion=true) to surface unlinked directories/endpoints;
  * for any endpoint that serves a resource by id (a path segment like note/user/
    order/card/item/account), fuzz the id with wordlist 'ids'
    (url="<base>/<resource>/FUZZ") — unlinked id endpoints are classic IDOR;
  * if a crawl/katana response exposes an API prefix (e.g. /api, /rest, /v1),
    ffuf UNDER that prefix too;
  * arjun on each real endpoint to reveal hidden parameters.
- Read each OBSERVATION and act on it. Never repeat an identical call. Stay on the
  given target host.
- STOP when you have covered the security-relevant surface: reply WITHOUT a tool
  call, a single line "DONE — <one-line why>".
"""

RECON_GRADE_SYSTEM = """\
You are a reconnaissance analyst. You are given the attack surface a crawl mapped
(endpoints, forms, parameterised requests, API paths, technologies). Produce a
short summary and grade the notable, test-worthy findings.

Reply with ONLY JSON, no prose:
{"summary":"<2-4 sentences on the security-relevant surface>",
 "findings":[{"finding":"<what it is>","where":"<path or parameter>",
              "grade":"high|medium|low","reason":"<one short line>"}]}
Grade by test-worthiness for a pen test: high = authentication / user-input /
injection / access-control surface; medium = app or API surface with less obvious
risk; low = minor. Only include REAL findings — do not pad. Base everything ONLY on
the surface given; invent nothing.
"""


class ReconWorker:
    """Agentic recon: shallow seed, agent-driven crawl loop, then grade."""

    def __init__(self, llm: LlmClient | None = None) -> None:
        self._llm = llm  # unused: the loop drives the model itself via agentic

    async def __call__(self, ctx: WorkContext) -> dict:
        mode = (getattr(ctx, "recon_mode", "") or DEFAULT_MODE).lower()
        if mode not in ("broad", "focused"):
            mode = "broad"
        pre = agentic.directive_block(ctx.directive)
        modepre = _mode_preamble(mode)
        creds = ctx.credentials or {}
        domains = list(ctx.scope.domains)
        log.info("recon starting in %s mode against %s", mode, ctx.target_url)

        try:
            async with Client(agentic.MCP_URL) as client, \
                    httpx.AsyncClient(timeout=agentic.LLM_TIMEOUT) as llm:
                # 1) shallow seed crawl (code) — one page + mined route table
                seed = await self._crawl(client, {
                    "url": ctx.target_url, "allow_domains": domains,
                    "allow_paths": list(ctx.scope.allow_paths),
                    "deny_paths": list(ctx.scope.deny_paths),
                    "max_pages": 1, "max_depth": 1, **self._cred_args(creds)})
                mined = seed.get("mined_routes", []) or []
                log.info("recon seed: %d request(s), %d mined route(s)",
                         len(seed.get("observed_requests", [])), len(mined))

                # 2) agent-driven crawl loop (LangGraph)
                tools = [t for t in (await client.list_tools()).tools
                         if t.name in ("crawl", "katana", "ffuf", "arjun")]
                openai_tools = agentic.mcp_tools_to_openai(tools)

                async def model_call(messages):
                    return await agentic.chat(llm, messages, tools=openai_tools)

                async def call_tool(name, args):
                    out = await client.call_tool(name, args)
                    return out.structured_content or {}

                graph = build_recon_graph(model_call, call_tool, MAX_STEPS)
                seed_pages = [p.get("url", "") for p in seed.get("pages", []) if p.get("url")]
                task = self._seed_task(seed, mined, mode, pre)
                out = await graph.ainvoke({
                    "mode": mode, "target": ctx.target_url, "domains": domains,
                    "creds": creds,
                    "messages": [{"role": "system", "content": modepre + RECON_LOOP_SYSTEM},
                                 {"role": "user", "content": task}],
                    "tried": {}, "crawled": list(seed_pages), "crawls": [seed],
                    "enum": [], "step": 0,
                }, config={"recursion_limit": 2 * MAX_STEPS + 5})

                crawls = out.get("crawls") or [seed]

                # 3) assemble the raw surface (CODE — intact), then grade (model)
                merged = self._merge(crawls)
                observed = self._observed_requests(merged)
                self._assign_interest(observed)
                if mode == "focused":  # keep fruitful; the floor (params/body) is always high/medium
                    observed = [r for r in observed if r.interest != "low"]
                summary, findings = await self._grade(
                    llm, merged, observed, modepre + pre)
                # fold enumeration-tool output into the surface: unlinked paths
                # (katana/ffuf) become api_paths; arjun params become findings.
                extra_paths, enum_findings = set(), []
                for e in (out.get("enum") or []):
                    tool, res, a = e.get("tool"), e.get("result") or {}, e.get("args") or {}
                    if tool in ("katana", "ffuf"):
                        urls = res.get("endpoints", []) + [h.get("url", "") for h in res.get("hits", [])]
                        for u in urls:
                            try:
                                pth = urlparse(u).path
                                if pth:
                                    extra_paths.add(pth)
                            except Exception:  # noqa: BLE001
                                pass
                    elif tool == "arjun":
                        for prm in res.get("parameters", []):
                            enum_findings.append({
                                "finding": f"hidden parameter '{prm}'",
                                "where": a.get("url", ""), "grade": "high",
                                "reason": "endpoint accepts a parameter not exposed in the UI (arjun)"})
                findings = (findings or []) + enum_findings
        except WorkFailed:
            raise
        except Exception as exc:  # noqa: BLE001 — retryable stage failure
            raise WorkFailed(f"recon loop failed: {type(exc).__name__}: {exc}") from exc

        request_tree = self._request_tree(summary, merged, observed)
        asset = AssetMap(
            target_url=ctx.target_url, mode=mode, summary=summary, findings=findings,
            request_tree=request_tree,
            endpoints=self._endpoints(merged), forms=self._forms(merged),
            technologies=[Technology(name=t["name"], source=t.get("source", ""),
                                     version=t.get("version") or None)
                          for t in merged.get("technologies", [])],
            api_paths=sorted(set(merged.get("js_api_paths", [])) | extra_paths),
            observed_requests=observed,
            third_party=merged.get("third_party_hosts", []),
            pages_crawled=merged.get("pages_crawled", 0),
            truncated=bool(merged.get("truncated")))

        # 4) validate the CONTRACT — the raw surface must be real and intact.
        self._validate(asset, ctx.target_url)
        log.info("recon done [%s]: %d endpoints, %d api paths, %d observed "
                 "(%d high / %d medium / %d low), %d forms, %d pages, %d graded "
                 "finding(s)%s", mode, len(asset.endpoints), len(asset.api_paths),
                 len(asset.observed_requests),
                 sum(1 for r in observed if r.interest == "high"),
                 sum(1 for r in observed if r.interest == "medium"),
                 sum(1 for r in observed if r.interest == "low"),
                 len(asset.forms), asset.pages_crawled, len(findings),
                 ", TRUNCATED" if asset.truncated else "")
        return asset.model_dump(mode="json")

    # --- crawl helper ------------------------------------------------------ #
    @staticmethod
    async def _crawl(client, args: dict) -> dict:
        out = await client.call_tool("crawl", args)
        return out.structured_content or {}

    @staticmethod
    def _cred_args(creds: dict) -> dict:
        out = {}
        for k in ("headers", "cookies", "basic_auth"):
            if creds.get(k):
                out[k] = creds[k]
        return out

    @staticmethod
    def _seed_task(seed: dict, mined: list[str], mode: str, pre: str) -> str:
        obs = seed.get("observed_requests", []) or []
        reqs = "\n".join(f"  {r.get('method')} {urlparse(r.get('url','')).path or '/'}"
                         f"{'  [body]' if r.get('post_data') else ''}"
                         for r in obs[:25]) or "  (none)"
        routes = "\n".join(f"  {m}" for m in mined[:60]) or "  (none mined)"
        return (f"{pre}## Seed page: {seed.get('seed','')}\n"
                f"Requests fired on load ({len(obs)}):\n{reqs}\n\n"
                f"## Mined client routes (not yet crawled) — candidates to consider:\n{routes}\n\n"
                f"Crawl the routes worth mapping for a penetration test, one at a time, "
                f"then reply DONE. You are in {mode.upper()} mode.")

    # --- merge crawls into one surface dict (code-owned, intact) ---------- #
    @staticmethod
    def _merge(crawls: list[dict]) -> dict:
        pages: list[dict] = []
        seen_pages: set[str] = set()
        forms: list[dict] = []
        seen_forms: set[str] = set()
        observed: list[dict] = []
        seen_obs: set[tuple] = set()
        api_paths: set[str] = set()
        third: set[str] = set()
        techs: dict[str, dict] = {}
        truncated = False
        for c in crawls:
            truncated = truncated or bool(c.get("truncated"))
            for p in c.get("pages", []):
                u = p.get("url", "")
                if u and normalize_url(u) not in seen_pages:
                    seen_pages.add(normalize_url(u))
                    pages.append(p)
            for f in c.get("forms", []):
                k = json.dumps({"p": f.get("page"), "m": f.get("method"),
                                "a": f.get("action"),
                                "fl": [x.get("name") for x in f.get("fields", [])]},
                               sort_keys=True)
                if k not in seen_forms:
                    seen_forms.add(k)
                    forms.append(f)
            for r in c.get("observed_requests", []):
                k = (r.get("method"), r.get("url"), r.get("post_data"))
                if k not in seen_obs:
                    seen_obs.add(k)
                    observed.append(r)
            for a in c.get("js_api_paths", []):
                api_paths.add(a)
            for h in c.get("third_party_hosts", []):
                third.add(h)
            for t in c.get("technologies", []):
                techs.setdefault(t["name"], t)
        return {"pages": pages, "forms": forms, "observed_requests": observed,
                "js_api_paths": sorted(api_paths), "third_party_hosts": sorted(third),
                "technologies": list(techs.values()), "pages_crawled": len(pages),
                "truncated": truncated}

    # --- deterministic interest (no per-page model calls) ----------------- #
    @staticmethod
    def _assign_interest(observed: list[ObservedRequest]) -> None:
        for r in observed:
            if _params_of(r):
                r.interest, r.interest_reason = "high", "carries a parameter or body"
            elif (r.resource_type or "").lower() in ("xhr", "fetch") or r.method != "GET":
                r.interest, r.interest_reason = "medium", "app/API call without parameters"
            else:
                r.interest, r.interest_reason = "low", "static/transport"

    # --- the single grade call (model; additive, never touches raw data) --- #
    async def _grade(self, llm, merged: dict, observed: list[ObservedRequest],
                     preamble: str) -> tuple[str, list[dict]]:
        endpoints = sorted({r.get("url", "") and (urlparse(r["url"]).path or "/")
                            for r in merged.get("observed_requests", [])})
        forms = [f"{urlparse(f.get('page','')).path or '/'} "
                 f"[{','.join(x.get('name','') for x in f.get('fields', []))}]"
                 for f in merged.get("forms", [])]
        params = sorted({f"{urlparse(r.url).path or '/'}?{p}"
                        for r in observed if r.interest == "high"
                        for p in _params_of(r)})
        view = {
            "target_paths": endpoints[:80],
            "forms": forms[:20],
            "parameterised_requests": params[:80],
            "api_paths": merged.get("js_api_paths", [])[:80],
            "technologies": [t.get("name") for t in merged.get("technologies", [])],
        }
        user = f"{preamble}Attack surface:\n{json.dumps(view, default=str)[:6000]}"
        try:
            msg = await agentic.chat(
                llm, [{"role": "system", "content": RECON_GRADE_SYSTEM},
                      {"role": "user", "content": user}], max_tokens=MAX_TOKENS)
        except httpx.HTTPError as exc:
            log.warning("recon grade call failed: %s — keeping raw surface only", exc)
            return "", []
        return _parse_grade(msg.get("content") or "")

    # --- validation: the contract must hold ------------------------------- #
    @staticmethod
    def _validate(asset: AssetMap, target: str) -> None:
        if not asset.observed_requests and not asset.endpoints and not asset.api_paths:
            raise WorkFailed(
                f"recon mapped an empty surface for {target} — the crawl reached "
                f"nothing testable (target down, out of scope, or not HTML?)")
        for r in asset.observed_requests:  # raw requests must be intact
            if not r.url or not r.method:
                raise WorkFailed("recon produced a malformed observed request "
                                 "(missing method/url) — surface not trustworthy")

    # --- AssetMap builders ------------------------------------------------- #
    @classmethod
    def _endpoints(cls, crawl: dict) -> list[Endpoint]:
        endpoints: list[Endpoint] = []
        seen: set[str] = set()
        for page in crawl.get("pages", []):
            parsed = urlparse(page.get("url", ""))
            path = cls._endpoint_path(parsed)
            if path in seen:
                continue
            seen.add(path)
            endpoints.append(Endpoint(
                path=path, status=page.get("status"),
                params=sorted({p.split("=")[0] for p in parsed.query.split("&") if p}),
                content_type=page.get("content_type", ""),
                response_headers=page.get("response_headers", {}) or {}))
        return endpoints

    @staticmethod
    def _endpoint_path(parsed) -> str:
        path = parsed.path or "/"
        fragment = parsed.fragment
        if fragment.startswith("/"):
            prefix = "" if path == "/" else path.rstrip("/")
            return f"{prefix}/#{fragment}"
        return path

    @staticmethod
    def _observed_requests(crawl: dict) -> list[ObservedRequest]:
        return [
            ObservedRequest(
                method=r.get("method", "GET"), url=r.get("url", ""),
                resource_type=r.get("resource_type", ""),
                content_type=r.get("content_type", ""),
                post_data=r.get("post_data"),
                headers=r.get("headers", {}) or {},
                source_page=r.get("source_page", ""))
            for r in crawl.get("observed_requests", [])
        ]

    @staticmethod
    def _forms(crawl: dict) -> list[Form]:
        return [
            Form(page=urlparse(form.get("page", "")).path or "/",
                 method=form.get("method", "GET"), action=form.get("action", ""),
                 fields=[FormField(name=f["name"], type=f.get("type", "text"))
                         for f in form.get("fields", [])])
            for form in crawl.get("forms", [])
        ]


    @classmethod
    def _request_tree(cls, summary: str, merged: dict, observed: list) -> dict:
        """Build the UI/report tree: recon summary + tech, then each page with its
        NOTABLE (non-static) requests. A derived view; observed_requests stays
        authoritative. Grouped by the page that fired each request (source_page)."""
        pages: dict[str, list] = {}
        order: list[str] = []
        for r in observed:
            if r.interest == "low":
                continue  # notable = high/medium only
            label = cls._endpoint_path(urlparse(r.source_page or "")) or "(unknown page)"
            if label not in pages:
                pages[label] = []
                order.append(label)
            pages[label].append({
                "method": r.method,
                "path": urlparse(r.url).path or "/",
                "params": _params_of(r),
                "interest": r.interest,
                "reason": r.interest_reason,
            })
        return {
            "summary": summary,
            "technologies": [t.get("name") for t in merged.get("technologies", [])],
            "pages": [{"page": p, "requests": pages[p]} for p in order],
        }


def _params_of(req: ObservedRequest) -> list[str]:
    params = [k for k, _ in parse_qsl(urlparse(req.url).query, keep_blank_values=True)]
    if req.post_data and req.post_data.strip():
        try:
            obj = json.loads(req.post_data)
            if isinstance(obj, dict):
                params += list(obj.keys())
        except json.JSONDecodeError:
            params += [k for k, _ in parse_qsl(req.post_data, keep_blank_values=True)]
    seen: set[str] = set()
    return [p for p in params if not (p in seen or seen.add(p))]


def _parse_grade(text: str) -> tuple[str, list[dict]]:
    """Pull {summary, findings} out of the grade reply, tolerant of stray prose."""
    import re
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return "", []
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return "", []
    if not isinstance(data, dict):
        return "", []
    summary = str(data.get("summary", ""))[:2000]
    raw = data.get("findings") if isinstance(data.get("findings"), list) else []
    findings = []
    for f in raw[:50]:
        if not isinstance(f, dict):
            continue
        findings.append({
            "finding": str(f.get("finding", ""))[:200],
            "where": str(f.get("where", ""))[:200],
            "grade": str(f.get("grade", "")).lower().strip()
                     if str(f.get("grade", "")).lower().strip() in ("high", "medium", "low") else "",
            "reason": str(f.get("reason", ""))[:200]})
    return summary, findings
