"""Reconnaissance — crawl the target, then have the model triage what it found.

Recon is now a two-move loop, per the "tool runs, model verifies" pattern:

1. **The tool runs.** The browser-driven crawler (a native MCP ``crawl`` tool on
   mcp-native) maps the attack surface deterministically — pages, forms, tech,
   and every in-scope request the browser fired, each tagged with the page that
   fired it. No model touches "what exists", so nothing is invented.
2. **The model verifies.** For each page's observed requests the model rates how
   worth testing each one is (high / medium / low) with a one-line reason. It
   **ranks, it does not drop** — every request is kept and carried forward with
   its rating, so the Vulnerability stage decides what to pursue rather than
   having recon silently discard something.

The Asset Map is unchanged in shape (the downstream stages read it as before);
the observed requests just gain ``source_page`` and the model's ``interest`` /
``interest_reason``.
"""
from __future__ import annotations

import json
import logging
import os
import re
from urllib.parse import parse_qsl, urlparse

import httpx
from mcp import Client

from shared.llm import LlmClient
from shared.models import (
    AssetMap,
    Endpoint,
    Form,
    FormField,
    ObservedRequest,
    Technology,
)

from agent.services.mcp_service import McpService
from agent.services.workers import agentic
from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("agent.workers.recon")

MAX_TOKENS = int(os.environ.get("APTS_RECON_MAX_TOKENS", "800"))

RANK_SYSTEM = """\
You are a web recon analyst triaging observed HTTP requests for an authorised
penetration test. For the page below you are given the requests the browser
fired. Rate EACH request for how worth testing it is — do not drop any, rate all:
- high:   carries user input into app logic — a login/search/API call with
          params or a body, an ID in the path, anything reaching a backend
          query, command, or template.
- medium: an app/API call with little or no obvious input, still worth a look.
- low:    static assets, analytics, polling/transport, health checks — little to test.

Reply with ONLY JSON, no prose:
{"rankings":[{"i":<index>,"interest":"high|medium|low","reason":"<one short line>"}]}
Rate every index you are given, exactly once.
"""


class ReconWorker:
    """Crawls the target (tool) then triages the observed requests (model)."""

    def __init__(self, mcp: McpService, llm: LlmClient | None = None) -> None:
        # The loop drives the crawl tool and the model itself via the native MCP
        # client and the shared agentic plumbing; mcp/llm are kept for
        # constructor compatibility with the composition root.
        self._mcp = mcp
        self._llm = llm

    async def __call__(self, ctx: WorkContext) -> dict:
        try:
            async with Client(agentic.MCP_URL) as client, \
                    httpx.AsyncClient(timeout=agentic.LLM_TIMEOUT) as llm:
                crawl = (await client.call_tool("crawl", {
                    "url": ctx.target_url,
                    "allow_domains": list(ctx.scope.domains),
                    "allow_paths": list(ctx.scope.allow_paths),
                    "deny_paths": list(ctx.scope.deny_paths),
                })).structured_content or {}
                observed = self._observed_requests(crawl)
                await self._verify(llm, observed)
                # Keep only what the model rated worth testing. The rest is
                # dropped here so the downstream stages only ever see the
                # high-interest attack surface (a proof run, not a full dump).
                dropped = len(observed)
                observed = [r for r in observed if r.interest == "high"]
                log.info("recon triage: kept %d high-interest request(s), "
                         "dropped %d", len(observed), dropped - len(observed))
        except Exception as exc:  # noqa: BLE001 — retryable stage failure
            raise WorkFailed(f"recon loop failed: {type(exc).__name__}: {exc}") from exc

        asset_map = AssetMap(
            target_url=ctx.target_url,
            endpoints=self._endpoints(crawl),
            forms=self._forms(crawl),
            technologies=[Technology(name=t["name"], source=t.get("source", ""),
                                     version=t.get("version") or None)
                          for t in crawl.get("technologies", [])],
            api_paths=crawl.get("js_api_paths", []),
            observed_requests=observed,
            third_party=crawl.get("third_party_hosts", []),
            pages_crawled=crawl.get("pages_crawled", 0),
            truncated=bool(crawl.get("truncated")),
        )
        log.info("asset map: %d endpoints, %d api paths, %d observed requests "
                 "(%d high / %d medium / %d low), %d forms, crawled %d pages%s",
                 len(asset_map.endpoints), len(asset_map.api_paths),
                 len(asset_map.observed_requests),
                 sum(1 for r in observed if r.interest == "high"),
                 sum(1 for r in observed if r.interest == "medium"),
                 sum(1 for r in observed if r.interest == "low"),
                 len(asset_map.forms), asset_map.pages_crawled,
                 ", TRUNCATED" if asset_map.truncated else "")
        if not asset_map.endpoints and not asset_map.api_paths:
            log.warning("crawl reached the target but found no endpoints — "
                        "check that %s serves HTML", ctx.target_url)
        return asset_map.model_dump(mode="json")

    # --- the model verification pass -------------------------------------- #

    async def _verify(self, llm, observed: list[ObservedRequest]) -> None:
        """Rate each page's requests high/medium/low (in place). Ranks, not drops."""
        by_page: dict[str, list[int]] = {}
        for idx, req in enumerate(observed):
            by_page.setdefault(req.source_page or "(unknown page)", []).append(idx)

        for page, idxs in by_page.items():
            listing = "\n".join(
                f"{n}: {observed[i].method} {urlparse(observed[i].url).path or '/'}"
                f"  params: {', '.join(_params_of(observed[i])) or '(none)'}"
                f"{'  [has body]' if observed[i].post_data else ''}"
                for n, i in enumerate(idxs))
            user = f"Page: {page}\nRequests:\n{listing}"
            try:
                msg = await agentic.chat(
                    llm, [{"role": "system", "content": RANK_SYSTEM},
                          {"role": "user", "content": user}], max_tokens=MAX_TOKENS)
            except httpx.HTTPError as exc:
                log.warning("recon rank call failed for %s: %s", page, exc)
                continue
            for rank in _parse_rankings(msg.get("content") or ""):
                pos = rank.get("i")
                if isinstance(pos, int) and 0 <= pos < len(idxs):
                    req = observed[idxs[pos]]
                    interest = str(rank.get("interest", "")).lower().strip()
                    req.interest = interest if interest in ("high", "medium", "low") else ""
                    req.interest_reason = str(rank.get("reason", ""))[:200]
            log.info("  page %s: %d request(s) ranked [%s]", page, len(idxs),
                     ", ".join(f"{observed[i].method} "
                               f"{urlparse(observed[i].url).path or '/'}="
                               f"{observed[i].interest or '?'}" for i in idxs))

    # --- Asset Map builders (unchanged, plus source_page) ----------------- #

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
                content_type=page.get("content_type", "")))
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
                source_page=r.get("source_page", ""),
            )
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


def _params_of(req: ObservedRequest) -> list[str]:
    params = [k for k, _ in parse_qsl(urlparse(req.url).query)]
    if req.post_data and req.post_data.strip():
        try:
            obj = json.loads(req.post_data)
            if isinstance(obj, dict):
                params += list(obj.keys())
        except json.JSONDecodeError:
            params += [k for k, _ in parse_qsl(req.post_data)]
    seen: set[str] = set()
    return [p for p in params if not (p in seen or seen.add(p))]


def _parse_rankings(text: str) -> list[dict]:
    """Pull the rankings array out of the model's reply, tolerant of stray prose."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    rankings = data.get("rankings") if isinstance(data, dict) else None
    return rankings if isinstance(rankings, list) else []
