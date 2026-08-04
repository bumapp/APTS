"""Reconnaissance — maps the target's attack surface (PRD §5.2).

The first stage that touches a real target, and deliberately the one stage with
no model in it. Everything here is deterministic: crawl, parse, count. An LLM
would add nothing to "what URLs exist" except the opportunity to invent one, and
an invented endpoint propagates through the whole pipeline — the Vulnerability
agent tests it, the Adviser reports it, and the client is handed a finding about
a page that does not exist.

So Recon reports only what the crawler actually observed. Judgement about what
those findings *mean* belongs to the stages downstream that have models.

All traffic goes through the MCP crawl tool, which enforces the engagement scope
on every link it follows — including ones discovered mid-crawl that the
guardrails checkpoint never saw.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from shared.models import AssetMap, Endpoint, Form, FormField, Technology

from agent.services.mcp_service import McpService, ToolCallFailed
from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("agent.workers.recon")


class ReconWorker:
    """Crawls the target and produces an Asset Map."""

    def __init__(self, mcp: McpService) -> None:
        self._mcp = mcp

    async def __call__(self, ctx: WorkContext) -> dict:
        try:
            outcome = await self._mcp.call(
                "crawl", ctx.engagement_id, url=ctx.target_url)
        except ToolCallFailed as exc:
            raise WorkFailed(f"crawl failed: {exc}") from exc

        if outcome.blocked:
            # Guardrails refused the seed URL. That is a scope misconfiguration
            # rather than a transient fault, so retrying will not help — but the
            # orchestrator's retry counter is still the right place for it to
            # surface, since Recon is a critical agent and this must stop the run.
            raise WorkFailed(f"crawl blocked by guardrails: {outcome.reason}")

        crawl = outcome.output
        asset_map = AssetMap(
            target_url=ctx.target_url,
            endpoints=self._endpoints(crawl),
            forms=self._forms(crawl),
            technologies=[
                Technology(name=t["name"], source=t.get("source", ""))
                for t in crawl.get("technologies", [])
            ],
            api_paths=crawl.get("js_api_paths", []),
            third_party=crawl.get("third_party_hosts", []),
            pages_crawled=crawl.get("pages_crawled", 0),
            truncated=bool(crawl.get("truncated")),
        )

        log.info(
            "asset map: %d endpoints, %d api paths, %d forms, %d technologies, "
            "%d third-party hosts (crawled %d pages%s)",
            len(asset_map.endpoints), len(asset_map.api_paths),
            len(asset_map.forms), len(asset_map.technologies),
            len(asset_map.third_party),
            asset_map.pages_crawled,
            ", TRUNCATED" if asset_map.truncated else "",
        )
        if not asset_map.endpoints and not asset_map.api_paths:
            log.warning("crawl reached the target but found no endpoints — "
                        "check that %s serves HTML", ctx.target_url)

        return asset_map.model_dump(mode="json")

    # ----------------------------------------------------------------- #

    @staticmethod
    def _endpoints(crawl: dict) -> list[Endpoint]:
        endpoints = []
        for page in crawl.get("pages", []):
            parsed = urlparse(page.get("url", ""))
            endpoints.append(Endpoint(
                path=parsed.path or "/",
                status=page.get("status"),
                params=sorted({p.split("=")[0] for p in parsed.query.split("&") if p}),
                content_type=page.get("content_type", ""),
            ))
        return endpoints

    @staticmethod
    def _forms(crawl: dict) -> list[Form]:
        forms = []
        for form in crawl.get("forms", []):
            forms.append(Form(
                page=urlparse(form.get("page", "")).path or "/",
                method=form.get("method", "GET"),
                action=form.get("action", ""),
                fields=[FormField(name=f["name"], type=f.get("type", "text"))
                        for f in form.get("fields", [])],
            ))
        return forms
