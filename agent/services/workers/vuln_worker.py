"""Vulnerability Assessment — turns an Asset Map into a Register (PRD §5.3).

This is the stage where a hallucination becomes expensive. An invented endpoint
in Recon is a wasted request; an invented *vulnerability* here is a finding
about a flaw that does not exist, delivered to a client in a report they may
act on. So the model is given the narrowest useful job and is checked at every
step it could get wrong.

The division of labour:

* **The model judges.** Given real observed assets, which look likely to carry
  which class of weakness, and what CVSS *vector* describes the exposure. That
  is genuine analytical work and the reason this stage has a model at all.
* **Code scores.** ``shared.cvss`` computes the number from the vector. A model
  asked for "8.8" produces a plausible number; a model asked for a vector
  produces judgements that arithmetic then converts. An unparseable vector
  drops the candidate rather than defaulting it — a default severity is a
  confident wrong answer.
* **A probe disposes.** Every candidate's asset is fetched for real. If it does
  not exist, the model invented it and the candidate is discarded. If it
  responds, the request/response pair becomes the evidence artifact §5.3
  requires.

What this stage does **not** do is confirm exploitability. Probing proves an
asset is reachable, not that it is vulnerable, so nothing here is ever marked
``confirmed`` — that is the Exploitation agent's word to use. Findings leave
here as ``possible`` or, where the response corroborates the hypothesis,
``probable``. Presenting an unproven hypothesis as a confirmed finding is the
single most damaging thing this pipeline could do.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import ValidationError

from shared.cvss import CvssError, base_score, severity_label
from shared.cvss_reference import clamp
from shared.llm import LlmClient, LlmError
from shared.models import Evidence, VulnerabilityRegister, Weakness

from agent.services.mcp_service import McpService, ToolCallFailed
from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("agent.workers.vuln")

MAX_CANDIDATES = 15
_EVIDENCE_SNIPPET = 400

SYSTEM_PROMPT = """\
You are a web application security analyst reviewing a reconnaissance report.

Propose candidate weaknesses for the assets you are shown. Reply with ONLY JSON:
{"candidates": [{"title": "<short description>",
                 "asset": "<exact path from the report>",
                 "owasp_category": "<OWASP Top 10 2021 category>",
                 "cvss_vector": "CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...",
                 "rationale": "<one sentence: why this asset, what evidence>"}]}

Rules:
- Use ONLY asset paths that appear verbatim in the report. Never invent a path.
- Give a full CVSS v3.1 base vector. Do NOT give a numeric score; it is computed.
- Judge severity honestly. Not every endpoint is critical. Reference vectors:
    reflected XSS      CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N   (6.1)
    stored XSS         CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N   (9.0)
    unauth SQLi        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H   (9.8)
    IDOR (authed)      CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N   (8.1)
    info disclosure    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N   (7.5)
    user enumeration   CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N   (5.3)
  Use S:C only when the flaw genuinely escapes its security authority, and
  C:H/I:H/A:H only for full compromise. Both are rare.
- Propose at most %d candidates, the most plausible first.
- If an asset gives no real reason for suspicion, leave it out. An empty list is
  a valid and correct answer.
""" % MAX_CANDIDATES


def _summarise_assets(asset_map: dict[str, Any]) -> str:
    """Render the asset map as prompt text, bounded."""
    lines = [f"Target: {asset_map.get('target_url', '?')}"]

    technologies = asset_map.get("technologies") or []
    if technologies:
        lines.append("Technologies: " + ", ".join(
            t.get("name", "") for t in technologies[:10]))

    endpoints = asset_map.get("endpoints") or []
    if endpoints:
        lines.append("\nPages observed:")
        for endpoint in endpoints[:30]:
            lines.append(f"  {endpoint.get('path')} "
                         f"(HTTP {endpoint.get('status')}, "
                         f"{endpoint.get('content_type', '')})")

    forms = asset_map.get("forms") or []
    if forms:
        lines.append("\nForms:")
        for form in forms[:20]:
            fields = ", ".join(f.get("name", "") for f in form.get("fields", []))
            lines.append(f"  {form.get('method')} {form.get('page')} [{fields}]")

    api_paths = asset_map.get("api_paths") or []
    if api_paths:
        lines.append("\nAPI routes found in client-side JavaScript:")
        for path in api_paths[:60]:
            lines.append(f"  {path}")

    third_party = asset_map.get("third_party") or []
    if third_party:
        lines.append("\nThird-party script hosts: " + ", ".join(third_party[:10]))

    return "\n".join(lines)


class VulnWorker:
    """LLM-proposed, code-scored, probe-verified vulnerability assessment."""

    def __init__(self, llm: LlmClient, mcp: McpService) -> None:
        self._llm = llm
        self._mcp = mcp

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        asset_map = ctx.upstream
        known = self._known_assets(asset_map)
        if not known:
            log.warning("asset map is empty; nothing to assess")
            return VulnerabilityRegister().model_dump(mode="json")

        candidates = await self._propose(asset_map)
        weaknesses, dropped = await self._verify(candidates, known, ctx)

        register = VulnerabilityRegister(
            weaknesses=weaknesses, candidates_dropped=dropped)
        log.info("register: %d weaknesses kept, %d candidates dropped",
                 len(register.weaknesses), dropped)
        return register.model_dump(mode="json")

    # ----------------------------------------------------------------- #

    @staticmethod
    def _known_assets(asset_map: dict[str, Any]) -> set[str]:
        """Every path Recon actually observed. The model may not go outside it."""
        assets = {e.get("path") for e in asset_map.get("endpoints") or []}
        assets |= {f.get("page") for f in asset_map.get("forms") or []}
        assets |= set(asset_map.get("api_paths") or [])
        assets.discard(None)
        assets.discard("")
        return assets

    async def _propose(self, asset_map: dict[str, Any]) -> list[dict]:
        try:
            raw = await self._llm.complete_json(
                SYSTEM_PROMPT, _summarise_assets(asset_map))
        except LlmError as exc:
            raise WorkFailed(f"assessment call failed: {exc}") from exc

        candidates = raw.get("candidates")
        if not isinstance(candidates, list):
            raise WorkFailed(
                f"model returned no 'candidates' list (got keys: {sorted(raw)})")
        return candidates[:MAX_CANDIDATES]

    async def _verify(self, candidates: list[dict], known: set[str],
                      ctx: WorkContext) -> tuple[list[Weakness], int]:
        weaknesses: list[Weakness] = []
        dropped = 0

        for candidate in candidates:
            asset = str(candidate.get("asset") or "").strip()
            if asset not in known:
                log.warning("dropping candidate on unknown asset %r", asset)
                dropped += 1
                continue

            vector = str(candidate.get("cvss_vector") or "")
            try:
                score = base_score(vector)
            except CvssError as exc:
                log.warning("dropping candidate on %s: bad CVSS vector (%s)",
                            asset, exc)
                dropped += 1
                continue

            vector, score, clamp_note = clamp(
                vector, score,
                str(candidate.get("title") or ""),
                str(candidate.get("owasp_category") or ""))
            if clamp_note:
                log.warning("%s: %s", asset, clamp_note)

            evidence, reachable = await self._probe(asset, ctx)
            if not reachable:
                log.warning("dropping candidate on %s: asset did not respond", asset)
                dropped += 1
                continue

            try:
                weaknesses.append(Weakness(
                    id=f"W-{len(weaknesses) + 1:03d}",
                    title=str(candidate.get("title") or "unspecified weakness")[:200],
                    asset=asset,
                    owasp_category=str(candidate.get("owasp_category") or "")[:100],
                    cvss_vector=vector,
                    cvss_score=score,
                    severity=severity_label(score),
                    # Reachable, not proven. Only Exploitation may say "confirmed".
                    confidence="probable",
                    rationale=" | ".join(
                        p for p in (str(candidate.get("rationale") or "")[:500],
                                    clamp_note) if p),
                    evidence=[evidence] if evidence else [],
                ))
            except ValidationError as exc:
                log.warning("dropping candidate on %s: %s",
                            asset, json.dumps(exc.errors()[:2], default=str)[:200])
                dropped += 1

        return weaknesses, dropped

    async def _probe(self, asset: str, ctx: WorkContext) -> tuple[Evidence | None, bool]:
        """Fetch the asset for real, and turn the exchange into evidence.

        A transport failure means unreachable. A 404 means the path does not
        exist, which for a model-proposed asset is the hallucination signal this
        whole step is here to catch. Everything else — including 401 and 403 —
        counts as existing: an endpoint that refuses you is still an endpoint,
        and is frequently the interesting one.
        """
        url = ctx.target_url.rstrip("/") + "/" + asset.lstrip("/")
        try:
            outcome = await self._mcp.call("http", ctx.engagement_id,
                                           url=url, method="GET")
        except ToolCallFailed as exc:
            log.info("probe of %s failed: %s", url, exc)
            return None, False

        if outcome.blocked:
            log.info("probe of %s blocked by guardrails: %s", url, outcome.reason)
            return None, False

        output = outcome.output
        if output.get("error"):
            return None, False

        status = output.get("status_code")
        if status == 404:
            return None, False

        body = str(output.get("body") or "")
        return Evidence(
            request=f"GET {url}",
            response=f"HTTP {status} {output.get('headers', {}).get('content-type', '')}\n"
                     f"{body[:_EVIDENCE_SNIPPET]}",
            note="Asset confirmed reachable. This evidences existence, "
                 "not exploitability.",
        ), True
