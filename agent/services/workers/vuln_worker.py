"""Vulnerability Assessment — the agentic hypothesis loop (PRD §5.3).

This stage runs the native-MCP vulnerability loop (``mcp_native.vuln_loop``):
for each request reconnaissance observed, the model consults the HackTricks
knowledge base and proposes testable hypotheses. Each hypothesis becomes a
``Weakness`` in the register the rest of the pipeline already iterates over —
MITRE tags it, Exploitation tries to prove it — so the DB handoff is unchanged.

Division of labour, unchanged in spirit from the old scored-candidate worker:

* **The model judges** which vulnerability classes are worth testing on each
  real request, grounded in HackTricks examples it fetches itself.
* **Code scores.** The model names the class in each hypothesis; a per-class
  CVSS reference maps that to a vector and ``shared.cvss`` computes the number.
  A model asked for "8.8" produces a plausible number; a class maps to a vector
  that arithmetic converts.
* **Nothing is confirmed here.** Every weakness leaves as ``possible`` — proving
  it is Exploitation's job, and only that stage may say ``confirmed``.
"""
from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from shared.cvss import CvssError, base_score, severity_label
from shared.llm import LlmClient
from shared.models import VulnerabilityRegister, Weakness

from agent.services.mcp_service import McpService
from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("agent.workers.vuln")

MCP_URL = os.environ.get("APTS_MCP_URL", "http://mcp-native:9000/mcp")
MAX_REQUESTS = int(os.environ.get("APTS_VULN_MAX_REQUESTS", "8"))
LLM_TIMEOUT = float(os.environ.get("APTS_LOOP_LLM_TIMEOUT", "150"))
_NOISE = {"stylesheet", "image", "font", "media"}

# Vulnerability class -> CVSS v3.1 base vector. The loop names the class in each
# hypothesis; this maps it to a reference vector (the same references the old
# prompt used) and shared.cvss turns the vector into a score. Order matters —
# more specific keys first (e.g. "stored xss" before "xss"). An unrecognised
# class gets a conservative medium default.
_CLASS_VECTORS = [
    ("nosql",            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("sql inj",          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("command inj",      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("code inj",         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("remote code",      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("ssti",             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("template inj",     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("deserial",         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("stored xss",       "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"),
    ("account takeover", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("login bypass",     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("auth",             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("ldap inj",         "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("mass assign",      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    ("idor",             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    ("xxe",              "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("ssrf",             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("path travers",     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("file inclus",      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("info disclos",     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    ("xss",              "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("open redirect",    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"),
    ("csrf",             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    ("websocket",        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    ("captcha",          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
]
_DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"  # ~6.3 medium


def _vector_for(title: str) -> str:
    t = title.lower()
    for key, vec in _CLASS_VECTORS:
        if key in t:
            return vec
    return _DEFAULT_VECTOR


def _prioritise(requests: list[dict]) -> list[dict]:
    """Assess endpoints that carry user input first — that is the attack surface.

    Recon order is crawl order, which buries the interesting endpoints (a login
    POST, a search query) behind static assets and parameterless admin GETs. With
    a request cap, first-come crawl order can spend the whole budget on dead ends.
    A request with a POST body ranks first, one with a query string next, the rest
    last; the sort is stable so original order is kept within each group.
    """
    def rank(req: dict) -> int:
        if (req.get("post_data") or "").strip():
            return 0
        url = req.get("url") or ""
        if "?" in url and url.split("?", 1)[1]:
            return 1
        return 2
    return sorted(requests, key=rank)


class VulnWorker:
    """Runs the agentic vuln loop and renders its hypotheses as a register."""

    def __init__(self, llm: LlmClient, mcp: McpService) -> None:
        # The loop talks to the model and the native MCP server itself; these are
        # kept only for constructor compatibility with the composition root.
        self._llm = llm
        self._mcp = mcp

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        from mcp import Client
        from mcp_native import vuln_loop as V

        weaknesses: list[Weakness] = []
        try:
            async with Client(MCP_URL) as client, \
                    httpx.AsyncClient(timeout=LLM_TIMEOUT) as llm:
                tools = [t for t in (await client.list_tools()).tools
                         if t.name in V.AGENT_TOOLS]
                openai_tools = V.mcp_tools_to_openai(tools)
                overview = (await client.call_tool(
                    "hacktricks_overview", {})).structured_content
                menu = V._render_menu((overview or {}).get("techniques", []))
                batch = (await client.call_tool(
                    "list_recorded_requests",
                    {"engagement_id": str(ctx.engagement_id)})).structured_content
                requests = _prioritise([r for r in (batch or {}).get("requests", [])
                                        if r.get("resource_type") not in _NOISE])[:MAX_REQUESTS]
                log.info("vuln loop: assessing %d request(s): %s", len(requests),
                         ", ".join(r.get("path", "?") for r in requests))

                for req in requests:
                    hyps, _raw, _trail = await V.run_request(
                        client, llm, openai_tools, menu, req)
                    for hypothesis in hyps:
                        weakness = self._to_weakness(
                            hypothesis, req, len(weaknesses) + 1)
                        if weakness:
                            weaknesses.append(weakness)
        except Exception as exc:  # noqa: BLE001 — retryable stage failure
            raise WorkFailed(
                f"vuln loop failed: {type(exc).__name__}: {exc}") from exc

        # Rank by severity so Exploitation (which tests a bounded top slice) spends
        # its budget on the highest-impact weaknesses first, then re-id in that order.
        weaknesses.sort(key=lambda w: w.cvss_score, reverse=True)
        weaknesses = [w.model_copy(update={"id": f"W-{i:03d}"})
                      for i, w in enumerate(weaknesses, 1)]
        register = VulnerabilityRegister(weaknesses=weaknesses)
        log.info("register: %d weaknesses from hypotheses (ranked by severity)",
                 len(register.weaknesses))
        return register.model_dump(mode="json")

    @staticmethod
    def _to_weakness(hypothesis: str, req: dict, idx: int) -> Weakness | None:
        lines = hypothesis.splitlines()
        title = (lines[0].strip() or "unspecified weakness")[:200]
        rationale = ""
        for line in lines[1:]:
            if line.strip().lower().startswith("hypothesis:"):
                rationale = line.split(":", 1)[1].strip()[:500]
        vector = _vector_for(title)
        try:
            score = base_score(vector)
        except CvssError:
            return None
        try:
            return Weakness(
                id=f"W-{idx:03d}", title=title, asset=req.get("path") or "/",
                owasp_category="", cvss_vector=vector, cvss_score=score,
                severity=severity_label(score), confidence="possible",
                rationale=rationale or hypothesis[:500], evidence=[])
        except Exception:  # noqa: BLE001 — a malformed item must not kill the stage
            log.warning("dropping unmappable hypothesis: %s", title)
            return None
