"""Adviser — turns the proven findings into a readable report (PRD §5.7).

Reads every stage's artifact and produces the client-facing report. Redesigned
around three rules the raw register did not give a reader:

* **Only proven findings are reported.** A finding is a *confirmed* weakness. The
  unproven and untested candidates are not listed as findings — they would read
  as vulnerabilities the test did not demonstrate — but they are not hidden: a
  coverage line and the caveats state exactly how many were tested and proven.
* **Similar findings are grouped.** The same vulnerability class on the same
  asset is one finding, however many times it was confirmed, carrying all its
  evidence and a proof count. This is the difference between a report and a dump.
* **Impact first.** Findings are ordered most-impactful first, severity assigned
  by the adviser (impact is a reporting judgement — the vuln loop no longer
  scores CVSS).

The judgement runs as a small agentic reasoning loop: the confirmed findings are
pre-grouped deterministically, the model then assigns severity, writes the impact
and remediation, and orders them; a bounded retry corrects malformed output and a
deterministic fallback guarantees a report even if the model is unreachable — the
report is the deliverable and must never be lost.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any

import httpx

from shared import trace
from shared.models import (
    AttackPlaybook,
    EngagementReport,
    Evidence,
    ExecutiveSummary,
    Finding,
)

from agent.services.workers import agentic
from agent.services.workers.base import WorkContext

log = logging.getLogger("agent.workers.adviser")

MAX_STEPS = int(os.environ.get("APTS_ADVISER_MAX_STEPS", "2"))
MAX_TOKENS = int(os.environ.get("APTS_ADVISER_MAX_TOKENS", "2000"))

# Vulnerability class -> (canonical label, default severity). Used to normalise
# titles for grouping and to seed / fall back on severity. Order matters: more
# specific keys first. This is a *reporting* judgement, not a CVSS vector.
_CLASS_RULES = [
    ("nosql", "NoSQL Injection", "critical"),
    ("sql inj", "SQL Injection", "critical"),
    ("command inj", "Command Injection", "critical"),
    ("remote code", "Remote Code Execution", "critical"),
    ("rce", "Remote Code Execution", "critical"),
    ("template inj", "Server-Side Template Injection", "critical"),
    ("ssti", "Server-Side Template Injection", "critical"),
    ("deserial", "Insecure Deserialization", "critical"),
    ("authentication bypass", "Authentication Bypass", "critical"),
    ("login bypass", "Authentication Bypass", "critical"),
    ("account takeover", "Account Takeover", "critical"),
    ("privilege escal", "Privilege Escalation", "high"),
    ("ldap inj", "LDAP Injection", "high"),
    ("mass assign", "Mass Assignment", "high"),
    ("prototype pollution", "Prototype Pollution", "high"),
    ("idor", "IDOR (Broken Access Control)", "high"),
    ("broken access", "Broken Access Control", "high"),
    ("ssrf", "SSRF", "high"),
    ("xxe", "XXE", "high"),
    ("path travers", "Path Traversal / File Inclusion", "high"),
    ("file inclus", "Path Traversal / File Inclusion", "high"),
    ("stored xss", "Stored XSS", "high"),
    ("xss", "Cross-Site Scripting", "high"),
    ("cors", "CORS Misconfiguration", "medium"),
    ("csrf", "CSRF", "medium"),
    ("open redirect", "Open Redirect", "medium"),
    ("information disclosure", "Information Disclosure", "medium"),
    ("info disclos", "Information Disclosure", "medium"),
    ("verbose", "Information Disclosure", "medium"),
    ("version", "Version Disclosure", "low"),
    ("captcha", "CAPTCHA Bypass", "low"),
    ("websocket", "WebSocket Misconfiguration", "medium"),
]
_SEVERITY_SCORE = {"critical": 9.5, "high": 7.5, "medium": 5.0,
                   "low": 2.5, "informational": 1.0}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

SYSTEM_PROMPT = """\
You are writing the FINDINGS section of a penetration-test report. You are given
CONFIRMED, pre-grouped findings — each is already one vulnerability class on one
asset, with how many times it was proven. For every group:
- assign a severity: critical | high | medium | low, by real-world impact;
- write ONE sentence of concrete business impact;
- write a specific, actionable remediation for that asset and class (never
  "validate input");
- give an effort to fix: low | medium | high.
Then ORDER the findings most-impactful first.

Reply with ONLY JSON, no prose:
{"findings":[{"key":"<the exact group key given>","title":"<short finding title>",
  "severity":"critical|high|medium|low","impact":"<one sentence>",
  "recommendation":"<two or three sentences>","effort":"low|medium|high"}],
 "narrative":"<3-5 sentences for a CISO: risk posture, what to fix first, and how
              much confidence these proven results warrant>"}
Use only the group keys given; every group must appear exactly once. Do not invent
findings.
"""


def _class_of(title: str) -> tuple[str, str]:
    """(canonical class label, default severity) for a weakness title."""
    t = (title or "").lower()
    for key, label, sev in _CLASS_RULES:
        if key in t:
            return label, sev
    # Unknown class: keep the title's lead segment as the label, medium default.
    lead = re.split(r"[—\-(:]", title or "", 1)[0].strip() or "Other"
    return lead[:60], "medium"


class AdviserWorker:
    """Aggregates all stage artifacts into a grouped, proven-only, ranked report."""

    def __init__(self, llm, results, reports) -> None:
        self._llm = llm  # kept for parity; the loop uses agentic.chat itself
        self._results = results
        self._reports = reports

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        load = lambda agent: self._results.load(ctx.engagement_id, agent) or {}
        asset_map = load("recon")
        register = load("vuln")
        attack_map = load("mitre")
        exploitation = load("exploit")
        playbook_raw = ctx.upstream if "scripts" in ctx.upstream else load("script")

        weaknesses = register.get("weaknesses", [])
        attempts = {a["weakness_id"]: a for a in exploitation.get("attempts", [])}
        mappings = attack_map.get("mappings", {})

        # Proven only. The unproven/untested are counted (coverage + caveats), not
        # listed as findings.
        proven = [w for w in weaknesses
                  if attempts.get(w.get("id"), {}).get("confirmed")]
        groups = self._pregroup(proven, attempts, mappings)

        findings, narrative = await self._reason(groups)

        n_total = len(weaknesses)
        n_tested = len(attempts)
        n_proven = len(proven)
        coverage = (f"{n_tested} hypotheses tested, {n_proven} proven and reported"
                    f"{f'; {n_total - n_tested} not tested' if n_total > n_tested else ''}"
                    f". Unproven candidates are in the raw artifacts, not shown as findings.")

        report = EngagementReport(
            engagement_id=str(ctx.engagement_id),
            target_url=ctx.target_url,
            executive_summary=self._summarise(findings, narrative, coverage),
            findings=findings,
            playbook=AttackPlaybook(**playbook_raw) if playbook_raw else AttackPlaybook(),
            attack_coverage=self._coverage(mappings, {f.id for f in findings}),
            exploitation_confirmed=n_proven > 0,
            caveats=self._caveats(asset_map, register, exploitation,
                                  n_total, n_tested, n_proven),
        )

        paths = self._reports.save(report)
        log.info("report: %d grouped finding(s) from %d proven weakness(es) → %s",
                 len(findings), n_proven, ", ".join(paths))
        trace.record("report_written", {
            "paths": paths, "findings": len(findings), "confirmed": n_proven,
            "risk_score": report.executive_summary.risk_score})

        payload = report.model_dump(mode="json")
        payload["report_files"] = paths
        return payload

    # --- grouping (deterministic) ---------------------------------------- #

    @staticmethod
    def _pregroup(proven: list[dict], attempts: dict, mappings: dict) -> list[dict]:
        """Collapse proven weaknesses by (class, asset), merging evidence + tags."""
        groups: dict[tuple[str, str], dict] = {}
        for w in proven:
            wid = w.get("id")
            label, default_sev = _class_of(w.get("title", ""))
            asset = w.get("asset", "")
            key = (label, asset)
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "key": f"{label} @ {asset}", "label": label, "asset": asset,
                    "default_severity": default_sev, "wids": [], "count": 0,
                    "evidence": [], "techniques": set(), "reasons": []}
            g["wids"].append(wid)
            g["count"] += 1
            # Merge evidence: the weakness's own + the exploit attempt's.
            for e in w.get("evidence", []):
                g["evidence"].append(e)
            att = attempts.get(wid, {})
            if att.get("evidence"):
                g["evidence"].append(att["evidence"])
            if att.get("reason"):
                g["reasons"].append(att["reason"])
            for tag in mappings.get(wid, []):
                g["techniques"].add(tag.get("technique_id"))
        # Dedup evidence by (request, response); cap per group.
        for g in groups.values():
            seen: set[tuple] = set()
            deduped = []
            for e in g["evidence"]:
                sig = (str(e.get("request"))[:200], str(e.get("response"))[:200])
                if sig not in seen:
                    seen.add(sig)
                    deduped.append(e)
            g["evidence"] = deduped[:5]
            g["techniques"] = sorted(t for t in g["techniques"] if t)
        return list(groups.values())

    # --- the reasoning loop ---------------------------------------------- #

    async def _reason(self, groups: list[dict]) -> tuple[list[Finding], str]:
        """Model assigns severity/impact/fix and orders the groups. Bounded loop
        with a deterministic fallback so a report is always produced."""
        if not groups:
            return [], ("No weaknesses were proven exploitable within the scope "
                        "and time window of this engagement.")

        listing = "\n".join(
            f'- key="{g["key"]}": {g["label"]} on {g["asset"]}, proven '
            f'{g["count"]}x' + (f', ATT&CK {", ".join(g["techniques"])}'
                                if g["techniques"] else '')
            + (f' — {g["reasons"][0][:160]}' if g["reasons"] else '')
            for g in groups)
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": "## Confirmed, grouped findings\n" + listing}]

        by_key = {g["key"]: g for g in groups}
        async with httpx.AsyncClient(timeout=agentic.LLM_TIMEOUT) as llm:
            for step in range(max(MAX_STEPS, 1)):
                try:
                    msg = await agentic.chat(llm, messages, max_tokens=MAX_TOKENS)
                except httpx.HTTPError as exc:
                    log.error("adviser reasoning call failed: %s", exc)
                    break
                data = _parse_json(msg.get("content") or "")
                items = data.get("findings") if isinstance(data, dict) else None
                if isinstance(items, list) and items:
                    findings = self._to_findings(items, by_key)
                    if findings:
                        return findings, str(data.get("narrative") or "")
                # Malformed / empty — one corrective nudge, then fall back.
                messages.append({"role": "assistant",
                                 "content": msg.get("content") or ""})
                messages.append({"role": "user", "content": (
                    "That was not the required JSON. Reply with ONLY the JSON "
                    "object: {\"findings\":[...],\"narrative\":\"...\"}, one entry "
                    "per group key, nothing else.")})

        log.warning("adviser reasoning did not yield usable findings; "
                    "falling back to deterministic grouping")
        return self._fallback(groups), ("Automated summary: the findings below "
                                        "were proven exploitable during the test.")

    def _to_findings(self, items: list[dict], by_key: dict) -> list[Finding]:
        findings: list[Finding] = []
        used: set[str] = set()
        for it in items:
            g = by_key.get(str(it.get("key", "")))
            if g is None or g["key"] in used:
                continue
            used.add(g["key"])
            sev = str(it.get("severity", "")).lower().strip()
            if sev not in _SEVERITY_SCORE:
                sev = g["default_severity"]
            findings.append(self._finding(g, sev,
                                          title=str(it.get("title") or g["label"]),
                                          impact=str(it.get("impact") or ""),
                                          rec=str(it.get("recommendation") or ""),
                                          effort=str(it.get("effort", "medium")).lower()))
        # Any group the model dropped is still a proven finding — never lose it.
        for g in by_key.values():
            if g["key"] not in used:
                findings.append(self._finding(g, g["default_severity"]))
        findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), -f.cvss_score))
        return findings

    def _fallback(self, groups: list[dict]) -> list[Finding]:
        findings = [self._finding(g, g["default_severity"]) for g in groups]
        findings.sort(key=lambda f: (_SEVERITY_RANK.get(f.severity, 9), -f.cvss_score))
        return findings

    @staticmethod
    def _finding(g: dict, severity: str, *, title: str = "", impact: str = "",
                 rec: str = "", effort: str = "medium") -> Finding:
        note = f"Confirmed via {g['count']} attempt(s)."
        recommendation = " ".join(p for p in (impact, rec) if p).strip() or note
        return Finding(
            id=g["wids"][0], title=title or g["label"], asset=g["asset"],
            severity=severity, cvss_score=_SEVERITY_SCORE.get(severity, 5.0),
            cvss_vector="", confirmed=True,
            status=f"confirmed exploitable ({g['count']} proof(s))",
            technique_ids=list(g["techniques"]), owasp_category="",
            recommendation=recommendation,
            effort=effort if effort in ("low", "medium", "high") else "medium",
            evidence=[Evidence(**e) for e in g["evidence"]][:5])

    # --- summary + caveats ----------------------------------------------- #

    @staticmethod
    def _summarise(findings: list[Finding], narrative: str,
                   coverage: str) -> ExecutiveSummary:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        risk = max((f.cvss_score for f in findings), default=0.0)
        full_narrative = (coverage + "\n\n" + narrative).strip() if narrative else coverage
        return ExecutiveSummary(
            risk_score=risk, narrative=full_narrative, counts_by_severity=counts,
            confirmed_count=len(findings), total_findings=len(findings))

    @staticmethod
    def _coverage(mappings: dict, known: set[str]) -> dict[str, list[str]]:
        coverage: dict[str, list[str]] = {}
        for weakness_id, tags in mappings.items():
            if weakness_id not in known:
                continue
            for tag in tags:
                coverage.setdefault(tag["technique_id"], []).append(weakness_id)
        return {k: sorted(v) for k, v in sorted(coverage.items())}

    @staticmethod
    def _caveats(asset_map: dict, register: dict, exploitation: dict,
                 n_total: int, n_tested: int, n_proven: int) -> list[str]:
        """State what limits these results. Generated from the run, not boilerplate."""
        caveats = [
            "Produced by an autonomous pipeline with no human review. Findings "
            "should be validated by a security engineer before remediation is "
            "prioritised or the results are shared externally.",
            f"Only proven findings are listed. Of {n_total} candidate weakness(es), "
            f"{n_tested} were tested for exploitability and {n_proven} were proven; "
            f"the remainder are hypotheses and are not reported as findings.",
        ]
        if asset_map.get("truncated"):
            caveats.append(
                f"The crawl hit a configured limit after "
                f"{asset_map.get('pages_crawled', '?')} pages, so the asset map is "
                f"a lower bound and parts of the application were never seen.")
        skipped = exploitation.get("skipped") or []
        if skipped:
            caveats.append(
                f"{len(skipped)} weakness(es) were never tested for exploitability. "
                f"No claim is made about them either way.")
        caveats.append(
            "Absence of a finding is not evidence of absence. This engagement "
            "covered what the crawler reached within its configured bounds.")
        return caveats


def _parse_json(text: str) -> dict:
    """Pull the JSON object out of the model's reply, tolerant of stray prose."""
    m = re.search(r"\{.*\}", text or "", re.DOTALL)
    if not m:
        return {}
    try:
        data = json.loads(m.group(0))
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}
