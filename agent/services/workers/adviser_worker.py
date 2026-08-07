"""Adviser — assembles the deliverable (PRD §5.8).

Reads every stage's artifact from the shared store and produces the report the
client actually receives. This is the last point at which the system can
misrepresent what it did, so most of the logic here is about *not* doing that.

Three rules the assembly enforces:

**Status is never collapsed.** A finding is confirmed, tested-but-not-proven, or
never-tested. Folding the last two into "no issue" would claim coverage the
engagement did not have — and the second is far more alarming than the third.

**The risk score is the worst confirmed finding, not an average.** Averaging is
how a report with one critical and eleven lows reports as "medium". If nothing
was confirmed, the score reflects the worst unproven finding and the summary
says so explicitly.

**Caveats are mandatory.** Every report carries them, generated from what
actually happened in this run — stubbed stages, truncated crawls, unproven
findings. A report with no stated limitations is making a claim of completeness
that an autonomous pipeline has not earned.

Recommendations come from the model, because asset-specific remediation advice
is genuine writing work. Severities, scores, counts, and statuses do not — they
are computed from the artifacts, so the numbers cannot drift from the evidence.
"""
from __future__ import annotations

import logging
from typing import Any

from shared import trace
from shared.cvss import severity_label
from shared.llm import LlmClient, LlmError
from shared.models import (
    AttackPlaybook,
    EngagementReport,
    Evidence,
    ExecutiveSummary,
    Finding,
)

from agent.services.workers.base import WorkContext

log = logging.getLogger("agent.workers.adviser")

SYSTEM_PROMPT = """\
You are writing the remediation guidance for a penetration test report.

For each finding, give a specific, actionable fix for that asset and technology
— not generic advice. Reply with ONLY JSON:
{"recommendations": {"W-001": {"fix": "<two or three sentences>",
                               "effort": "low" | "medium" | "high"}},
 "narrative": "<3-5 sentences for a CISO: what the risk posture is, what to do
               first, and how much confidence these results warrant>"}

Rules:
- Address the specific asset and weakness. "Validate input" is not a fix.
- Be honest about confidence. Findings marked unproven are hypotheses; say so
  in the narrative rather than implying the test confirmed them.
- Do not invent findings that are not listed.
"""


class AdviserWorker:
    """Aggregates all stage artifacts into the final report."""

    def __init__(self, llm: LlmClient, results, reports) -> None:
        self._llm = llm
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

        advice, narrative = await self._advise(weaknesses, attempts)
        findings = self._build_findings(weaknesses, attempts, mappings, advice)

        report = EngagementReport(
            engagement_id=str(ctx.engagement_id),
            target_url=ctx.target_url,
            executive_summary=self._summarise(findings, narrative),
            findings=findings,
            playbook=AttackPlaybook(**playbook_raw) if playbook_raw else AttackPlaybook(),
            attack_coverage=self._coverage(mappings, {f.id for f in findings}),
            exploitation_confirmed=bool(exploitation.get("attempts")),
            caveats=self._caveats(asset_map, register, exploitation, findings),
        )

        paths = self._reports.save(report)
        log.info("report: %d findings (%d confirmed) → %s",
                 len(findings), report.executive_summary.confirmed_count,
                 ", ".join(paths))
        trace.record("report_written", {
            "paths": paths,
            "findings": len(findings),
            "confirmed": report.executive_summary.confirmed_count,
            "risk_score": report.executive_summary.risk_score,
        })

        payload = report.model_dump(mode="json")
        payload["report_files"] = paths
        return payload

    # ----------------------------------------------------------------- #

    async def _advise(self, weaknesses: list[dict],
                      attempts: dict) -> tuple[dict, str]:
        """Ask the model for remediation text. Never for severities or counts."""
        if not weaknesses:
            return {}, ("No weaknesses were identified on the target within the "
                        "scope and time window of this engagement.")

        lines = []
        for weakness in weaknesses:
            attempt = attempts.get(weakness["id"])
            state = ("CONFIRMED exploitable" if attempt and attempt.get("confirmed")
                     else "tested, not proven" if attempt else "not tested")
            lines.append(
                f"{weakness['id']}: {weakness.get('title')} on "
                f"{weakness.get('asset')} — CVSS {weakness.get('cvss_score')}, "
                f"{state}")

        try:
            raw = await self._llm.complete_json(SYSTEM_PROMPT, "\n".join(lines))
        except LlmError as exc:
            # The report is the deliverable; missing prose must not lose it.
            log.error("advice generation failed, reporting without it: %s", exc)
            return {}, ("Remediation narrative unavailable: the language model "
                        "could not be reached. The findings below are complete.")

        recommendations = raw.get("recommendations")
        return (recommendations if isinstance(recommendations, dict) else {},
                str(raw.get("narrative") or ""))

    @staticmethod
    def _build_findings(weaknesses: list[dict], attempts: dict,
                        mappings: dict, advice: dict) -> list[Finding]:
        findings: list[Finding] = []
        for weakness in weaknesses:
            wid = weakness["id"]
            attempt = attempts.get(wid)
            confirmed = bool(attempt and attempt.get("confirmed"))

            if confirmed:
                status = "confirmed exploitable"
            elif attempt:
                status = f"tested, not proven ({attempt.get('reason', 'no signal')})"
            else:
                status = "not tested"

            evidence = [Evidence(**e) for e in weakness.get("evidence", [])]
            if attempt and attempt.get("evidence"):
                evidence.append(Evidence(**attempt["evidence"]))

            guidance = advice.get(wid) or {}
            effort = guidance.get("effort")
            score = float(weakness.get("cvss_score", 0.0))

            findings.append(Finding(
                id=wid,
                title=weakness.get("title", "unspecified"),
                asset=weakness.get("asset", ""),
                severity=severity_label(score),
                cvss_score=score,
                cvss_vector=weakness.get("cvss_vector", ""),
                confirmed=confirmed,
                status=status,
                technique_ids=[t["technique_id"] for t in mappings.get(wid, [])],
                owasp_category=weakness.get("owasp_category", ""),
                recommendation=str(guidance.get("fix") or ""),
                effort=effort if effort in ("low", "medium", "high") else "medium",
                evidence=evidence[:3],
            ))

        # Confirmed first, then by severity: the ordering a reader needs.
        findings.sort(key=lambda f: (not f.confirmed, -f.cvss_score))
        return findings

    @staticmethod
    def _summarise(findings: list[Finding], narrative: str) -> ExecutiveSummary:
        confirmed = [f for f in findings if f.confirmed]
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

        # Worst confirmed, else worst unproven. Never an average.
        if confirmed:
            risk = max(f.cvss_score for f in confirmed)
        elif findings:
            risk = max(f.cvss_score for f in findings)
        else:
            risk = 0.0

        return ExecutiveSummary(
            risk_score=risk,
            narrative=narrative,
            counts_by_severity=counts,
            confirmed_count=len(confirmed),
            total_findings=len(findings),
        )

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
                 findings: list[Finding]) -> list[str]:
        """State what limits these results. Generated from the run, not boilerplate."""
        caveats = [
            "Produced by an autonomous pipeline with no human review. Findings "
            "should be validated by a security engineer before remediation is "
            "prioritised or the results are shared externally.",
        ]

        if asset_map.get("truncated"):
            caveats.append(
                f"The crawl hit a configured limit after "
                f"{asset_map.get('pages_crawled', '?')} pages, so the asset map "
                f"is a lower bound and parts of the application were never seen.")

        if asset_map.get("api_paths"):
            caveats.append(
                "API routes were extracted from client-side JavaScript. They are "
                "candidate routes the application references, not a verified "
                "inventory of its endpoints.")

        unproven = [f.id for f in findings if not f.confirmed]
        if unproven:
            caveats.append(
                f"{len(unproven)} of {len(findings)} findings were not proven "
                f"exploitable ({', '.join(unproven[:8])}"
                f"{', …' if len(unproven) > 8 else ''}). They are hypotheses "
                f"based on observed assets, not demonstrated vulnerabilities.")

        skipped = exploitation.get("skipped") or []
        if skipped:
            caveats.append(
                f"{len(skipped)} findings were never tested for exploitability "
                f"({', '.join(skipped[:8])}). No claim is made about them either "
                f"way.")

        dropped = register.get("candidates_dropped", 0)
        if dropped:
            caveats.append(
                f"{dropped} proposed weakness(es) were discarded because their "
                f"asset did not exist or their CVSS vector was invalid.")

        caveats.append(
            "Absence of a finding is not evidence of absence. This engagement "
            "covered what the crawler reached within its configured bounds.")
        return caveats
