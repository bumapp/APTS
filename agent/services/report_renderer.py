"""Renders an :class:`EngagementReport` to Markdown.

Markdown rather than PDF: WeasyPrint is not in the image, and a PDF that cannot
be produced is worse than a document that renders anywhere. §5.8 asks for PDF
plus machine-readable JSON — the JSON half is exact, and this is the human half
until the ``report`` MCP tool wraps a real renderer.

The one editorial rule enforced here: **the report never lets an unproven
finding read as proven.** Every finding carries its status in plain language,
the summary states how many were actually confirmed, and the caveats section is
always present. A clean-looking report over a shallow test is the most damaging
artifact this system could produce.
"""
from __future__ import annotations

from shared.models import EngagementReport

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


def render_markdown(report: EngagementReport) -> str:
    """Return the report as a Markdown document."""
    summary = report.executive_summary
    out: list[str] = []

    out.append(f"# Penetration Test Report")
    out.append("")
    out.append(f"**Target:** `{report.target_url}`  ")
    out.append(f"**Engagement:** `{report.engagement_id}`  ")
    out.append(f"**Generated:** {report.generated_at:%Y-%m-%d %H:%M UTC}  ")
    out.append(f"**Produced by:** APTS — autonomous pipeline, no human review")
    out.append("")

    if not report.exploitation_confirmed:
        out.append("> **Weaknesses found but not confirmed.** The exploitation "
                   "stage did not complete, so no finding below has been proven "
                   "exploitable. Treat every entry as a hypothesis.")
        out.append("")

    # ---- Executive summary ------------------------------------------- #
    out.append("## Executive summary")
    out.append("")
    out.append(summary.narrative)
    out.append("")
    out.append(f"| | |")
    out.append(f"|---|---|")
    out.append(f"| Risk score | **{summary.risk_score}** / 10 |")
    out.append(f"| Findings | {summary.total_findings} |")
    out.append(f"| Confirmed exploitable | **{summary.confirmed_count}** |")
    for severity in _SEVERITY_ORDER:
        count = summary.counts_by_severity.get(severity, 0)
        if count:
            out.append(f"| {severity.capitalize()} | {count} |")
    out.append("")

    # ---- Findings ----------------------------------------------------- #
    out.append("## Finding register")
    out.append("")
    out.append("| ID | Severity | CVSS | Status | Asset | Finding |")
    out.append("|---|---|---|---|---|---|")
    for finding in report.findings:
        mark = "**CONFIRMED**" if finding.confirmed else finding.status
        out.append(
            f"| {finding.id} | {finding.severity} | {finding.cvss_score} | "
            f"{mark} | `{finding.asset}` | {finding.title} |")
    out.append("")

    # ---- Detail ------------------------------------------------------- #
    out.append("## Findings in detail")
    out.append("")
    for finding in report.findings:
        out.append(f"### {finding.id} — {finding.title}")
        out.append("")
        out.append(f"- **Asset:** `{finding.asset}`")
        out.append(f"- **Severity:** {finding.severity} "
                   f"(CVSS {finding.cvss_score}, `{finding.cvss_vector}`)")
        out.append(f"- **Status:** {finding.status}")
        if finding.owasp_category:
            out.append(f"- **OWASP:** {finding.owasp_category}")
        if finding.technique_ids:
            out.append(f"- **ATT&CK:** {', '.join(finding.technique_ids)}")
        out.append(f"- **Remediation effort:** {finding.effort}")
        out.append("")
        if finding.recommendation:
            out.append(f"**Recommendation.** {finding.recommendation}")
            out.append("")
        for evidence in finding.evidence[:2]:
            out.append("```http")
            out.append(evidence.request)
            out.append("")
            out.append(evidence.response[:600])
            out.append("```")
            if evidence.note:
                out.append(f"*{evidence.note}*")
            out.append("")

    # ---- Playbook ----------------------------------------------------- #
    out.append("## Attack playbook")
    out.append("")
    if report.playbook.scripts:
        out.append("Reproduction scripts for confirmed findings only. Each has "
                   "passed a static safety check and performs no destructive "
                   "action.")
        out.append("")
        for script in report.playbook.scripts:
            out.append(f"### {script.weakness_id} — reproduction")
            out.append("")
            if script.description:
                out.append(script.description)
                out.append("")
            out.append(f"```{script.language}")
            out.append(script.source)
            out.append("```")
            out.append("")
            if script.remediation_pointer:
                out.append(f"**Fix.** {script.remediation_pointer}")
                out.append("")
    else:
        out.append("_No scripts. Nothing was confirmed exploitable, and a "
                   "reproduction script for an unproven finding would be a "
                   "guess presented as a demonstration._")
        out.append("")
    if report.playbook.rejected:
        out.append(f"_{report.playbook.rejected} generated script(s) were "
                   f"rejected by the safety check and are not included._")
        out.append("")

    # ---- ATT&CK coverage ---------------------------------------------- #
    out.append("## ATT&CK coverage")
    out.append("")
    if report.attack_coverage:
        out.append("| Technique | Findings |")
        out.append("|---|---|")
        for technique, findings in sorted(report.attack_coverage.items()):
            out.append(f"| `{technique}` | {', '.join(findings)} |")
    else:
        out.append("_No techniques mapped._")
    out.append("")

    # ---- Caveats ------------------------------------------------------ #
    out.append("## Caveats and limitations")
    out.append("")
    out.append("These bound how far the results above can be relied on.")
    out.append("")
    for caveat in report.caveats:
        out.append(f"- {caveat}")
    out.append("")

    return "\n".join(out)
