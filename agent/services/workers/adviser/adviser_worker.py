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
import re
from typing import Any

from shared import prompts, trace
from shared.llm import (build_chat_model, flush, run_config, set_run_output,
                        trace_run)
from shared.models import (
    AttackPlaybook,
    EngagementReport,
    Evidence,
    ExecutiveSummary,
    Finding,
)

from agent.services.workers.common import common_agentic as agentic
from agent.services.workers.base import WorkContext
from .adviser_constants import (
    ADVISER_SYSTEM_PROMPT_ID, MAX_STEPS, MAX_TOKENS, _CLASS_RULES, _SEVERITY_RANK, _SEVERITY_SCORE)

log = logging.getLogger("agent.workers.adviser")


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

    def __init__(self, results, reports) -> None:
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

        model = build_chat_model("adviser", max_tokens=MAX_TOKENS)
        config = run_config(engagement_id=str(ctx.engagement_id), agent="adviser")
        with trace_run(name="adviser", run_input=f"reason over {len(groups)} finding group(s)", engagement_id=str(ctx.engagement_id)) as _stage:
            try:
                findings, narrative = await self._reason(
                    groups, agentic.directive_block(ctx.directive), model, config)
            finally:
                flush()  # short-lived stage: push any buffered Langfuse spans
            set_run_output(_stage, f"{len(findings)} finding(s)")

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
            loot=self._dedup_loot(exploitation.get("loot", [])),
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

    _LOOT_JUNK = ("request failed", "error", "all connection attempts",
                  "connection refused", "timed out", "none")

    @classmethod
    def _dedup_loot(cls, loot: list[dict]) -> list[dict]:
        """Drop junk (empty/None/error values) and near-duplicates (same value seen
        on many weaknesses), keeping the first source. So the report's collected-data
        table is signal, not noise. Capped."""
        seen: set[str] = set()
        out: list[dict] = []
        for item in loot:
            if not isinstance(item, dict):
                continue
            val = str(item.get("value", "")).strip()
            low = val.lower()
            if not val or low in ("none", "null", "n/a", "-", "(none)", "(empty)",
                                  "(no data)", "unknown", "true", "false"):
                continue
            if any(low.startswith(j) for j in cls._LOOT_JUNK):
                continue
            vkey = low[:60]
            if vkey in seen:
                continue
            seen.add(vkey)
            out.append({"type": (str(item.get("type", "")).strip() or "data")[:40],
                        "value": val[:200], "source": item.get("source", "")})
            if len(out) >= 30:
                break
        return out

    # --- grouping (deterministic) ---------------------------------------- #

    @staticmethod
    def _pregroup(proven: list[dict], attempts: dict, mappings: dict) -> list[dict]:
        """Collapse proven weaknesses by (PROVEN class, asset), merging evidence.

        Keyed by what Exploitation actually PROVED (``proven_vuln``), NOT the
        hypothesis title — so 'Account Takeover', 'LDAP Injection' and 'SQL
        Injection' that all proved the same SQLi on the same login endpoint
        collapse into one group instead of three. The model can merge further."""
        groups: dict[tuple[str, str], dict] = {}
        for w in proven:
            wid = w.get("id")
            att = attempts.get(wid, {})
            # What was PROVEN drives the group; fall back to the hypothesis title.
            label, default_sev = _class_of(att.get("proven_vuln") or w.get("title", ""))
            asset = w.get("asset", "")
            key = (label, asset)
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "key": f"{label} @ {asset}", "label": label, "asset": asset,
                    "default_severity": default_sev, "wids": [], "count": 0,
                    "evidence": [], "techniques": set(), "reasons": [],
                    "hypotheses": [], "writeups": [], "bases": set()}
            g["wids"].append(wid)
            g["count"] += 1
            if w.get("title"):
                g["hypotheses"].append(str(w["title"])[:80])
            if att.get("writeup"):
                g["writeups"].append(str(att["writeup"])[:200])
            if att.get("signal_basis"):
                g["bases"].add(str(att["signal_basis"]).split(" ")[0])
            # Merge evidence: the weakness's own + the exploit attempt's.
            for e in w.get("evidence", []):
                g["evidence"].append(e)
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
            g["hypotheses"] = list(dict.fromkeys(g["hypotheses"]))  # dedup, keep order
            g["bases"] = sorted(g["bases"])
        return list(groups.values())

    # --- the reasoning loop ---------------------------------------------- #

    async def _reason(self, groups: list[dict], directive: str,
                      model, config: dict) -> tuple[list[Finding], str]:
        """Model assigns severity/impact/fix and orders the groups. Bounded loop
        with a deterministic fallback so a report is always produced."""
        if not groups:
            return [], ("No weaknesses were proven exploitable within the scope "
                        "and time window of this engagement.")

        def _line(g: dict) -> str:
            out = (f'- key="{g["key"]}": proved {g["label"]} on {g["asset"]} '
                   f'({g["count"]}x')
            if g.get("bases"):
                out += f', via {", ".join(g["bases"])}'
            out += ")"
            if g.get("hypotheses"):
                out += f'\n    from hypotheses: {"; ".join(g["hypotheses"])[:160]}'
            if g.get("writeups"):
                out += f'\n    proved: {g["writeups"][0]}'
            if g.get("evidence"):
                out += f'\n    evidence: {str(g["evidence"][0].get("request", ""))[:120]}'
            if g.get("techniques"):
                out += f'\n    ATT&CK: {", ".join(g["techniques"])}'
            return out
        listing = "\n".join(_line(g) for g in groups)
        system = prompts.get(ADVISER_SYSTEM_PROMPT_ID)  # Langfuse-backed, default fallback
        user = directive + "## Confirmed, grouped findings\n" + listing
        convo = agentic.to_lc_messages(system.text, user)

        by_key = {g["key"]: g for g in groups}
        with trace_run(name="adviser-reason", run_input=user,
                       prompt=system.trace_prompt) as span:
            for _ in range(max(MAX_STEPS, 1)):
                try:
                    msg = await model.ainvoke(convo, config=config)
                except Exception as exc:  # noqa: BLE001 — a failed call falls back
                    log.error("adviser reasoning call failed: %s", exc)
                    break
                reply = agentic.message_text(msg)
                data = _parse_json(reply)
                items = data.get("findings") if isinstance(data, dict) else None
                if isinstance(items, list) and items:
                    findings = self._to_findings(items, by_key)
                    if findings:
                        set_run_output(span, f"{len(findings)} finding(s)")
                        return findings, str(data.get("narrative") or "")
                # Malformed / empty — one corrective nudge, then fall back.
                convo.append(agentic.AIMessage(content=reply))
                convo.append(agentic.HumanMessage(content=(
                    "That was not the required JSON. Reply with ONLY the JSON "
                    "object: {\"findings\":[...],\"narrative\":\"...\"}, one entry "
                    "per group key, nothing else.")))
            set_run_output(span, "(fell back to deterministic grouping)")

        log.warning("adviser reasoning did not yield usable findings; "
                    "falling back to deterministic grouping")
        return self._fallback(groups), ("Automated summary: the findings below "
                                        "were proven exploitable during the test.")

    @staticmethod
    def _merge_groups(gs: list[dict]) -> dict:
        """Combine several groups the model merged into one, unioning evidence,
        techniques, wids, hypotheses. Severity default = the most severe."""
        if len(gs) == 1:
            return gs[0]
        m = {"key": gs[0]["key"], "label": gs[0]["label"], "asset": gs[0]["asset"],
             "wids": [], "count": 0, "evidence": [], "techniques": set(),
             "reasons": [], "hypotheses": [], "writeups": [], "bases": set()}
        for g in gs:
            m["wids"] += g["wids"]
            m["count"] += g["count"]
            m["evidence"] += g["evidence"]
            m["techniques"] |= set(g.get("techniques", []))
            m["reasons"] += g.get("reasons", [])
            m["hypotheses"] += g.get("hypotheses", [])
            m["writeups"] += g.get("writeups", [])
            m["bases"] |= set(g.get("bases", []))
        m["techniques"] = sorted(t for t in m["techniques"] if t)
        m["hypotheses"] = list(dict.fromkeys(m["hypotheses"]))
        m["bases"] = sorted(m["bases"])
        m["evidence"] = m["evidence"][:5]
        m["default_severity"] = sorted(
            (g["default_severity"] for g in gs),
            key=lambda s: _SEVERITY_RANK.get(s, 9))[0]
        return m

    def _to_findings(self, items: list[dict], by_key: dict) -> list[Finding]:
        findings: list[Finding] = []
        used: set[str] = set()
        for it in items:
            # Accept a merged finding ("keys": [...]) or a single "key".
            keys = it.get("keys") if isinstance(it.get("keys"), list) else None
            if not keys and it.get("key"):
                keys = [it["key"]]
            gs = [by_key[k] for k in (keys or []) if k in by_key and k not in used]
            if not gs:
                continue
            for g in gs:
                used.add(g["key"])
            g = self._merge_groups(gs)
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
        n_hyp = len(g.get("hypotheses", []) or g.get("wids", []))
        status = (f"confirmed exploitable ({g['count']} proof(s)"
                  + (f"; merged from {n_hyp} hypotheses" if n_hyp > 1 else "") + ")")
        return Finding(
            id=g["wids"][0], title=title or g["label"], asset=g["asset"],
            severity=severity, cvss_score=_SEVERITY_SCORE.get(severity, 5.0),
            cvss_vector="", confirmed=True,
            status=status,
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
    def _caveats(asset_map: dict, _register: dict, exploitation: dict,
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
