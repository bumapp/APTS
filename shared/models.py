"""Message envelopes exchanged between components.

Every request between APTS components carries a JSON body matching one of these
models. Keeping them in one shared module means the orchestrator, every agent,
and the MCP tools container all agree on the wire format.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


# --------------------------------------------------------------------------- #
# The engagement itself
# --------------------------------------------------------------------------- #

class Scope(BaseModel):
    """The boundary the system is allowed to operate in (per Characterization §2.2.8)."""
    domains: list[str] = Field(default_factory=list, description="e.g. ['*.example.com']")
    allow_paths: list[str] = Field(default_factory=list, description="e.g. ['/app/']")
    deny_paths: list[str] = Field(default_factory=list, description="e.g. ['/admin/']")


class TimeWindow(BaseModel):
    starts_at: datetime | None = None
    ends_at: datetime | None = None


class EngagementSpec(BaseModel):
    """What the operator submits via the CLI to kick off a run."""
    target_url: str
    scope: Scope
    time_window: TimeWindow | None = None
    objective: str = Field(default="",
        description="Free-text engagement brief from the operator — any intent at all "
                    "(what to concentrate on or ignore, how aggressive to be, a stage "
                    "to skip). Advisory: the orchestrator folds it into the directive "
                    "it composes for EVERY stage, so it steers the whole run. Never "
                    "narrows scope by itself — the Scope still bounds what may be "
                    "touched. Empty means test broadly.")
    credentials: dict[str, Any] = Field(default_factory=dict,
        description="Optional auth for crawling behind a login: {headers: {...}, "
                    "cookies: [...], basic_auth: {...}}. Used by Recon's crawl; "
                    "sent only to in-scope hosts.")


# --------------------------------------------------------------------------- #
# Chain handoff — Agent → Agent (and Orchestrator → Recon for the first hop)
# --------------------------------------------------------------------------- #

class ChainHandoff(BaseModel):
    """The payload one agent pushes to the next.

    For the Orchestrator → Recon kickoff, `results` is empty and only
    `engagement_id`, `target_url`, and `scope` matter.
    """
    engagement_id: UUID
    from_component: str            # 'orchestrator' or 'agent-<name>'
    target_url: str
    scope: Scope
    time_window: TimeWindow | None = None
    results: dict[str, Any] = Field(default_factory=dict,
        description="The producing agent's result payload. Empty for the initial kickoff.")
    directive: str = Field(default="",
        description="The orchestrator's natural-language start prompt for this "
                    "stage, generated from the previous stage's output. Advisory "
                    "framing only — the structured artifact still flows via "
                    "`results`. Empty in agent-driven mode.")
    credentials: dict[str, Any] = Field(default_factory=dict,
        description="Optional auth carried to Recon for an authenticated crawl "
                    "(headers/cookies/basic_auth). Empty for unauthenticated runs.")


class HandoffAck(BaseModel):
    """Immediate acknowledgment the receiving agent returns."""
    engagement_id: UUID
    accepted_by: str
    started_at: datetime


# --------------------------------------------------------------------------- #
# Progress updates — Agent → Orchestrator
# --------------------------------------------------------------------------- #

ProgressStatus = Literal["started", "in_progress", "done", "failed"]


class ProgressUpdate(BaseModel):
    engagement_id: UUID
    agent: str                     # 'recon', 'vuln', 'mitre', 'exploit', 'script', 'adviser'
    status: ProgressStatus
    message: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    at: datetime = Field(default_factory=datetime.utcnow)


class ProgressAck(BaseModel):
    received: bool = True


# --------------------------------------------------------------------------- #
# MCP tool call — Agent → MCP tools container
# --------------------------------------------------------------------------- #

class ToolCall(BaseModel):
    engagement_id: UUID
    tool: str                      # 'scanner', 'http', 'cve', 'attack_kb', 'sandbox', 'report'
    args: dict[str, Any] = Field(default_factory=dict)


class ToolResult(BaseModel):
    tool: str
    ok: bool
    output: dict[str, Any] = Field(default_factory=dict)
    blocked_by_guardrails: bool = False
    reason: str | None = None


# --------------------------------------------------------------------------- #
# Sandbox exec — MCP tools → sandbox container
# --------------------------------------------------------------------------- #

class SandboxExecRequest(BaseModel):
    engagement_id: UUID
    # Legacy raw-command mode, kept for the mcp-tools SandboxService.
    command: str = ""
    # Script mode: the native sandbox tool sends a whole program to run. When
    # ``language`` is set, ``source`` is written to a file under /tmp and run
    # with ``args`` as argv; ``command`` is ignored.
    language: Literal["python", "bash"] | None = None
    source: str = ""
    args: list[str] = Field(default_factory=list)
    timeout_seconds: int = 20


class SandboxExecResult(BaseModel):
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_ms: int = 0


# --------------------------------------------------------------------------- #
# Operator CLI → Orchestrator admin API
# --------------------------------------------------------------------------- #

class StartEngagementResponse(BaseModel):
    engagement_id: UUID
    status: str


class EngagementStatus(BaseModel):
    engagement_id: UUID
    target_url: str
    status: str
    per_agent: dict[str, dict[str, Any]] = Field(default_factory=dict,
        description="Keyed by agent name; each value has status + retry_count + last_error.")
    started_at: datetime | None = None
    completed_at: datetime | None = None


# --------------------------------------------------------------------------- #
# Engagement artifacts
#
# One typed artifact per pipeline stage is the eventual goal (PRD §5.2–§5.8).
# Only the MITRE stage has one so far, because it is the only stage backed by a
# real model — and a model's output is exactly what must not be trusted as an
# untyped dict. The remaining five arrive with their agents.
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# Recon → Asset Map (§5.2)
# --------------------------------------------------------------------------- #

class FormField(BaseModel):
    name: str
    type: str = "text"


class Form(BaseModel):
    """An input surface. These are where the Vulnerability agent starts."""
    page: str
    method: str = "GET"
    action: str = ""
    fields: list[FormField] = Field(default_factory=list)


class Endpoint(BaseModel):
    path: str
    method: str = "GET"
    status: int | None = None
    params: list[str] = Field(default_factory=list)
    content_type: str = ""
    response_headers: dict[str, str] = Field(default_factory=dict,
        description="The page's full response headers, verbatim. Part of the "
                    "target's technological basis (Server, X-Powered-By, Set-Cookie, "
                    "CSP/security headers, custom X-* headers) that later stages read "
                    "— recon records them in full rather than distilling to a couple.")


class Technology(BaseModel):
    name: str
    version: str | None = None
    source: str = Field(default="", description="Which signal identified it.")


class ObservedRequest(BaseModel):
    """One HTTP request the browser actually fired during the crawl.

    Observed on the wire, not inferred: every field is what the browser put in
    the request. Only in-scope requests are recorded — cross-origin traffic
    (analytics, CDNs, external links) is dropped before it reaches here — so
    nothing in this list points off the approved target. These are the concrete
    API calls the app makes, including the POST bodies it sends, which is the
    richest signal the Vulnerability stage gets about how the app really works.
    """
    method: str
    url: str
    resource_type: str = ""
    content_type: str = ""
    post_data: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    source_page: str = Field(default="",
        description="The page whose activity fired this request — the URL the "
                    "browser was on when the request went out.")
    # Set by the recon loop's verification pass: the model ranks each observed
    # request for how worth testing it is, keeping (not dropping) everything so
    # the next stage decides. Empty until that pass runs.
    interest: str = Field(default="",
        description="Model's test-worthiness rating: high | medium | low.")
    interest_reason: str = Field(default="",
        description="One line: why the model rated it that way.")


class AssetMap(BaseModel):
    """The attack surface Recon discovered; consumed by Vulnerability Assessment."""
    target_url: str
    endpoints: list[Endpoint] = Field(default_factory=list)
    forms: list[Form] = Field(default_factory=list)
    technologies: list[Technology] = Field(default_factory=list)
    api_paths: list[str] = Field(default_factory=list,
        description="Candidate API routes mined from JS bundles. On a single-page "
                    "app this is most of the real surface, since the HTML shell "
                    "has no links. Candidates, not confirmed endpoints.")
    observed_requests: list[ObservedRequest] = Field(default_factory=list,
        description="Every in-scope HTTP request the browser actually fired while "
                    "crawling (XHR/fetch, plus any non-GET such as a login POST), "
                    "deduplicated by method+url+body. Unlike api_paths these are "
                    "confirmed calls with their real payloads, not path guesses.")
    third_party: list[str] = Field(default_factory=list,
        description="External script hosts — supply-chain surface.")
    pages_crawled: int = 0
    truncated: bool = Field(default=False,
        description="True when a crawl limit stopped the sweep early. The map is "
                    "then a lower bound, and any coverage figure derived from it "
                    "must say so rather than reading as complete.")
    # --- additive metadata from the phased recon (downstream still reads the raw
    # surface above directly, so these never remove a request/endpoint) ---
    mode: str = Field(default="", description="Recon mode: broad | focused.")
    summary: str = Field(default="", description="Recon's summary of the surface.")
    findings: list[dict[str, Any]] = Field(default_factory=list,
        description="Graded recon findings — each {finding, where, category, grade, "
                    "reason, page, request}. `request` is the raw captured request when one exists.")
    findings_tree: dict[str, Any] = Field(default_factory=dict,
        description="Findings grouped for the report/UI: {summary, rogue_findings, "
                    "pages:[{page, findings}]}. Rogue (no backing page) listed first.")
    request_tree: dict[str, Any] = Field(default_factory=dict,
        description="Recorded surface as a tree: {summary, technologies, pages:[{page, "
                    "requests}]}. Derived view; observed_requests stays authoritative.")
    peek: list[dict[str, Any]] = Field(default_factory=list,
        description="Phase-0.5 peek behaviour map: per route {requested, title, inputs, "
                    "buttons, xhr_on_load}. Why recon judged a page interesting.")


# --------------------------------------------------------------------------- #
# Vulnerability Assessment → Vulnerability Register (§5.3)
# --------------------------------------------------------------------------- #

Severity = Literal["critical", "high", "medium", "low", "informational"]
Confidence = Literal["confirmed", "probable", "possible"]


class Evidence(BaseModel):
    """A captured request/response pair backing a claim.

    §5.3 makes evidence an acceptance criterion, and rightly: a finding with no
    artifact is an assertion. Everything here was observed, not inferred.
    """
    request: str
    response: str
    note: str = ""
    captured_at: datetime = Field(default_factory=datetime.utcnow)


class Weakness(BaseModel):
    """One candidate weakness on a real asset.

    The Vulnerability stage no longer scores these (CVSS was removed there); the
    fields below stay optional so a weakness is just a typed hypothesis until the
    Adviser assigns severity/impact over what Exploitation proved.

    ``confidence`` is deliberately conservative. Nothing reaches ``confirmed``
    without the Exploitation stage proving it; a weakness whose asset merely
    responds is ``probable`` at best.
    """
    id: str = Field(pattern=r"^W-\d{3,}$", description="Stable ID, e.g. W-001.")
    title: str
    asset: str = Field(description="Path this affects, e.g. /rest/user/login.")
    owasp_category: str = ""
    # CVSS is optional: the agentic vuln loop proposes hypotheses, it does not
    # score them. Left empty/zero unless a stage that scores fills them in.
    cvss_vector: str = ""
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    severity: Severity = "informational"
    confidence: Confidence = "possible"
    rationale: str = ""
    evidence: list[Evidence] = Field(default_factory=list)
    origin_request: dict[str, Any] = Field(default_factory=dict,
        description="The recorded request this hypothesis was raised on (method, "
                    "path, url, content_type, params, body). Carried so the "
                    "Exploitation stage has the exact request without a lookup.")


class VulnerabilityRegister(BaseModel):
    """Ranked weaknesses; feeds MITRE Mapping and Exploitation."""
    weaknesses: list[Weakness] = Field(default_factory=list)
    candidates_dropped: int = Field(default=0,
        description="Model-proposed weaknesses discarded because their asset did "
                    "not exist or their CVSS vector would not parse. Reported "
                    "rather than silently swallowed: a rising count is the "
                    "signal that the prompt or the model has drifted.")


# --------------------------------------------------------------------------- #
# Exploitation → Exploitation Evidence (§5.5)
# --------------------------------------------------------------------------- #

class ExploitAttempt(BaseModel):
    """One proof-of-concept attempt against one weakness.

    ``confirmed`` is set by a deterministic check against ``detection``, never
    by a model reading its own output and deciding it worked. A model asked
    "did that succeed?" is strongly biased toward yes, and this is the field
    that decides whether the client is told a flaw is real.
    """
    weakness_id: str
    confirmed: bool
    payload: str = ""
    detection: str = Field(default="",
        description="The deterministic signal checked for, stated before the "
                    "request was sent.")
    evidence: Evidence | None = None
    reason: str = Field(default="",
        description="Why an attempt did not confirm — blocked, no signal, "
                    "refused by guardrails.")
    hypothesis: str = Field(default="",
        description="The weakness the model was asked to prove — the input claim.")
    proven_vuln: str = Field(default="",
        description="What the model ACTUALLY proved, which is often a different "
                    "class than the hypothesis (e.g. hypothesised LDAP, proved SQLi).")
    signal_basis: str = Field(default="",
        description="How confirmation was reached: a deterministic tool signal "
                    "(sqlmap injectable, http_prove signal_found) or model_judgment. "
                    "Lets the Adviser weight a finding by how hard the proof was.")
    writeup: str = Field(default="",
        description="One or two sentences describing the exploit actually found.")


class ExploitationEvidence(BaseModel):
    """What Exploitation could actually prove.

    A weakness absent from ``attempts`` was never tested; one present but not
    ``confirmed`` was tested and not proven. Those are different statements and
    the report must not collapse them into "not vulnerable".
    """
    attempts: list[ExploitAttempt] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list,
        description="Weakness IDs never attempted, with no claim made about them.")
    loot: list[dict[str, Any]] = Field(default_factory=list,
        description="Interesting data the stage extracted along the way — session "
                    "cookies, credentials, user info, DB type, tokens — each "
                    "{type, value, source} — surfaced to the orchestrator/report. "
                    "Values are stored in FULL: items the model names are kept as "
                    "written, and secrets are also harvested deterministically from "
                    "raw tool output (so a long token is never abbreviated away).")
    transcript: list[dict[str, Any]] = Field(default_factory=list,
        description="The full raw tool I/O of the run — one entry per tool call "
                    "{weakness_id, step, tool, request, response}. This is the "
                    "un-summarised record the chat model queries for exact values "
                    "(full tokens, response bodies) that the human-facing summaries "
                    "necessarily shorten. Per-response text is bounded, not dropped.")

    @property
    def confirmed_ids(self) -> set[str]:
        return {a.weakness_id for a in self.attempts if a.confirmed}


# --------------------------------------------------------------------------- #
# Attack Script Builder → Attack Playbook (§5.6)
# --------------------------------------------------------------------------- #

class AttackScript(BaseModel):
    """A reproduction script for one confirmed weakness.

    Scripts are written only for weaknesses Exploitation actually proved. A
    "reproduction" of something that was never reproduced is not a script, it is
    a guess with syntax highlighting — and it would be handed to a client as
    though someone had run it.
    """
    weakness_id: str
    language: Literal["python", "bash"] = "python"
    source: str
    description: str = ""
    technique_ids: list[str] = Field(default_factory=list)
    remediation_pointer: str = ""
    safety_checked: bool = Field(default=False,
        description="Passed the static safety check. §5.6 requires this before "
                    "a script may ship in the playbook.")
    safety_notes: str = ""


class AttackPlaybook(BaseModel):
    scripts: list[AttackScript] = Field(default_factory=list)
    rejected: int = Field(default=0,
        description="Scripts discarded by the safety check rather than shipped.")


# --------------------------------------------------------------------------- #
# Adviser → Engagement Report (§5.8)
# --------------------------------------------------------------------------- #

class Finding(BaseModel):
    """A weakness promoted to a reportable finding."""
    id: str
    title: str
    asset: str
    severity: Severity
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_vector: str = ""
    confirmed: bool = False
    status: str = Field(default="",
        description="Plain-language state: confirmed, tested but not proven, or "
                    "not tested. Collapsing the last two into 'not vulnerable' "
                    "would misrepresent the engagement.")
    technique_ids: list[str] = Field(default_factory=list)
    owasp_category: str = ""
    recommendation: str = ""
    effort: Literal["low", "medium", "high"] = "medium"
    evidence: list[Evidence] = Field(default_factory=list)


class ExecutiveSummary(BaseModel):
    risk_score: float = Field(ge=0.0, le=10.0,
        description="Highest confirmed severity, or highest unconfirmed if none "
                    "were proven. Never an average — averaging hides the one "
                    "critical finding among a dozen lows.")
    narrative: str
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    confirmed_count: int = 0
    total_findings: int = 0


class EngagementReport(BaseModel):
    """The final deliverable (§5.8)."""
    engagement_id: str
    target_url: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    executive_summary: ExecutiveSummary
    findings: list[Finding] = Field(default_factory=list)
    playbook: AttackPlaybook = Field(default_factory=AttackPlaybook)
    attack_coverage: dict[str, list[str]] = Field(default_factory=dict,
        description="ATT&CK technique ID → the findings that exercised it.")
    exploitation_confirmed: bool = Field(default=True,
        description="False when Exploitation could not run to completion. The "
                    "report must then read 'weaknesses found but not confirmed' "
                    "rather than presenting a confirmed test (§2.2.4).")
    caveats: list[str] = Field(default_factory=list,
        description="Everything limiting how far these results can be trusted. "
                    "Present in every report; an empty list would itself be a "
                    "misleading claim.")
    loot: list[dict[str, Any]] = Field(default_factory=list,
        description="Interesting data collected during exploitation — session "
                    "cookies, credentials, user info, DB type, tokens — each "
                    "{type, value, source}. Deduped from ExploitationEvidence.loot.")


# MITRE ATT&CK technique IDs: T1190, or a sub-technique like T1059.007.
TECHNIQUE_ID_PATTERN = r"^T\d{4}(\.\d{3})?$"


class TechniqueTag(BaseModel):
    """One ATT&CK technique attributed to a weakness.

    ``technique_id`` is pattern-constrained so a malformed identifier is caught
    at parse time. That is a syntax check, not a truth check: it rejects
    ``T99`` and ``TXXXX`` but happily accepts a plausible-looking ID the model
    invented. Confirming an ID actually exists needs the ``attack_validate``
    tool against the STIX bundle — see §9's hallucination risk.
    """
    technique_id: str = Field(pattern=TECHNIQUE_ID_PATTERN)
    technique_name: str = ""
    tactic: str = ""


class AttackMap(BaseModel):
    """The MITRE Mapping agent's artifact: technique tags per weakness.

    §5.4 requires 100% of register entries to carry at least one technique, so
    an empty tag list is a schema violation rather than a tolerated gap — it
    fails here instead of quietly reaching the report as an untagged finding.
    """
    mappings: dict[str, list[TechniqueTag]] = Field(default_factory=dict,
        description="Weakness ID → its ATT&CK technique tags.")

    @field_validator("mappings")
    @classmethod
    def _every_weakness_tagged(
        cls, value: dict[str, list[TechniqueTag]]
    ) -> dict[str, list[TechniqueTag]]:
        untagged = sorted(wid for wid, tags in value.items() if not tags)
        if untagged:
            raise ValueError(
                f"every mapped weakness needs >= 1 technique tag; "
                f"untagged: {', '.join(untagged)}")
        return value
