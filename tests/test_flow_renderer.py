"""Tests for the flow file — the rendered execution trace.

The renderer's job is to stay faithful to the trace while being readable. The
assertions that matter are therefore about *not losing things*: every event
reaching the timeline, prompts surviving into the document, a blocked tool call
reading as blocked rather than as a success, and token totals adding up. A flow
file that quietly omits a stage is worse than no flow file, because it is the
artifact someone consults when they already distrust the report.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from uuid import uuid4

from agent.repositories.flow_repository import FlowRepository
from agent.repositories.trace_repository import TraceEvent
from agent.services.flow_renderer import render_markdown

ENGAGEMENT = uuid4()
START = datetime(2026, 8, 7, 9, 0, 0)


def event(agent: str, event_type: str, payload: dict | None = None,
          offset: float = 0.0, duration_ms: int | None = None,
          seq: int = 1) -> TraceEvent:
    return TraceEvent(agent=agent, seq=seq, event_type=event_type,
                      payload=payload or {}, duration_ms=duration_ms,
                      logged_at=START + timedelta(seconds=offset))


def a_full_run() -> list[TraceEvent]:
    """A miniature but complete engagement: request → report."""
    return [
        event("orchestrator", "engagement_requested", {
            "target_url": "https://target.test/",
            "scope": {"domains": ["*.target.test"], "deny_paths": ["/admin/"]},
            "chain": ["recon", "vuln", "adviser"]}, offset=0),
        event("orchestrator", "kickoff", {"agent": "recon"}, offset=0.1),
        event("recon", "stage_input", {
            "from_component": "orchestrator", "target_url": "https://target.test/",
            "scope": {"domains": ["*.target.test"]}, "upstream": {},
            "upstream_keys": [], "upstream_bytes": 2}, offset=0.2),
        event("recon", "tool_call", {
            "tool": "crawl", "args": {"url": "https://target.test/"}, "ok": True,
            "blocked": False, "output": {"pages": [{"path": "/"}, {"path": "/login"}]}},
            offset=0.5, duration_ms=2400),
        event("recon", "tool_call", {
            "tool": "http", "args": {"url": "https://evil.test/"}, "ok": False,
            "blocked": True, "reason": "host evil.test is out of scope"},
            offset=3.0, duration_ms=40),
        event("recon", "stage_output", {
            "artifact": {"endpoints": [{"path": "/"}, {"path": "/login"}]},
            "summary": "2 endpoints"}, offset=3.1, duration_ms=3100),
        event("recon", "handoff", {"next_agent": "vuln"}, offset=3.2),
        event("vuln", "stage_input", {
            "from_component": "agent-recon", "target_url": "https://target.test/",
            "scope": {"domains": ["*.target.test"]},
            "upstream": {"endpoints": [{"path": "/login"}]},
            "upstream_keys": ["endpoints"], "upstream_bytes": 30}, offset=3.3),
        event("vuln", "llm_call", {
            "model": "deepseek-v4-flash", "attempt": 1,
            "system_prompt": "PROPOSE CANDIDATE WEAKNESSES",
            "user_prompt": "Pages observed: /login",
            "raw_response": '{"candidates": [{"asset": "/login"}]}',
            "usage": {"prompt_tokens": 900, "completion_tokens": 120,
                      "reasoning_tokens": 0, "cached_tokens": 64}},
            offset=4.0, duration_ms=5200),
        event("vuln", "stage_output", {
            "artifact": {"weaknesses": [{"id": "W-001"}]},
            "summary": "1 weaknesses"}, offset=9.5, duration_ms=6200),
        event("adviser", "llm_call", {
            "model": "deepseek-v4-flash", "attempt": 1,
            "system_prompt": "WRITE REMEDIATION", "user_prompt": "W-001: ...",
            "raw_response": '{"recommendations": {}}',
            "usage": {"prompt_tokens": 300, "completion_tokens": 400,
                      "reasoning_tokens": 150, "cached_tokens": 0}},
            offset=10.0, duration_ms=3000),
        event("adviser", "report_written", {
            "paths": ["/var/apts/reports/report-x.md"], "findings": 1,
            "confirmed": 0, "risk_score": 6.1}, offset=13.5),
        event("orchestrator", "engagement_complete", {}, offset=13.6),
    ]


# --------------------------------------------------------------------------- #
# Shape
# --------------------------------------------------------------------------- #

def test_an_empty_trace_says_why_rather_than_rendering_a_blank_page():
    """A blank flow file reads as "nothing happened", which is never the case."""
    out = render_markdown(str(ENGAGEMENT), [])
    assert "No trace events were recorded" in out
    assert "APTS_TRACE_ENABLED=0" in out
    assert "init_db.sql" in out


def test_the_header_carries_the_engagement_and_wall_clock():
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    assert str(ENGAGEMENT) in out
    assert "13.6s" in out
    assert "**Events:** 13" in out


def test_every_event_reaches_the_timeline():
    """One row per event. A dropped row is a lost step in the flow."""
    events = a_full_run()
    out = render_markdown(str(ENGAGEMENT), events)
    timeline = out.split("## Timeline")[1].split("## Model usage")[0]

    # Two header rows plus one row per event.
    assert len([ln for ln in timeline.splitlines() if ln.startswith("|")]) == \
        len(events) + 2


def test_elapsed_time_is_relative_to_the_first_event():
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    assert "+   0.0s" in out
    assert "+  13.6s" in out


def test_stage_sections_appear_in_the_order_the_agents_first_ran():
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    detail = out.split("## Stage detail")[1]
    positions = [detail.index(f"### {a}")
                 for a in ("orchestrator", "recon", "vuln", "adviser")]
    assert positions == sorted(positions)


# --------------------------------------------------------------------------- #
# Fidelity — the reason the file exists
# --------------------------------------------------------------------------- #

def test_prompts_and_raw_replies_survive_into_the_document():
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    assert "PROPOSE CANDIDATE WEAKNESSES" in out
    assert "Pages observed: /login" in out
    assert '{"candidates": [{"asset": "/login"}]}' in out


def test_long_prompts_are_collapsed_not_inlined():
    """Collapsed, because a hundred kilobytes of prompt would bury the structure."""
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    assert "<summary>system prompt</summary>" in out
    assert "<summary>user prompt</summary>" in out
    assert "<summary>raw response</summary>" in out


def test_tool_arguments_and_output_are_both_present():
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    assert "https://target.test/" in out
    assert "<summary>arguments</summary>" in out
    assert "<summary>output</summary>" in out


def test_a_blocked_tool_call_never_reads_as_a_success():
    """The single most misleading thing this file could do."""
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    assert "BLOCKED" in out
    assert "host evil.test is out of scope" in out


def test_a_failed_stage_shows_its_error_and_traceback():
    events = [event("vuln", "stage_failed", {
        "error": "model returned no candidates list", "type": "WorkFailed",
        "traceback": "Traceback (most recent call last):\n  WorkFailed"})]
    out = render_markdown(str(ENGAGEMENT), events)
    assert "model returned no candidates list" in out
    assert "Traceback (most recent call last)" in out


def test_a_failed_model_call_is_marked_failed_in_the_timeline():
    events = [event("mitre", "llm_call", {
        "model": "deepseek-v4-flash", "attempt": 1, "system_prompt": "s",
        "user_prompt": "u", "raw_response": "",
        "error": "LLM returned HTTP 500", "usage": {}})]
    out = render_markdown(str(ENGAGEMENT), events)
    assert "FAILED" in out
    assert "HTTP 500" in out


def test_a_retry_is_visible_as_its_own_event():
    events = [event("orchestrator", "retry_launched", {
        "agent": "vuln", "attempt": 2, "reason": "assessment call failed",
        "replayed_from": "recon"})]
    out = render_markdown(str(ENGAGEMENT), events)
    assert "retry_launched" in out
    assert "attempt 2" in out


def test_the_report_paths_are_recorded():
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    assert "/var/apts/reports/report-x.md" in out


# --------------------------------------------------------------------------- #
# Model usage
# --------------------------------------------------------------------------- #

def test_usage_is_summed_per_agent_and_in_total():
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    usage = out.split("## Model usage")[1].split("## Stage detail")[0]

    assert "| vuln | 1 | 900 | 120 | 0 |" in usage
    assert "| adviser | 1 | 300 | 400 | 150 |" in usage
    # 900+300 prompt, 120+400 completion, 0+150 reasoning.
    assert "**1200**" in usage and "**520**" in usage and "**150**" in usage


def test_a_run_with_no_model_calls_says_so():
    """Recon is tool-backed by design; "0" in a table would look like a fault."""
    out = render_markdown(str(ENGAGEMENT), [event("recon", "stage_output", {})])
    assert "No model calls were made" in out


def test_reasoning_tokens_are_broken_out_not_folded_in():
    """Folded in, an agent whose cost is mostly hidden reasoning looks cheap."""
    out = render_markdown(str(ENGAGEMENT), a_full_run())
    assert "Reasoning" in out
    assert "| adviser | 1 | 300 | 400 | 150 |" in out


def test_display_clipping_states_the_full_length():
    """The trace row is already capped; this is the tighter display bound."""
    events = [event("recon", "tool_call", {
        "tool": "http", "args": {"url": "https://target.test/"}, "ok": True,
        "blocked": False, "output": {"body": "q" * 7000}})]
    out = render_markdown(str(ENGAGEMENT), events)
    assert "clipped for display" in out
    assert "chars in trace" in out


# --------------------------------------------------------------------------- #
# Writing the files
# --------------------------------------------------------------------------- #

def test_both_formats_are_written(tmp_path):
    paths = FlowRepository(str(tmp_path)).save(ENGAGEMENT, a_full_run())

    assert len(paths) == 2
    assert (tmp_path / f"flow-{ENGAGEMENT}.md").exists()
    assert (tmp_path / f"flow-{ENGAGEMENT}.json").exists()


def test_the_json_form_holds_the_raw_events_not_the_prose(tmp_path):
    """Anything the renderer chooses not to show stays recoverable from the file."""
    FlowRepository(str(tmp_path)).save(ENGAGEMENT, a_full_run())
    payload = json.loads((tmp_path / f"flow-{ENGAGEMENT}.json").read_text())

    assert payload["engagement_id"] == str(ENGAGEMENT)
    assert payload["event_count"] == 13
    assert payload["events"][0]["event_type"] == "engagement_requested"
    llm = next(e for e in payload["events"] if e["event_type"] == "llm_call")
    assert llm["payload"]["system_prompt"] == "PROPOSE CANDIDATE WEAKNESSES"
    assert llm["duration_ms"] == 5200


def test_the_filename_carries_the_engagement_id(tmp_path):
    """Concurrent engagements must not overwrite each other's flow file."""
    other = uuid4()
    FlowRepository(str(tmp_path)).save(ENGAGEMENT, a_full_run())
    FlowRepository(str(tmp_path)).save(other, a_full_run())

    assert {p.name for p in tmp_path.glob("flow-*.md")} == {
        f"flow-{ENGAGEMENT}.md", f"flow-{other}.md"}


def test_an_unwritable_directory_is_reported_not_raised(tmp_path):
    """The trace is safe in the database; a finished run must not fail here."""
    blocker = tmp_path / "wall"
    blocker.write_text("not a directory")

    assert FlowRepository(str(blocker / "reports")).save(ENGAGEMENT, []) == []


def test_the_directory_is_created_if_absent(tmp_path):
    target = tmp_path / "nested" / "reports"
    assert FlowRepository(str(target)).save(ENGAGEMENT, a_full_run())
    assert target.is_dir()
