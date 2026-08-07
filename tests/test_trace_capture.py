"""Tests that the instrumented layers record what the flow file needs.

Separate from ``test_trace.py``, which tests the recorder in isolation. These
tests are about the call sites: an ``llm_call`` row that omits the prompt, or a
``tool_call`` row that omits the arguments, leaves the flow file unable to
answer the question it exists to answer, and nothing else in the suite would
notice.

Every test binds a stage and captures ``record_for``, so no database is touched.
"""
from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest

from shared import trace
from shared.llm import LlmClient, LlmError
from shared.models import Scope

from agent.services.mcp_service import McpService, ToolCallFailed

from tests.test_llm import completion, stub_client

ENGAGEMENT = uuid4()
SCOPE = Scope(domains=["*.target.test"])


@pytest.fixture
def rows(monkeypatch):
    """Capture trace writes as plain dicts."""
    captured: list[dict] = []

    def fake_record_for(engagement_id, agent, event_type, payload=None,
                        duration_ms=None, seq=0):
        captured.append({"agent": agent, "event_type": event_type,
                         "payload": payload or {}, "duration_ms": duration_ms,
                         "seq": seq})

    monkeypatch.setattr(trace, "record_for", fake_record_for)
    return captured


def only(rows: list[dict], event_type: str) -> dict:
    matches = [r for r in rows if r["event_type"] == event_type]
    assert len(matches) == 1, f"expected one {event_type}, got {len(matches)}"
    return matches[0]


# --------------------------------------------------------------------------- #
# LLM calls
# --------------------------------------------------------------------------- #

async def test_llm_call_records_both_prompts_and_the_raw_reply(rows):
    """The raw string, not the parsed object.

    When a stage fails on malformed output the parsed object is precisely the
    thing that does not exist — the raw reply is the only evidence of what the
    model actually said.
    """
    reply = '{"candidates": []}'
    with trace.stage(ENGAGEMENT, "vuln"):
        async with LlmClient("vuln", client=stub_client(completion(reply)),
                             api_key="k") as llm:
            await llm.complete_json("SYSTEM SCHEMA HERE", "the asset map")

    payload = only(rows, "llm_call")["payload"]
    assert payload["system_prompt"] == "SYSTEM SCHEMA HERE"
    assert payload["user_prompt"] == "the asset map"
    assert payload["raw_response"] == reply
    assert payload["attempt"] == 1


async def test_llm_call_records_token_usage_including_reasoning(rows):
    """Reasoning tokens are billed as output but reported separately.

    Folding them into the completion count would make a thinking model's true
    cost invisible in the flow file's usage table.
    """
    with trace.stage(ENGAGEMENT, "mitre"):
        async with LlmClient("mitre",
                             client=stub_client(completion("{}", reasoning_tokens=880)),
                             api_key="k") as llm:
            await llm.complete_json("s", "u")

    usage = only(rows, "llm_call")["payload"]["usage"]
    assert usage == {"prompt_tokens": 100, "completion_tokens": 50,
                     "reasoning_tokens": 880, "cached_tokens": 0}


async def test_every_retry_is_recorded_separately(rows):
    """Two attempts, two rows — a retry that vanishes hides why a stage was slow."""
    with trace.stage(ENGAGEMENT, "mitre"):
        async with LlmClient(
            "mitre",
            client=stub_client(completion("not json"), completion('{"ok": true}')),
            api_key="k",
        ) as llm:
            await llm.complete_json("s", "u")

    calls = [r for r in rows if r["event_type"] == "llm_call"]
    assert [c["payload"]["attempt"] for c in calls] == [1, 2]
    assert calls[0]["payload"]["raw_response"] == "not json"


async def test_an_unreachable_model_still_leaves_a_row(rows):
    """A stage that failed because the provider was down must show the attempt.

    Otherwise the flow file jumps from ``stage_input`` to ``stage_failed`` with
    nothing in between, which reads as a crash before any work was tried.
    """
    with trace.stage(ENGAGEMENT, "mitre"):
        async with LlmClient("mitre",
                             client=stub_client(completion("{}", status=500)),
                             api_key="k") as llm:
            with pytest.raises(LlmError):
                await llm.complete_json("s", "u")

    payload = only(rows, "llm_call")["payload"]
    assert "HTTP 500" in payload["error"]
    assert payload["raw_response"] == ""


async def test_llm_calls_outside_a_stage_record_nothing(rows):
    """Unit tests and health probes must not write trace rows."""
    async with LlmClient("mitre", client=stub_client(completion("{}")),
                         api_key="k") as llm:
        await llm.complete_json("s", "u")
    assert rows == []


# --------------------------------------------------------------------------- #
# Tool calls
# --------------------------------------------------------------------------- #

def tool_client(body: dict, status: int = 200) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=body)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_tool_call_records_arguments_and_output(rows):
    """mcp-tools audits that a call happened; only this row says what it fetched."""
    mcp = McpService(
        tool_client({"tool": "http", "ok": True,
                     "output": {"status_code": 200, "body": "<html>hello</html>"}}),
        token="t")

    with trace.stage(ENGAGEMENT, "vuln"):
        await mcp.call("http", ENGAGEMENT, url="https://target.test/login",
                       method="GET")

    payload = only(rows, "tool_call")["payload"]
    assert payload["tool"] == "http"
    assert payload["args"] == {"url": "https://target.test/login", "method": "GET"}
    assert payload["output"]["status_code"] == 200
    assert payload["ok"] is True
    assert payload["blocked"] is False


async def test_a_guardrails_block_records_the_reason_not_an_output(rows):
    """A blocked call is normal behaviour, and the reason is the interesting part."""
    mcp = McpService(
        tool_client({"tool": "http", "ok": False, "blocked_by_guardrails": True,
                     "reason": "host evil.test is out of scope"}),
        token="t")

    with trace.stage(ENGAGEMENT, "recon"):
        outcome = await mcp.call("http", ENGAGEMENT, url="https://evil.test/")

    assert outcome.blocked
    payload = only(rows, "tool_call")["payload"]
    assert payload["blocked"] is True
    assert "out of scope" in payload["reason"]
    assert "output" not in payload


async def test_a_failed_tool_call_records_the_error(rows):
    mcp = McpService(tool_client({"detail": "nope"}, status=403), token="t")

    with trace.stage(ENGAGEMENT, "recon"):
        with pytest.raises(ToolCallFailed):
            await mcp.call("sandbox", ENGAGEMENT, command="curl https://target.test/")

    payload = only(rows, "tool_call")["payload"]
    assert "refused" in payload["error"]
    assert payload["args"] == {"command": "curl https://target.test/"}


async def test_tool_call_duration_is_recorded(rows):
    mcp = McpService(tool_client({"tool": "http", "ok": True, "output": {}}),
                     token="t")
    with trace.stage(ENGAGEMENT, "recon"):
        await mcp.call("http", ENGAGEMENT, url="https://target.test/")

    assert only(rows, "tool_call")["duration_ms"] >= 0


async def test_a_tool_call_still_returns_its_outcome_when_tracing_is_off(rows, monkeypatch):
    """Instrumentation must not change what the worker sees."""
    monkeypatch.setattr(trace, "ENABLED", False)
    mcp = McpService(
        tool_client({"tool": "http", "ok": True, "output": {"status_code": 204}}),
        token="t")

    with trace.stage(ENGAGEMENT, "recon"):
        outcome = await mcp.call("http", ENGAGEMENT, url="https://target.test/")

    assert outcome.ok and outcome.output == {"status_code": 204}


# --------------------------------------------------------------------------- #
# Stage-level events, via the provider
# --------------------------------------------------------------------------- #

class FakeOrchestrator:
    def __init__(self):
        self.reports = []

    async def report(self, engagement_id, status, message="", detail=None):
        self.reports.append(status)


class FakeHandoff:
    def __init__(self):
        self.pushed = []

    async def push(self, next_agent, engagement_id, target_url, scope,
                   time_window, result):
        self.pushed.append(next_agent)


class FakeResults:
    def __init__(self):
        self.saved = {}

    def save(self, engagement_id, agent, payload):
        self.saved[agent] = payload


class FakeAudit:
    """In-memory ``AuditSink``. The component is bound by the real one, not passed."""

    def __init__(self):
        self.events = []

    def record(self, event_type, engagement_id=None, detail=None):
        self.events.append(event_type)


def build_provider(agent: str, worker, **kwargs):
    from agent.providers.run_provider import RunProvider
    return RunProvider(
        agent=agent, worker=worker,
        orchestrator=kwargs.get("orchestrator") or FakeOrchestrator(),
        handoff=kwargs.get("handoff") or FakeHandoff(),
        results=kwargs.get("results") or FakeResults(),
        audit=kwargs.get("audit") or FakeAudit(),
        traces=kwargs.get("traces"), flows=kwargs.get("flows"),
    )


def handoff_for(agent_from: str = "orchestrator", upstream: dict | None = None):
    from shared.models import ChainHandoff
    return ChainHandoff(
        engagement_id=ENGAGEMENT, from_component=agent_from,
        target_url="https://target.test/", scope=SCOPE, time_window=None,
        results=upstream if upstream is not None else {},
    )


async def test_stage_input_records_what_the_stage_was_handed(rows):
    async def worker(ctx):
        return {"weaknesses": []}

    upstream = {"endpoints": [{"path": "/login", "status": 200}]}
    provider = build_provider("vuln", worker)
    await provider.run(handoff_for("agent-recon", upstream))

    payload = only(rows, "stage_input")["payload"]
    assert payload["from_component"] == "agent-recon"
    assert payload["target_url"] == "https://target.test/"
    assert payload["upstream"] == upstream
    assert payload["upstream_keys"] == ["endpoints"]
    assert payload["upstream_bytes"] == len(json.dumps(upstream))
    assert payload["scope"]["domains"] == ["*.target.test"]


async def test_stage_output_records_the_artifact_and_a_summary(rows):
    artifact = {"weaknesses": [{"id": "W-001"}, {"id": "W-002"}],
                "candidates_dropped": 3}

    async def worker(ctx):
        return artifact

    provider = build_provider("vuln", worker)
    await provider.run(handoff_for())

    payload = only(rows, "stage_output")["payload"]
    assert payload["artifact"] == artifact
    assert "2 weaknesses" in payload["summary"]


async def test_handoff_is_recorded_with_the_successor(rows):
    async def worker(ctx):
        return {}

    provider = build_provider("recon", worker)
    await provider.run(handoff_for())

    assert only(rows, "handoff")["payload"]["next_agent"] == "vuln"


async def test_a_failed_stage_records_the_error_and_a_traceback(rows):
    async def worker(ctx):
        raise RuntimeError("model returned no candidates list")

    orchestrator = FakeOrchestrator()
    provider = build_provider("vuln", worker, orchestrator=orchestrator)
    await provider.run(handoff_for())

    payload = only(rows, "stage_failed")["payload"]
    assert payload["error"] == "model returned no candidates list"
    assert payload["type"] == "RuntimeError"
    assert "RuntimeError" in payload["traceback"]
    # Still reported to the orchestrator — tracing must not swallow the failure.
    assert orchestrator.reports == ["started", "failed"]


async def test_every_stage_event_is_attributed_to_this_agent(rows):
    async def worker(ctx):
        return {"scripts": []}

    provider = build_provider("script", worker)
    await provider.run(handoff_for())

    assert {r["agent"] for r in rows} == {"script"}
    assert [r["seq"] for r in rows] == list(range(1, len(rows) + 1))


# --------------------------------------------------------------------------- #
# The flow file
# --------------------------------------------------------------------------- #

class FakeTraces:
    def __init__(self, events=()):
        self.events = list(events)
        self.loaded = []

    def load(self, engagement_id):
        self.loaded.append(engagement_id)
        return self.events


class FakeFlows:
    def __init__(self):
        self.saved = []

    def save(self, engagement_id, events):
        self.saved.append((engagement_id, events))
        return [f"/var/apts/reports/flow-{engagement_id}.md"]


async def test_the_terminal_stage_writes_the_flow_file(rows):
    async def worker(ctx):
        return {"findings": []}

    traces, flows = FakeTraces(), FakeFlows()
    provider = build_provider("adviser", worker, traces=traces, flows=flows)
    await provider.run(handoff_for())

    assert traces.loaded == [ENGAGEMENT]
    assert len(flows.saved) == 1


async def test_non_terminal_stages_do_not_write_a_flow_file(rows):
    """Six agents writing the same file would each produce a partial one."""
    async def worker(ctx):
        return {}

    traces, flows = FakeTraces(), FakeFlows()
    provider = build_provider("recon", worker, traces=traces, flows=flows)
    await provider.run(handoff_for())

    assert traces.loaded == [] and flows.saved == []


async def test_a_flow_file_failure_does_not_fail_the_engagement(rows):
    """Reached only after every stage succeeded; it must not undo that.

    A raise here would be reported as an Adviser failure and retried, which
    would regenerate the whole report to fix an observability write.
    """
    async def worker(ctx):
        return {"findings": []}

    class ExplodingFlows:
        def save(self, engagement_id, events):
            raise OSError("read-only filesystem")

    orchestrator = FakeOrchestrator()
    provider = build_provider("adviser", worker, orchestrator=orchestrator,
                              traces=FakeTraces(), flows=ExplodingFlows())
    await provider.run(handoff_for())

    assert orchestrator.reports == ["started", "done"]


async def test_the_flow_file_is_written_before_done_is_reported(rows):
    """An operator who sees "complete" should find the file already on disk."""
    order: list[str] = []

    async def worker(ctx):
        return {}

    class RecordingOrchestrator(FakeOrchestrator):
        async def report(self, engagement_id, status, message="", detail=None):
            order.append(f"report:{status}")
            await super().report(engagement_id, status, message, detail)

    class RecordingFlows(FakeFlows):
        def save(self, engagement_id, events):
            order.append("flow_written")
            return super().save(engagement_id, events)

    provider = build_provider("adviser", worker,
                              orchestrator=RecordingOrchestrator(),
                              traces=FakeTraces(), flows=RecordingFlows())
    await provider.run(handoff_for())

    assert order == ["report:started", "flow_written", "report:done"]
