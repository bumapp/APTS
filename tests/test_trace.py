"""Tests for the execution trace recorder.

No database. :func:`shared.trace.record_for` is the single seam that touches
Postgres, so these tests either patch it out (when the subject is context
binding or sequencing) or patch ``get_conn`` beneath it (when the subject is the
write itself). That split keeps every assertion here about behaviour this module
owns rather than about psycopg.

The properties worth pinning are the ones whose failure is silent: a trace that
records nothing because no stage was bound, a truncated field that does not
admit it was truncated, and — the important one — attribution leaking from one
stage into the next.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest

from shared import trace

ENGAGEMENT = uuid4()


@pytest.fixture
def recorded(monkeypatch):
    """Capture what would have been written, without a database."""
    rows: list[dict] = []

    def fake_record_for(engagement_id, agent, event_type, payload=None,
                        duration_ms=None, seq=0):
        rows.append({"engagement_id": str(engagement_id), "agent": agent,
                     "event_type": event_type, "payload": payload or {},
                     "duration_ms": duration_ms, "seq": seq})

    monkeypatch.setattr(trace, "record_for", fake_record_for)
    return rows


# --------------------------------------------------------------------------- #
# Truncation
# --------------------------------------------------------------------------- #

def test_short_string_is_untouched():
    assert trace.cap("a prompt") == "a prompt"


def test_long_string_states_its_original_length():
    """A clipped field must admit it was clipped, and by how much.

    A silently truncated prompt is worse than an absent one: it reads as the
    whole prompt, and a reader debugging a bad model reply would conclude the
    model saw less than it did.
    """
    original = "x" * (trace.MAX_FIELD_CHARS + 500)
    capped = trace.cap(original)

    assert len(capped) < len(original)
    assert capped.startswith("x" * 100)
    assert f"{trace.MAX_FIELD_CHARS + 500} chars total" in capped
    assert "truncated" in capped


def test_long_list_keeps_a_bounded_head_and_says_so():
    capped = trace.cap(list(range(trace.MAX_ITEMS + 40)))

    assert len(capped) == trace.MAX_ITEMS + 1
    assert capped[:3] == [0, 1, 2]
    assert f"{trace.MAX_ITEMS + 40} items total" in capped[-1]


def test_nested_structures_are_capped_at_every_level():
    capped = trace.cap({"endpoints": [{"body": "y" * 20_000}]})
    assert "truncated" in capped["endpoints"][0]["body"]


def test_keys_are_never_dropped():
    """A missing key would read as "the stage did not set it"."""
    capped = trace.cap({"a": "1", "b": "2", "c": None, "d": False})
    assert sorted(capped) == ["a", "b", "c", "d"]
    assert capped["c"] is None and capped["d"] is False


def test_runaway_nesting_is_summarised_not_walked():
    deep: dict = {"leaf": 1}
    for _ in range(trace.MAX_DEPTH + 4):
        deep = {"down": deep}
    assert "depth limit" in repr(trace.cap(deep))


def test_uuid_and_datetime_survive_as_strings():
    """Both appear in artifacts and neither is JSON-serialisable by psycopg."""
    engagement = uuid4()
    capped = trace.cap({"id": engagement, "at": datetime(2026, 8, 7, 12, 30)})
    assert capped["id"] == str(engagement)
    assert capped["at"].startswith("2026-08-07")


def test_unknown_types_degrade_to_their_repr():
    class Odd:
        def __str__(self):
            return "odd-value"

    assert trace.cap(Odd()) == "odd-value"


# --------------------------------------------------------------------------- #
# Context binding
# --------------------------------------------------------------------------- #

def test_record_outside_a_stage_is_a_no_op(recorded):
    """Shared code calls record() unconditionally; outside a run it must not write.

    This is what lets ``LlmClient`` and ``McpService`` record themselves without
    every caller knowing whether it is inside an engagement.
    """
    trace.record("llm_call", {"model": "x"})
    assert recorded == []


def test_record_inside_a_stage_is_attributed_to_it(recorded):
    with trace.stage(ENGAGEMENT, "vuln"):
        trace.record("llm_call", {"model": "x"}, duration_ms=1200)

    assert len(recorded) == 1
    row = recorded[0]
    assert row["agent"] == "vuln"
    assert row["engagement_id"] == str(ENGAGEMENT)
    assert row["event_type"] == "llm_call"
    assert row["duration_ms"] == 1200


def test_events_are_numbered_in_call_order(recorded):
    with trace.stage(ENGAGEMENT, "recon"):
        trace.record("stage_input")
        trace.record("tool_call")
        trace.record("stage_output")

    assert [r["seq"] for r in recorded] == [1, 2, 3]
    assert [r["event_type"] for r in recorded] == [
        "stage_input", "tool_call", "stage_output"]


def test_binding_is_released_on_exit(recorded):
    with trace.stage(ENGAGEMENT, "recon"):
        pass
    trace.record("llm_call")
    assert recorded == []
    assert trace.current_agent() is None


def test_binding_is_released_even_when_the_stage_raises(recorded):
    """A failed stage must not leave its attribution behind.

    Without the ``finally`` reset, the next run on this task would record its
    events against the stage that crashed.
    """
    with pytest.raises(ValueError):
        with trace.stage(ENGAGEMENT, "exploit"):
            raise ValueError("stage blew up")

    assert trace.current_agent() is None
    trace.record("llm_call")
    assert recorded == []


def test_nested_stages_restore_the_outer_binding(recorded):
    with trace.stage(ENGAGEMENT, "outer"):
        with trace.stage(ENGAGEMENT, "inner"):
            trace.record("stage_input")
        trace.record("stage_output")

    assert [r["agent"] for r in recorded] == ["inner", "outer"]


async def test_concurrent_stages_do_not_see_each_other(recorded):
    """One process runs many engagements; contextvars is why they stay separate.

    asyncio copies the context when a task is created, so two stage runs
    interleaving in the same event loop cannot cross-contaminate. A
    module-level global would — and the symptom would be one engagement's
    prompts filed under another's flow file.

    The ``sleep(0)`` between binding and recording is the point: it forces the
    two tasks to interleave, so a shared binding would be observably wrong
    rather than accidentally correct.
    """
    import asyncio

    async def one(engagement, agent):
        with trace.stage(engagement, agent):
            await asyncio.sleep(0)
            trace.record("stage_output")

    a, b = uuid4(), uuid4()
    await asyncio.gather(one(a, "recon"), one(b, "vuln"))

    by_agent = {r["agent"]: r["engagement_id"] for r in recorded}
    assert by_agent == {"recon": str(a), "vuln": str(b)}


def test_current_agent_reports_the_bound_stage():
    with trace.stage(ENGAGEMENT, "mitre"):
        assert trace.current_agent() == "mitre"


# --------------------------------------------------------------------------- #
# The write itself
# --------------------------------------------------------------------------- #

class FakeCursor:
    def __init__(self, calls):
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params):
        self._calls.append((sql, params))


class FakeConn:
    def __init__(self, calls):
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def cursor(self):
        return FakeCursor(self._calls)


@pytest.fixture
def executed(monkeypatch):
    calls: list = []
    monkeypatch.setattr(trace, "get_conn", lambda: FakeConn(calls))
    return calls


def test_record_for_inserts_one_row(executed):
    trace.record_for(ENGAGEMENT, "orchestrator", "engagement_requested",
                     {"target_url": "https://target.test/"}, seq=0)

    assert len(executed) == 1
    sql, params = executed[0]
    assert "INSERT INTO agent_trace" in sql
    assert params[0] == str(ENGAGEMENT)
    assert params[1] == "orchestrator"
    assert params[3] == "engagement_requested"


def test_payload_is_capped_on_the_way_in(executed):
    """Truncation happens at the write, so no caller can bypass it."""
    trace.record_for(ENGAGEMENT, "recon", "tool_call", {"body": "z" * 50_000})

    _, params = executed[0]
    assert "truncated" in params[4].obj["body"]


def test_a_write_failure_never_propagates(monkeypatch):
    """Losing an observability row must not fail a stage that did its work."""
    def exploding_conn():
        raise RuntimeError("database is down")

    monkeypatch.setattr(trace, "get_conn", exploding_conn)
    trace.record_for(ENGAGEMENT, "recon", "stage_output")  # must not raise


def test_disabling_tracing_writes_nothing(executed, monkeypatch):
    monkeypatch.setattr(trace, "ENABLED", False)
    trace.record_for(ENGAGEMENT, "recon", "stage_output")
    assert executed == []
