"""Tests for the ATT&CK mapping stage — now an agentic loop over mcp-native.

The point is not that the model picks good techniques. It is that the worker
trusts nothing it did not confirm: an id only survives if ``attack_technique``
validated it, an id for a weakness that was never in the register is dropped,
and the worker keeps re-running the loop for whatever is still untagged until a
check finds nothing left — or gives up when a pass makes no progress.

The model and the MCP server are both faked here. ``mitre_loop.run_weakness`` is
replaced with a table of canned answers per weakness id; the MCP ``Client`` is a
stub that only needs to answer ``list_tools`` and ``attack_catalog``.
"""
from __future__ import annotations

from uuid import uuid4

import pytest

import mcp
from mcp_native import mitre_loop
from shared.models import Scope

from agent.services.workers.base import WorkContext, WorkFailed
from agent.services.workers.mitre_worker import MitreWorker

REGISTER = {
    "weaknesses": [
        {"id": "W-001", "asset": "/search", "title": "reflected xss"},
        {"id": "W-002", "asset": "/login", "title": "sql injection"},
    ]
}


def ctx(upstream=None) -> WorkContext:
    return WorkContext(
        engagement_id=uuid4(),
        target_url="https://juice-shop.test/",
        scope=Scope(domains=["*.juice-shop.test"]),
        upstream=REGISTER if upstream is None else upstream,
    )


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #

class _Tool:
    def __init__(self, name):
        self.name = name


class _ToolList:
    def __init__(self, names):
        self.tools = [_Tool(n) for n in names]


class _Result:
    def __init__(self, content):
        self.structured_content = content


class FakeClient:
    """The bits of mcp.Client the worker touches: list_tools + attack_catalog."""

    def __init__(self, tool_names=None):
        self._names = tool_names or list(mitre_loop.AGENT_TOOLS)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def list_tools(self):
        return _ToolList(self._names)

    async def call_tool(self, name, args=None):
        if name == "attack_catalog":
            return _Result({"techniques": [
                {"technique_id": "T1190", "name": "Exploit Public-Facing Application"},
                {"technique_id": "T1059.007", "name": "…: JavaScript"},
            ]})
        return _Result({})


def patch(monkeypatch, *, answers, tool_names=None, client=None):
    """Wire the worker to fakes. `answers` maps weakness id -> list of tags."""
    monkeypatch.setattr(mcp, "Client",
                        lambda url: client or FakeClient(tool_names))

    calls: list[str] = []

    async def fake_run_weakness(client, llm, openai_tools, menu, weakness):
        wid = weakness["id"]
        calls.append(wid)
        # each entry in answers[wid] is a list of tags; pop one per pass
        seq = answers.get(wid)
        tags = seq.pop(0) if seq else []
        return tags, "", []

    monkeypatch.setattr(mitre_loop, "run_weakness", fake_run_weakness)
    return calls


def tag(tid="T1190", name="Exploit Public-Facing Application", tactic="Initial Access"):
    return {"technique_id": tid, "technique_name": name, "tactic": tactic}


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #

async def test_maps_every_weakness(monkeypatch):
    patch(monkeypatch, answers={
        "W-001": [[tag("T1059.007", "…: JavaScript", "Execution")]],
        "W-002": [[tag("T1190")]],
    })
    result = await MitreWorker(object())(ctx())
    assert set(result["mappings"]) == {"W-001", "W-002"}
    assert result["mappings"]["W-002"][0]["technique_id"] == "T1190"


async def test_loop_stops_as_soon_as_nothing_is_left(monkeypatch):
    """One good pass tags both — the worker must not start a second pass."""
    calls = patch(monkeypatch, answers={
        "W-001": [[tag("T1059.007", "x", "Execution")]],
        "W-002": [[tag("T1190")]],
    })
    await MitreWorker(object())(ctx())
    assert calls == ["W-001", "W-002"]  # each visited exactly once


async def test_loop_reruns_only_the_untagged_weakness(monkeypatch):
    """W-002 comes back empty on pass 1, tagged on pass 2; W-001 is not retried."""
    calls = patch(monkeypatch, answers={
        "W-001": [[tag("T1059.007", "x", "Execution")], [tag("T9999")]],
        "W-002": [[], [tag("T1190")]],
    })
    result = await MitreWorker(object())(ctx())
    assert set(result["mappings"]) == {"W-001", "W-002"}
    assert calls == ["W-001", "W-002", "W-002"]  # W-001 mapped on pass 1, not re-run


# --------------------------------------------------------------------------- #
# Not trusting the model / the loop
# --------------------------------------------------------------------------- #

async def test_empty_register_needs_no_loop(monkeypatch):
    def explode(url):
        raise AssertionError("must not open an MCP client for an empty register")

    monkeypatch.setattr(mcp, "Client", explode)
    assert await MitreWorker(object())(ctx(upstream={"weaknesses": []})) == {"mappings": {}}


async def test_weakness_the_loop_cannot_tag_fails_the_stage(monkeypatch):
    patch(monkeypatch, answers={
        "W-001": [[tag("T1059.007", "x", "Execution")]],
        "W-002": [[], []],   # never confirmed
    })
    with pytest.raises(WorkFailed, match="W-002"):
        await MitreWorker(object())(ctx())


async def test_missing_attack_tools_fails_the_stage(monkeypatch):
    patch(monkeypatch, answers={}, tool_names=["http_request", "sqlmap"])
    with pytest.raises(WorkFailed, match="ATT&CK tools"):
        await MitreWorker(object())(ctx())


async def test_mcp_server_unreachable_becomes_work_failure(monkeypatch):
    class Boom(FakeClient):
        async def __aenter__(self):
            raise ConnectionError("mcp-native down")

    monkeypatch.setattr(mcp, "Client", lambda url: Boom())
    with pytest.raises(WorkFailed, match="mitre loop failed"):
        await MitreWorker(object())(ctx())


# --------------------------------------------------------------------------- #
# The loop's own trust boundary
# --------------------------------------------------------------------------- #

async def test_validate_keeps_only_confirmed_ids_and_authoritative_names():
    """_validate must drop an unknown id and rewrite name/tactic from the tool."""
    class C:
        async def call_tool(self, name, args):
            tid = args["technique_id"]
            if tid == "T1190":
                return _Result({"found": True, "technique_id": "T1190",
                                "name": "Exploit Public-Facing Application",
                                "tactics": ["Initial Access"]})
            return _Result({"found": False, "did_you_mean": []})

    tags = await mitre_loop._validate(C(), [
        {"technique_id": "T1190", "technique_name": "wrong name", "tactic": "Nonsense"},
        {"technique_id": "T9999", "technique_name": "made up", "tactic": "Execution"},
    ])
    assert tags == [{"technique_id": "T1190",
                     "technique_name": "Exploit Public-Facing Application",
                     "tactic": "Initial Access"}]


def test_parse_tags_reads_the_technique_line_format():
    text = ("TECHNIQUE: T1190 | Exploit Public-Facing Application | Initial Access\n"
            "TECHNIQUE: t1059.007 | …: JavaScript | Execution")
    tags = mitre_loop.parse_tags(text)
    assert [t["technique_id"] for t in tags] == ["T1190", "T1059.007"]
    assert tags[0]["tactic"] == "Initial Access"


def test_parse_tags_falls_back_to_bare_ids():
    tags = mitre_loop.parse_tags("I'd go with T1190 and possibly T1213 here.")
    assert [t["technique_id"] for t in tags] == ["T1190", "T1213"]
