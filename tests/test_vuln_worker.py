"""Vulnerability Assessment tests.

Every test here feeds the worker output a real model plausibly produces, and
checks that the worker refuses to launder it into a finding. That is the whole
job of this stage's guard rails: an invented vulnerability reaches the client's
report, so the model gets no benefit of the doubt anywhere.
"""
from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest

from shared.llm import LlmClient
from shared.models import Scope

from agent.services.mcp_service import McpService, ToolOutcome
from agent.services.workers.base import WorkContext, WorkFailed
from agent.services.workers.vuln_worker import VulnWorker

ASSET_MAP = {
    "target_url": "http://target.test",
    "endpoints": [{"path": "/", "status": 200, "content_type": "text/html"}],
    "forms": [{"page": "/login", "method": "POST",
               "fields": [{"name": "email"}, {"name": "password"}]}],
    "api_paths": ["/rest/user/login", "/api/Users"],
    "technologies": [{"name": "nginx/1.25"}],
    "third_party": [],
}

GOOD_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"   # 9.8


def ctx(upstream=None) -> WorkContext:
    return WorkContext(
        engagement_id=uuid4(), target_url="http://target.test",
        scope=Scope(domains=["target.test"]),
        upstream=ASSET_MAP if upstream is None else upstream)


def llm_proposing(*candidates) -> LlmClient:
    payload = json.dumps({"candidates": list(candidates)})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": payload}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10}})

    return LlmClient("vuln", client=httpx.AsyncClient(
        transport=httpx.MockTransport(handler)), api_key="k")


class FakeMcp(McpService):
    """Answers http probes from a status map; records what was probed."""

    def __init__(self, statuses: dict[str, int] | None = None,
                 default: int = 200) -> None:
        self.statuses = statuses or {}
        self.default = default
        self.probed: list[str] = []

    async def call(self, tool, engagement_id, **args):
        url = args.get("url", "")
        self.probed.append(url)
        status = next((s for path, s in self.statuses.items() if url.endswith(path)),
                      self.default)
        if status == 0:
            return ToolOutcome(ok=False, output={"error": "connection refused"})
        return ToolOutcome(ok=True, output={
            "status_code": status, "headers": {"content-type": "application/json"},
            "body": '{"data":[]}'})


def candidate(asset="/rest/user/login", vector=GOOD_VECTOR, **over):
    base = {"title": "SQL injection in login", "asset": asset,
            "owasp_category": "A03:2021 Injection", "cvss_vector": vector,
            "rationale": "unescaped credential handling"}
    base.update(over)
    return base


# --------------------------------------------------------------------------- #

async def test_scores_from_the_vector_not_the_model():
    """The model supplies a vector; the score is arithmetic on it."""
    mcp = FakeMcp()
    async with (llm := llm_proposing(candidate())):
        result = await VulnWorker(llm, mcp)(ctx())

    weakness = result["weaknesses"][0]
    assert weakness["cvss_score"] == 9.8
    assert weakness["severity"] == "critical"
    assert weakness["id"] == "W-001"


async def test_model_supplied_score_is_ignored_entirely():
    """A model that volunteers 'cvss_score': 1.0 must not influence anything."""
    async with (llm := llm_proposing(candidate(cvss_score=1.0, severity="low"))):
        result = await VulnWorker(llm, FakeMcp())(ctx())

    assert result["weaknesses"][0]["cvss_score"] == 9.8


async def test_evidence_is_attached_from_a_real_probe():
    mcp = FakeMcp()
    async with (llm := llm_proposing(candidate())):
        result = await VulnWorker(llm, mcp)(ctx())

    evidence = result["weaknesses"][0]["evidence"][0]
    assert evidence["request"] == "GET http://target.test/rest/user/login"
    assert "HTTP 200" in evidence["response"]
    assert mcp.probed == ["http://target.test/rest/user/login"]


async def test_nothing_is_ever_marked_confirmed():
    """Only Exploitation may confirm. A reachable asset is 'probable' at most."""
    async with (llm := llm_proposing(candidate())):
        result = await VulnWorker(llm, FakeMcp())(ctx())

    assert result["weaknesses"][0]["confidence"] == "probable"


# --------------------------------------------------------------------------- #
# Refusing to launder model output into findings
# --------------------------------------------------------------------------- #

async def test_invented_asset_is_dropped():
    """The model may only name paths Recon actually observed."""
    mcp = FakeMcp()
    async with (llm := llm_proposing(candidate(asset="/totally/made/up"))):
        result = await VulnWorker(llm, mcp)(ctx())

    assert result["weaknesses"] == []
    assert result["candidates_dropped"] == 1
    assert mcp.probed == []          # not even probed — rejected before the request


async def test_asset_returning_404_is_dropped():
    mcp = FakeMcp(statuses={"/api/Users": 404})
    async with (llm := llm_proposing(candidate(asset="/api/Users"))):
        result = await VulnWorker(llm, FakeMcp(statuses={"/api/Users": 404}))(ctx())

    assert result["weaknesses"] == []
    assert result["candidates_dropped"] == 1


async def test_unreachable_asset_is_dropped():
    async with (llm := llm_proposing(candidate())):
        result = await VulnWorker(llm, FakeMcp(default=0))(ctx())

    assert result["weaknesses"] == []


async def test_401_counts_as_existing():
    """An endpoint that refuses you is still an endpoint — often the good one."""
    async with (llm := llm_proposing(candidate())):
        result = await VulnWorker(llm, FakeMcp(default=401))(ctx())

    assert len(result["weaknesses"]) == 1


@pytest.mark.parametrize("vector", [
    "", "high", "CVSS:3.1/AV:N/AC:L", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
])
async def test_unparseable_vector_drops_the_candidate(vector):
    """A default severity would be a confident wrong answer, so there isn't one."""
    async with (llm := llm_proposing(candidate(vector=vector))):
        result = await VulnWorker(llm, FakeMcp())(ctx())

    assert result["weaknesses"] == []
    assert result["candidates_dropped"] == 1


async def test_empty_candidate_list_is_a_valid_answer():
    async with (llm := llm_proposing()):
        result = await VulnWorker(llm, FakeMcp())(ctx())

    assert result["weaknesses"] == [] and result["candidates_dropped"] == 0


async def test_missing_candidates_key_fails_the_stage():
    def handler(request):
        return httpx.Response(200, json={
            "choices": [{"message": {"content": '{"findings": []}'}}],
            "usage": {}})

    llm = LlmClient("vuln", client=httpx.AsyncClient(
        transport=httpx.MockTransport(handler)), api_key="k")
    async with llm:
        with pytest.raises(WorkFailed, match="no 'candidates' list"):
            await VulnWorker(llm, FakeMcp())(ctx())


async def test_empty_asset_map_short_circuits():
    """Nothing observed means nothing to assess; do not call the model."""
    def explode(request):
        raise AssertionError("the model must not be called for an empty map")

    llm = LlmClient("vuln", client=httpx.AsyncClient(
        transport=httpx.MockTransport(explode)), api_key="k")
    async with llm:
        result = await VulnWorker(llm, FakeMcp())(
            ctx(upstream={"target_url": "http://target.test"}))

    assert result["weaknesses"] == []


async def test_ids_are_sequential_over_surviving_candidates_only():
    """A dropped candidate must not leave a gap in the register's IDs."""
    async with (llm := llm_proposing(
            candidate(asset="/nope"),                  # dropped: unknown asset
            candidate(asset="/rest/user/login"),
            candidate(asset="/api/Users"))):
        result = await VulnWorker(llm, FakeMcp())(ctx())

    assert [w["id"] for w in result["weaknesses"]] == ["W-001", "W-002"]
