"""Tests for the first LLM-backed stage.

The point of these is not that the model is clever — it is that the worker
does not trust it. Every test below feeds the worker output a real model
plausibly could produce and checks the worker's response to it.

The live test at the bottom runs the genuine provider and is skipped unless
``APTS_LIVE_LLM_TESTS=1`` and a key file are both present.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from shared.llm import LlmClient, load_api_key
from shared.models import Scope

from agent.services.workers.base import WorkContext, WorkFailed
from agent.services.workers.mitre_worker import MitreWorker

KEY_PATH = Path(__file__).resolve().parent.parent / "tokens" / "deepseek_api_key"
LIVE = os.environ.get("APTS_LIVE_LLM_TESTS") == "1" and KEY_PATH.exists()

REGISTER = {
    "weaknesses": [
        {"id": "W-001", "page": "/search", "kind": "reflected-xss", "cvss": 6.1},
        {"id": "W-002", "page": "/login", "kind": "sql-injection", "cvss": 8.8},
    ]
}


def ctx(upstream=None) -> WorkContext:
    return WorkContext(
        engagement_id=uuid4(),
        target_url="https://juice-shop.test/",
        scope=Scope(domains=["*.juice-shop.test"]),
        upstream=REGISTER if upstream is None else upstream,
    )


def llm_returning(payload) -> LlmClient:
    """An LlmClient wired to a transport that replays one canned completion."""
    content = payload if isinstance(payload, str) else json.dumps(payload)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        })

    return LlmClient("mitre", client=httpx.AsyncClient(
        transport=httpx.MockTransport(handler)), api_key="k")


# --------------------------------------------------------------------------- #

async def test_maps_every_weakness():
    llm = llm_returning({"mappings": {
        "W-001": [{"technique_id": "T1059.007", "technique_name": "JavaScript",
                   "tactic": "Execution"}],
        "W-002": [{"technique_id": "T1190",
                   "technique_name": "Exploit Public-Facing Application",
                   "tactic": "Initial Access"}],
    }})
    async with llm:
        result = await MitreWorker(llm)(ctx())

    assert set(result["mappings"]) == {"W-001", "W-002"}
    assert result["mappings"]["W-002"][0]["technique_id"] == "T1190"


async def test_empty_register_needs_no_model_call():
    """An upstream stage that found nothing gets an empty map, not a call."""
    def explode(request):
        raise AssertionError("the model must not be called for an empty register")

    llm = LlmClient("mitre", client=httpx.AsyncClient(
        transport=httpx.MockTransport(explode)), api_key="k")
    async with llm:
        assert await MitreWorker(llm)(ctx(upstream={"weaknesses": []})) == {"mappings": {}}


# --------------------------------------------------------------------------- #
# Not trusting the model
# --------------------------------------------------------------------------- #

async def test_malformed_technique_id_rejected():
    """'T99' is not a technique ID; the schema must refuse it."""
    llm = llm_returning({"mappings": {
        "W-001": [{"technique_id": "T99"}],
        "W-002": [{"technique_id": "T1190"}],
    }})
    async with llm:
        with pytest.raises(WorkFailed, match="schema validation"):
            await MitreWorker(llm)(ctx())


async def test_untagged_weakness_rejected():
    """§5.4 requires every register entry to carry at least one technique."""
    llm = llm_returning({"mappings": {"W-001": [{"technique_id": "T1190"}]}})
    async with llm:
        with pytest.raises(WorkFailed, match="untagged"):
            await MitreWorker(llm)(ctx())


async def test_empty_tag_list_rejected():
    llm = llm_returning({"mappings": {
        "W-001": [{"technique_id": "T1190"}],
        "W-002": [],
    }})
    async with llm:
        with pytest.raises(WorkFailed, match="schema validation"):
            await MitreWorker(llm)(ctx())


async def test_invented_weakness_ids_are_dropped():
    """The model must not add findings; downstream stages join on these IDs."""
    llm = llm_returning({"mappings": {
        "W-001": [{"technique_id": "T1059.007"}],
        "W-002": [{"technique_id": "T1190"}],
        "W-999": [{"technique_id": "T1486"}],   # never in the register
    }})
    async with llm:
        result = await MitreWorker(llm)(ctx())

    assert set(result["mappings"]) == {"W-001", "W-002"}


async def test_missing_mappings_key_rejected():
    llm = llm_returning({"result": "here you go"})
    async with llm:
        with pytest.raises(WorkFailed, match="no 'mappings' object"):
            await MitreWorker(llm)(ctx())


async def test_provider_failure_becomes_work_failure():
    """An LLM outage is a stage failure, so the orchestrator's retry path runs."""
    def broken(request):
        return httpx.Response(503, json={"error": "upstream unavailable"})

    llm = LlmClient("mitre", client=httpx.AsyncClient(
        transport=httpx.MockTransport(broken)), api_key="k")
    async with llm:
        with pytest.raises(WorkFailed, match="mapping call failed"):
            await MitreWorker(llm)(ctx())


# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not LIVE, reason="set APTS_LIVE_LLM_TESTS=1 with a key file")
async def test_live_model_produces_a_valid_attack_map():
    async with LlmClient("mitre", api_key=load_api_key(str(KEY_PATH))) as llm:
        result = await MitreWorker(llm)(ctx())

    assert set(result["mappings"]) == {"W-001", "W-002"}
    for tags in result["mappings"].values():
        assert tags and all(t["technique_id"].startswith("T") for t in tags)
