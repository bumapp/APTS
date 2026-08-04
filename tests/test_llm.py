"""Tests for the shared LLM client.

Offline by default: a stub httpx transport stands in for the provider, so the
suite is deterministic, free, and runs with no network. The failure modes worth
pinning here are the ones that bite silently in production — an empty completion
caused by thinking-mode budget exhaustion, and unparseable JSON.

One live test exercises the real provider and is skipped unless
``APTS_LIVE_LLM_TESTS=1`` and a key file are both present. Nothing that costs
money or needs the internet runs by accident.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest

from shared.llm import LlmClient, LlmError, Usage, load_api_key

KEY_PATH = Path(__file__).resolve().parent.parent / "tokens" / "deepseek_api_key"
LIVE = os.environ.get("APTS_LIVE_LLM_TESTS") == "1" and KEY_PATH.exists()


def stub_client(*responses: dict) -> httpx.AsyncClient:
    """An AsyncClient that replays canned provider responses in order."""
    queue = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        body = queue.pop(0) if queue else queue_exhausted()
        status = body.pop("_status", 200)
        return httpx.Response(status, json=body)

    def queue_exhausted():
        raise AssertionError("stub client received more calls than expected")

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def completion(content: str, *, reasoning_tokens: int = 0,
               status: int = 200) -> dict:
    return {
        "_status": status,
        "choices": [{"message": {"content": content}, "finish_reason": "stop"}],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "completion_tokens_details": {"reasoning_tokens": reasoning_tokens},
            "prompt_tokens_details": {"cached_tokens": 0},
        },
    }


# --------------------------------------------------------------------------- #
# Key handling
# --------------------------------------------------------------------------- #

def test_missing_key_file_is_actionable(tmp_path):
    with pytest.raises(LlmError, match="Was the secret mounted"):
        load_api_key(str(tmp_path / "nope"))


def test_empty_key_file_rejected(tmp_path):
    path = tmp_path / "key"
    path.write_text("   ")
    with pytest.raises(LlmError, match="empty"):
        load_api_key(str(path))


def test_key_is_read_from_file_not_environment(tmp_path):
    path = tmp_path / "key"
    path.write_text("sk-test-value\n")
    assert load_api_key(str(path)) == "sk-test-value"


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #

async def test_returns_parsed_json():
    payload = {"mappings": {"W-001": [{"technique_id": "T1190"}]}}
    async with LlmClient("mitre", client=stub_client(completion(json.dumps(payload))),
                         api_key="k") as llm:
        assert await llm.complete_json("schema", "weaknesses") == payload


async def test_retries_once_on_unparseable_json():
    async with LlmClient(
        "mitre",
        client=stub_client(completion("not json at all"), completion('{"ok": true}')),
        api_key="k",
    ) as llm:
        assert await llm.complete_json("schema", "input") == {"ok": True}


# --------------------------------------------------------------------------- #
# The failure modes that would otherwise be silent
# --------------------------------------------------------------------------- #

async def test_empty_content_explains_thinking_budget():
    """Thinking mode can eat the whole token budget and return empty content.

    The provider reports HTTP 200 with an empty string, so without this the
    agent would write an empty artifact and call it success.
    """
    empty = completion("", reasoning_tokens=4000)
    async with LlmClient("mitre", client=stub_client(empty, empty), api_key="k") as llm:
        with pytest.raises(LlmError, match="empty content"):
            await llm.complete_json("schema", "input", max_tokens=4000)


async def test_persistent_bad_json_raises():
    async with LlmClient(
        "mitre",
        client=stub_client(completion("nope"), completion("still nope")),
        api_key="k",
    ) as llm:
        with pytest.raises(LlmError, match="unparseable JSON"):
            await llm.complete_json("schema", "input")


async def test_json_array_rejected():
    """JSON mode permits any JSON value; artifacts are always objects."""
    async with LlmClient("mitre", client=stub_client(completion("[1,2,3]"),
                                                     completion("[4]")),
                         api_key="k") as llm:
        with pytest.raises(LlmError, match="expected a JSON object"):
            await llm.complete_json("schema", "input")


async def test_http_error_surfaces():
    async with LlmClient("mitre", client=stub_client(completion("{}", status=429)),
                         api_key="k") as llm:
        with pytest.raises(LlmError, match="HTTP 429"):
            await llm.complete_json("schema", "input")


async def test_use_outside_context_manager_is_caught():
    with pytest.raises(LlmError, match="outside its async context"):
        await LlmClient("mitre").complete_json("s", "u")


def test_usage_parses_reasoning_tokens():
    usage = Usage.from_response({
        "prompt_tokens": 88, "completion_tokens": 94,
        "completion_tokens_details": {"reasoning_tokens": 23},
        "prompt_tokens_details": {"cached_tokens": 64},
    })
    assert (usage.reasoning_tokens, usage.cached_tokens) == (23, 64)


# --------------------------------------------------------------------------- #
# Live provider — opt-in only
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not LIVE, reason="set APTS_LIVE_LLM_TESTS=1 with a key file")
async def test_live_mitre_mapping_round_trip():
    """Real call against the configured provider. Costs a fraction of a cent."""
    system = (
        'You map web weaknesses to MITRE ATT&CK for Enterprise. Reply ONLY with '
        'JSON: {"mappings":{"<weakness_id>":[{"technique_id":"T####",'
        '"technique_name":str,"tactic":str}]}}'
    )
    async with LlmClient("mitre", api_key=load_api_key(str(KEY_PATH))) as llm:
        result = await llm.complete_json(
            system, "W-002: SQL injection in the login form on /login")

    techniques = result["mappings"]["W-002"]
    assert techniques and techniques[0]["technique_id"].startswith("T")
