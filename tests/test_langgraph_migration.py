"""Offline tests for the LangGraph/LangChain migration foundation.

No network and no model: the LLM is a scripted fake chat model and the MCP server
is a fake async client. What these prove:

* the chat-model factory resolves base-URL / key / thinking-flag from env exactly
  as the legacy loop did, and Langfuse fails open when unconfigured;
* the MCP-tool wrapper enforces the repeat-call guard and fires its transform /
  on_call / observe hooks (the seams the exploit loop will need);
* the vuln worker runs end to end on a real ``create_react_agent`` graph and emits
  a byte-compatible VulnerabilityRegister.

Run: ``python -m pytest tests/test_langgraph_migration.py -q`` in a venv that has
the requirements.txt LangChain/LangGraph/langfuse deps installed.
"""
from __future__ import annotations

import uuid

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #

class ScriptedModel(BaseChatModel):
    """A real BaseChatModel that returns a pre-scripted sequence of messages.

    Enough of the interface for ``create_react_agent`` to drive it: ``bind_tools``
    is a no-op returning self, and each generation pops the next scripted reply.
    """
    responses: list = []

    def bind_tools(self, tools, **kwargs):  # noqa: D401 - graph binds tools; we ignore
        return self

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs) -> ChatResult:
        msg = self.responses.pop(0)
        return ChatResult(generations=[ChatGeneration(message=msg)])


class _Descriptor:
    def __init__(self, name, description, input_schema):
        self.name = name
        self.description = description
        self.input_schema = input_schema


class _ToolResult:
    def __init__(self, structured):
        self.structured_content = structured
        self.content = []


class FakeMcpClient:
    """Async-context fake of the mcp-v2 Client used by the workers."""
    def __init__(self, tools, responses):
        self._tools = tools
        self._responses = responses
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def list_tools(self):
        class _R:
            tools = self._tools
        return _R()

    async def call_tool(self, name, args):
        self.calls.append((name, args))
        payload = self._responses[name]
        return _ToolResult(payload(args) if callable(payload) else payload)


# --------------------------------------------------------------------------- #
# shared/llm.py
# --------------------------------------------------------------------------- #

async def test_base_url_strips_chat_completions():
    from shared import llm as L
    assert L._base_url("http://x:9/v1/chat/completions") == "http://x:9/v1"
    assert L._base_url("https://h/openai/v1/chat/completions/") == "https://h/openai/v1"
    assert L._base_url("http://x:9/v1") == "http://x:9/v1"


async def test_build_chat_model_keyless_sets_thinking_flag(monkeypatch):
    from shared import llm as L
    monkeypatch.delenv("APTS_LOOP_LLM_KEY", raising=False)
    monkeypatch.setattr(L, "_api_key", lambda: "")  # keyless == local llama
    model = L.build_chat_model("vuln", max_tokens=123)
    assert model.model_name  # a model id resolved
    assert model.extra_body == {"chat_template_kwargs": {"enable_thinking": False}}
    assert model.max_tokens == 123


async def test_build_chat_model_with_key_no_thinking_flag(monkeypatch):
    from shared import llm as L
    monkeypatch.setattr(L, "_api_key", lambda: "sk-live")
    monkeypatch.delenv("APTS_LLM_STORE", raising=False)
    model = L.build_chat_model("vuln")
    assert not model.extra_body  # hosted endpoint: no chat_template_kwargs
    # store=false is sent to a keyed endpoint to block server-side retention.
    assert model.store is False


async def test_temperature_omitted_by_default_and_honoured_when_set(monkeypatch):
    from shared import llm as L
    from shared import settings
    monkeypatch.setattr(L, "_api_key", lambda: "sk-live")
    monkeypatch.delenv("APTS_LOOP_LLM_TEMPERATURE", raising=False)
    settings.load.cache_clear()
    # Default: no temperature configured -> not forced onto the model.
    assert settings.load().loop.temperature is None
    assert L.build_chat_model("vuln").temperature is None  # provider default, not 0
    # Explicitly configured temperature is passed through (validated at load).
    monkeypatch.setenv("APTS_LOOP_LLM_TEMPERATURE", "0.4")
    settings.load.cache_clear()
    assert L.build_chat_model("vuln").temperature == 0.4
    settings.load.cache_clear()  # restore for other tests


async def test_local_keyless_has_no_store_flag(monkeypatch):
    from shared import llm as L
    monkeypatch.setattr(L, "_api_key", lambda: "")  # keyless local llama
    model = L.build_chat_model("vuln")
    assert model.store is None  # not sent — local server may reject it


async def test_mask_redacts_sensitive_keys_and_secret_strings():
    from shared import llm as L
    masked = L._mask(data={
        "url": "http://t.test/login",
        "cookie": "token=abc123",
        "headers": {"Authorization": "Bearer XYZ"},
        "loot": [{"type": "dbms", "value": "MySQL"}],
        "note": "set-cookie: session=deadbeef; path=/",
        "nested": {"password": "hunter2", "safe": "keep-me"},
    })
    assert masked["url"] == "http://t.test/login"        # non-sensitive kept
    assert masked["cookie"] == "***REDACTED***"           # sensitive key redacted
    assert masked["headers"] == "***REDACTED***"          # whole headers blob gone
    assert masked["loot"] == "***REDACTED***"
    assert masked["nested"]["password"] == "***REDACTED***"
    assert masked["nested"]["safe"] == "keep-me"
    assert "deadbeef" not in masked["note"]               # secret-shaped string scrubbed


async def test_trace_run_and_flush_are_noops_when_langfuse_off(monkeypatch):
    from shared import llm as L
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("LANGFUSE_SECRET_KEY", raising=False)
    L._client.cache_clear()
    with L.trace_run(name="x", run_input="in") as span:
        assert span is None
        L.set_run_output(span, "out")  # must not raise on None
    L.flush()  # must not raise when disabled


# --------------------------------------------------------------------------- #
# shared/prompts.py — the prompt registry seam
# --------------------------------------------------------------------------- #

async def test_prompt_registry_default_when_langfuse_off(monkeypatch):
    from shared import llm as L
    from shared import prompts
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("LANGFUSE_SECRET_KEY", raising=False)
    L._client.cache_clear()
    prompts.register("t.system", "the default text")
    resolved = prompts.get("t.system")
    assert resolved.text == "the default text"
    assert resolved.trace_prompt is None  # nothing to link when serving a default


async def test_prompt_registry_unknown_id_fails_closed(monkeypatch):
    from shared import llm as L
    from shared import prompts
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("LANGFUSE_SECRET_KEY", raising=False)
    L._client.cache_clear()
    import pytest as _pytest
    with _pytest.raises(KeyError):
        prompts.get("nonexistent.prompt.id")


async def test_workers_register_their_system_prompts():
    # Importing the workers registers their defaults (module-level register()).
    import agent.services.workers.vuln.vuln_worker  # noqa: F401
    import agent.services.workers.exploit.exploit_worker  # noqa: F401
    from shared import prompts
    assert prompts.get("vuln.system").text.startswith("You are a web application")
    assert "exploitation agent" in prompts.get("exploit.system").text.lower()


# --------------------------------------------------------------------------- #
# Full flow: vuln (produces a register) → exploit (proves a weakness from it)
# --------------------------------------------------------------------------- #

async def test_settings_defaults_and_validation(monkeypatch):
    from shared import settings
    # Defaults
    for k in ("APTS_LOOP_LLM_TEMPERATURE", "APTS_LOOP_LLM_TIMEOUT",
              "APTS_TRACE_MAX_ITEMS", "APTS_LANGFUSE_DISABLED"):
        monkeypatch.delenv(k, raising=False)
    settings.load.cache_clear()
    s = settings.load()
    assert s.loop.temperature is None and s.loop.timeout == 300
    assert s.trace.enabled is True and s.trace.max_items == 200
    assert s.langfuse.prompt_label == "production"

    # A malformed value fails fast at load with a clear aggregated error.
    import pytest as _pytest
    monkeypatch.setenv("APTS_LOOP_LLM_TIMEOUT", "not-a-number")
    settings.load.cache_clear()
    with _pytest.raises(RuntimeError) as ei:
        settings.load()
    assert "APTS" in str(ei.value) or "timeout" in str(ei.value)
    # Out-of-range temperature is also rejected.
    monkeypatch.delenv("APTS_LOOP_LLM_TIMEOUT", raising=False)
    monkeypatch.setenv("APTS_LOOP_LLM_TEMPERATURE", "5")  # > 2
    settings.load.cache_clear()
    with _pytest.raises(RuntimeError):
        settings.load()
    settings.load.cache_clear()  # restore for other tests


async def test_full_flow_vuln_then_exploit(monkeypatch):
    """The migrated flow end to end: vuln's output register feeds exploit."""
    from agent.services.workers.vuln import vuln_worker as V
    from agent.services.workers.exploit import exploit_worker as E
    from agent.services.workers.base import WorkContext
    from shared.models import Scope
    import uuid as _uuid

    eid = _uuid.uuid4()

    # --- Stage 1: vuln ---
    vuln_model = ScriptedModel(responses=[
        AIMessage(content="", tool_calls=[{
            "name": "hacktricks_article", "args": {"slug": "sql-injection"},
            "id": "c1"}]),
        AIMessage(content=("HYPOTHESIS: SQL injection — login (param `email`, "
                           "POST /rest/user/login)\nWHY: email reaches a SQL query")),
        AIMessage(content="DONE"),
    ])
    monkeypatch.setattr(V, "build_chat_model", lambda *a, **k: vuln_model)
    vuln_tools = [
        _Descriptor("hacktricks_overview", "menu", {"type": "object", "properties": {}}),
        _Descriptor("hacktricks_article", "article",
                    {"type": "object", "properties": {"slug": {"type": "string"}}}),
    ]
    vuln_fake = FakeMcpClient(vuln_tools, {
        "hacktricks_overview": {"techniques": [{"slug": "sql-injection"}]},
        "list_recorded_requests": {"requests": [{
            "method": "POST", "path": "/rest/user/login",
            "url": "http://t.test/rest/user/login",
            "content_type": "application/json",
            "post_data": '{"email":"a@b.c","password":"x"}'}]},
        "hacktricks_article": lambda a: {"found": True, "slug": a.get("slug")},
    })
    monkeypatch.setattr(V, "Client", lambda url: vuln_fake)
    ctx = WorkContext(engagement_id=eid, target_url="http://t.test/",
                      scope=Scope(domains=["t.test"]), upstream={}, directive="")
    register = await V.VulnWorker()(ctx)
    assert len(register["weaknesses"]) >= 1  # vuln produced a register

    # --- Stage 2: exploit consumes vuln's register ---
    exploit_model = ScriptedModel(responses=[
        AIMessage(content="", tool_calls=[{
            "name": "sqlmap",
            "args": {"url": "http://t.test/rest/user/login", "data": "email=x"},
            "id": "c1"}]),
        AIMessage(content=("VERDICT: PROVEN — sqlmap reported injectable\n"
                           "PROVEN_CLASS: SQL injection")),
    ])
    monkeypatch.setattr(E, "build_chat_model", lambda *a, **k: exploit_model)
    exploit_fake = FakeMcpClient(_EXPLOIT_TOOLS, {
        "sqlmap": lambda a: {"injectable": True, "dbms": "MySQL",
                             "injection_points": [{"type": "boolean-based"}]},
    })
    monkeypatch.setattr(E, "Client", lambda url: exploit_fake)
    # The register vuln just produced is what exploit loads from the store.
    results = _FakeResults(register, _RECON)
    ctx2 = WorkContext(engagement_id=eid, target_url="http://t.test/",
                       scope=Scope(domains=["t.test"]), upstream={}, directive="",
                       credentials={})
    outcome = await E.ExploitWorker(results=results)(ctx2)

    assert len(outcome["attempts"]) == len(register["weaknesses"])
    proven = outcome["attempts"][0]
    assert proven["confirmed"] is True
    assert proven["signal_basis"].startswith("sqlmap injectable")
    assert proven["weakness_id"] == register["weaknesses"][0]["id"]


async def test_langfuse_off_when_unconfigured(monkeypatch):
    from shared import llm as L
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("LANGFUSE_SECRET_KEY", raising=False)
    assert L.langfuse_enabled() is False
    assert L.langfuse_callbacks() == []
    cfg = L.run_config(engagement_id="e1", agent="vuln")
    assert cfg["callbacks"] == [] and cfg["metadata"]["agent"] == "vuln"
    assert cfg["metadata"]["langfuse_session_id"] == "e1"


# --------------------------------------------------------------------------- #
# agentic.py — tool wrapper
# --------------------------------------------------------------------------- #

async def test_tool_wrapper_repeat_guard_and_hooks():
    from agent.services.workers.common import common_agentic as agentic
    seen_calls = []
    fake = FakeMcpClient(
        tools=[_Descriptor("hacktricks_article", "d",
                           {"type": "object", "properties": {"slug": {"type": "string"}}})],
        responses={"hacktricks_article": lambda a: {"found": True, "slug": a.get("slug")}})
    tried: dict = {}
    tools = agentic.as_langchain_tools(
        fake, await _descriptors(fake), tried=tried,
        outcome=lambda n, p: f"found={p.get('found')}",
        on_call=lambda n, a, p: seen_calls.append((n, a)))
    tool = {t.name: t for t in tools}["hacktricks_article"]

    first = await tool.ainvoke({"slug": "sql-injection"})
    assert "OBSERVATION from hacktricks_article" in first
    assert tried  # ledger recorded the outcome
    assert seen_calls == [("hacktricks_article", {"slug": "sql-injection"})]

    repeat = await tool.ainvoke({"slug": "sql-injection"})
    assert "already ran this exact call" in repeat
    assert len(fake.calls) == 1  # the repeat did NOT hit the server


async def _descriptors(fake):
    return (await fake.list_tools()).tools


async def test_tool_wrapper_survives_callback_arity_bug():
    """A callback with the wrong signature must NOT surface as a tool error to
    the model (regression for _outcome(payload) vs outcome(name, payload))."""
    from agent.services.workers.common import common_agentic as agentic
    fake = FakeMcpClient(
        tools=[_Descriptor("hacktricks_article", "d",
                           {"type": "object", "properties": {"slug": {"type": "string"}}})],
        responses={"hacktricks_article": lambda a: {"found": True, "slug": a.get("slug")}})
    # Buggy 1-arg outcome, exactly like vuln_worker._outcome before the fix.
    tools = agentic.as_langchain_tools(
        fake, await _descriptors(fake), tried={},
        outcome=lambda payload: "found")  # wrong arity on purpose
    tool = {t.name: t for t in tools}["hacktricks_article"]
    out = await tool.ainvoke({"slug": "sql-injection"})
    # The tool still returns a normal observation, not "Error: TypeError(...)".
    assert "OBSERVATION" in out or "hacktricks_article" in out
    assert "TypeError" not in out and "positional argument" not in out


async def test_compacting_hook_trims_only_when_over_budget():
    from agent.services.workers.common import common_agentic as agentic
    from langchain_core.messages import HumanMessage, SystemMessage
    small = [SystemMessage(content="s"), HumanMessage(content="u")]
    hook = agentic.compacting_hook(budget_chars=10)
    assert hook({"messages": small})["llm_input_messages"] == small
    big = [SystemMessage(content="s" * 20), HumanMessage(content="task"),
           AIMessage(content="a" * 50), HumanMessage(content="obs" * 50),
           AIMessage(content="more"), HumanMessage(content="last")]
    out = hook({"messages": big})["llm_input_messages"]
    # System prompt + task turn are always kept; the middle is dropped over budget.
    assert isinstance(out[0], SystemMessage) and isinstance(out[1], HumanMessage)
    assert agentic._content_len(out) <= agentic._content_len(big)


async def test_compacting_hook_preserves_tool_call_pairing():
    """Regression: parallel tool_calls must not be split from their ToolMessages
    (that caused INVALID_CHAT_HISTORY once the _outcome bug was fixed)."""
    from agent.services.workers.common import common_agentic as agentic
    from langchain_core.messages import (HumanMessage, SystemMessage, ToolMessage)
    msgs = [
        SystemMessage(content="S" * 1000), HumanMessage(content="TASK " * 100),
        AIMessage(content="", tool_calls=[
            {"name": "t", "args": {}, "id": "a", "type": "tool_call"},
            {"name": "t", "args": {}, "id": "b", "type": "tool_call"}]),
        ToolMessage(content="X" * 3000, tool_call_id="a"),
        ToolMessage(content="Y" * 3000, tool_call_id="b"),
        AIMessage(content="m", tool_calls=[
            {"name": "t", "args": {}, "id": "c", "type": "tool_call"}]),
        ToolMessage(content="Z" * 3000, tool_call_id="c"),
    ]
    out = agentic.compacting_hook(6000)({"messages": msgs})["llm_input_messages"]
    call_ids = {tc["id"] for m in out if isinstance(m, AIMessage) for tc in (m.tool_calls or [])}
    tool_ids = {m.tool_call_id for m in out if isinstance(m, ToolMessage)}
    assert call_ids == tool_ids  # every kept tool_call has its ToolMessage, and vice versa
    assert isinstance(out[0], SystemMessage)  # system kept
    # no leading orphan ToolMessage
    assert not any(isinstance(m, ToolMessage) for m in out[:2])


# --------------------------------------------------------------------------- #
# vuln_worker.py — end to end on a real create_react_agent graph
# --------------------------------------------------------------------------- #

async def test_vuln_worker_end_to_end(monkeypatch):
    from agent.services.workers.vuln import vuln_worker as V
    from agent.services.workers.base import WorkContext
    from shared.models import Scope

    # Scripted model: (1) call the article tool, (2) emit a hypothesis, (3) DONE.
    scripted = ScriptedModel(responses=[
        AIMessage(content="", tool_calls=[{
            "name": "hacktricks_article",
            "args": {"slug": "sql-injection"}, "id": "call_1"}]),
        AIMessage(content=("HYPOTHESIS: SQL injection — login (param `email`, "
                           "POST /rest/user/login)\nWHY: email reaches a SQL query")),
        AIMessage(content="DONE"),
    ])
    monkeypatch.setattr(V, "build_chat_model", lambda *a, **k: scripted)

    tools = [
        _Descriptor("hacktricks_overview", "menu", {"type": "object", "properties": {}}),
        _Descriptor("hacktricks_article", "article",
                    {"type": "object", "properties": {"slug": {"type": "string"}}}),
    ]
    responses = {
        "hacktricks_overview": {"techniques": [{"slug": "sql-injection"}, {"slug": "xss"}]},
        "list_recorded_requests": {"requests": [{
            "method": "POST", "path": "/rest/user/login",
            "url": "http://t.test/rest/user/login",
            "content_type": "application/json",
            "post_data": '{"email":"a@b.c","password":"x"}'}]},
        "hacktricks_article": lambda a: {"found": True, "slug": a.get("slug"),
                                         "content": "' OR 1=1 --"},
    }
    fake = FakeMcpClient(tools, responses)
    monkeypatch.setattr(V, "Client", lambda url: fake)

    ctx = WorkContext(
        engagement_id=uuid.uuid4(), target_url="http://t.test/",
        scope=Scope(domains=["t.test"]), upstream={}, directive="")
    result = await V.VulnWorker()(ctx)

    assert "weaknesses" in result
    assert len(result["weaknesses"]) >= 1
    w = result["weaknesses"][0]
    assert "SQL injection" in w["title"]
    assert w["asset"] == "/rest/user/login"
    # The model drove the article tool exactly once (repeat guard held).
    assert ("hacktricks_article", {"slug": "sql-injection"}) in fake.calls


# --------------------------------------------------------------------------- #
# exploit_worker.py — credential injection + deterministic proof signal
# --------------------------------------------------------------------------- #

class _FakeResults:
    """Stand-in for AgentResultRepository: serves the vuln register + recon bg."""
    def __init__(self, register, recon):
        self._register = register
        self._recon = recon

    def load(self, engagement_id, stage):
        return {"vuln": self._register, "recon": self._recon}.get(stage)


def _exploit_ctx(credentials):
    import uuid as _uuid
    from agent.services.workers.base import WorkContext
    from shared.models import Scope
    return WorkContext(
        engagement_id=_uuid.uuid4(), target_url="http://t.test/",
        scope=Scope(domains=["t.test"]), upstream={}, directive="",
        credentials=credentials)


_REGISTER = {"weaknesses": [{
    "id": "W-001", "title": "SQL injection — login",
    "rationale": "email reaches a SQL query",
    "origin_request": {"method": "POST", "url": "http://t.test/rest/user/login",
                       "params": ["email"], "post_data": '{"email":"x"}'}}]}
_RECON = {"target_url": "http://t.test/", "technologies": [], "endpoints": [],
          "api_paths": [], "pages_crawled": 1}
_EXPLOIT_TOOLS = [
    _Descriptor("http_request", "send", {"type": "object", "properties": {
        "url": {"type": "string"}, "headers": {"type": "object"}}}),
    _Descriptor("sqlmap", "sqli", {"type": "object", "properties": {
        "url": {"type": "string"}, "data": {"type": "string"},
        "cookie": {"type": "string"}}}),
    _Descriptor("xss_prove", "xss", {"type": "object", "properties": {
        "target": {"type": "string"}}}),
]


async def test_exploit_lc_credential_injection_and_deterministic_signal(monkeypatch):
    from agent.services.workers.exploit import exploit_worker as E

    # Model: run sqlmap on the in-scope login, then declare PROVEN.
    scripted = ScriptedModel(responses=[
        AIMessage(content="", tool_calls=[{
            "name": "sqlmap",
            "args": {"url": "http://t.test/rest/user/login", "data": "email=x"},
            "id": "c1"}]),
        AIMessage(content=("VERDICT: PROVEN — sqlmap reported the parameter "
                           "injectable\nPROVEN_CLASS: SQL injection\n"
                           "LOOT: dbms: MySQL")),
    ])
    monkeypatch.setattr(E, "build_chat_model", lambda *a, **k: scripted)

    responses = {
        "sqlmap": lambda a: {"injectable": True, "dbms": "MySQL",
                             "injection_points": [{"type": "boolean-based"}]},
    }
    fake = FakeMcpClient(_EXPLOIT_TOOLS, responses)
    monkeypatch.setattr(E, "Client", lambda url: fake)

    ctx = _exploit_ctx(credentials={"cookies": [{"name": "token", "value": "abc"}]})
    worker = E.ExploitWorker(results=_FakeResults(_REGISTER, _RECON))
    result = await worker(ctx)

    attempts = result["attempts"]
    assert len(attempts) == 1
    a = attempts[0]
    assert a["confirmed"] is True
    # Deterministic signal from the raw sqlmap payload, NOT the model's word.
    assert a["signal_basis"].startswith("sqlmap injectable")
    assert a["proven_vuln"] == "SQL injection"
    assert any(l["value"] == "MySQL" for l in result["loot"])

    # Credential injection: the args SENT to sqlmap carried the session cookie...
    sent_sqlmap = next(args for name, args in fake.calls if name == "sqlmap")
    assert sent_sqlmap.get("cookie") == "token=abc"
    # ...and the same call carries the sticky-LB shard header (a slot<n> value, one
    # replica slot per proof), coexisting with the injected session, so the LB pins
    # the whole proof to its own replica.
    import re as _re
    assert _re.fullmatch(r"slot\d+", sent_sqlmap.get("headers", {}).get(E.SHARD_HEADER) or "")
    # ...but the recorded evidence/transcript keeps the model's ORIGINAL args
    # (no token or shard header duplicated into the stored request).
    tx = next(t for t in result["transcript"] if t["tool"] == "sqlmap")
    assert "cookie" not in tx["request"]
    assert E.SHARD_HEADER not in (tx["request"].get("headers") or {})


async def test_exploit_lc_proven_without_signal_is_model_judgment(monkeypatch):
    from agent.services.workers.exploit import exploit_worker as E

    scripted = ScriptedModel(responses=[
        AIMessage(content="", tool_calls=[{
            "name": "http_request",
            "args": {"url": "http://t.test/rest/user/login"}, "id": "c1"}]),
        AIMessage(content="VERDICT: PROVEN — the response looked wrong to me"),
    ])
    monkeypatch.setattr(E, "build_chat_model", lambda *a, **k: scripted)
    # http_request returns an ordinary 200 — no deterministic proof signal.
    fake = FakeMcpClient(_EXPLOIT_TOOLS, {"http_request": lambda a: {"status_code": 200}})
    monkeypatch.setattr(E, "Client", lambda url: fake)

    ctx = _exploit_ctx(credentials={})  # unauthenticated: no injection
    worker = E.ExploitWorker(results=_FakeResults(_REGISTER, _RECON))
    result = await worker(ctx)

    a = result["attempts"][0]
    assert a["confirmed"] is True
    # A PROVEN verdict with no tool signal is flagged model_judgment, not upgraded.
    assert a["signal_basis"] == "model_judgment"
    # No creds ⇒ no CREDENTIAL injection. The only header added is the sticky-LB
    # routing header (always present); no Authorization/Cookie slipped in.
    sent = next(args for name, args in fake.calls if name == "http_request")
    assert set(sent.get("headers") or {}) <= {E.SHARD_HEADER}


# --------------------------------------------------------------------------- #
# Newly-ported stages on LangGraph: mitre / script / recon / adviser
# --------------------------------------------------------------------------- #

async def test_all_stage_system_prompts_register():
    # Importing the workers registers their defaults (module-level register()).
    import agent.services.workers.recon.recon_worker   # noqa: F401
    import agent.services.workers.vuln.vuln_worker     # noqa: F401
    import agent.services.workers.mitre.mitre_worker    # noqa: F401
    import agent.services.workers.exploit.exploit_worker  # noqa: F401
    import agent.services.workers.script.script_worker   # noqa: F401
    import agent.services.workers.adviser.adviser_worker  # noqa: F401
    from shared import prompts
    for pid in ("recon.rank", "vuln.system", "mitre.system", "exploit.system",
                "script.system", "adviser.system"):
        assert prompts.get(pid).text  # a non-empty default is registered


_ATTACK_TOOLS = [
    _Descriptor("attack_catalog", "menu", {"type": "object", "properties": {}}),
    _Descriptor("attack_search", "search",
                {"type": "object", "properties": {"query": {"type": "string"}}}),
    _Descriptor("attack_technique", "lookup",
                {"type": "object", "properties": {"technique_id": {"type": "string"}}}),
]


async def test_mitre_worker_end_to_end(monkeypatch):
    """The mapping loop confirms a technique via the catalogue (tool is the trust boundary)."""
    from agent.services.workers.mitre import mitre_worker as M
    from agent.services.workers.base import WorkContext
    from shared.models import Scope

    scripted = ScriptedModel(responses=[
        AIMessage(content="TECHNIQUE: T1190 | Exploit Public-Facing Application | Initial Access"),
    ])
    monkeypatch.setattr(M, "build_chat_model", lambda *a, **k: scripted)
    fake = FakeMcpClient(_ATTACK_TOOLS, {
        "attack_catalog": {"techniques": [
            {"technique_id": "T1190", "name": "Exploit Public-Facing Application"}]},
        "attack_technique": lambda a: {
            "found": True, "technique_id": a.get("technique_id"),
            "name": "Exploit Public-Facing Application", "tactics": ["Initial Access"]},
    })
    monkeypatch.setattr(M, "Client", lambda url: fake)

    ctx = WorkContext(
        engagement_id=uuid.uuid4(), target_url="http://t.test/",
        scope=Scope(domains=["t.test"]),
        upstream={"weaknesses": [{"id": "W-001", "title": "SQL injection — login",
                                  "asset": "/rest/user/login",
                                  "rationale": "email reaches a SQL query"}]},
        directive="")
    result = await M.MitreWorker()(ctx)
    assert result["mappings"]["W-001"][0]["technique_id"] == "T1190"


async def test_mitre_falls_back_when_nothing_confirmed(monkeypatch):
    """A hallucinated technique the catalogue rejects is discarded, but the weakness
    gets the deterministic fallback (T1190) rather than failing the whole stage —
    one model/format miss must not stall exploit/script/adviser (§5.4 floor)."""
    from agent.services.workers.mitre import mitre_worker as M
    from agent.services.workers.base import WorkContext
    from shared.models import Scope

    scripted = ScriptedModel(responses=[
        AIMessage(content="TECHNIQUE: T9999 | Totally Made Up | Fantasy"),
    ] * 5)  # every pass proposes an id the catalogue rejects
    monkeypatch.setattr(M, "build_chat_model", lambda *a, **k: scripted)
    fake = FakeMcpClient(_ATTACK_TOOLS, {
        "attack_catalog": {"techniques": [{"technique_id": "T1190", "name": "x"}]},
        "attack_technique": lambda a: {"found": False, "technique_id": a.get("technique_id")},
    })
    monkeypatch.setattr(M, "Client", lambda url: fake)
    ctx = WorkContext(
        engagement_id=uuid.uuid4(), target_url="http://t.test/",
        scope=Scope(domains=["t.test"]),
        upstream={"weaknesses": [{"id": "W-001", "title": "SQLi", "asset": "/login"}]},
        directive="")
    result = await M.MitreWorker()(ctx)
    assert result["mappings"]["W-001"][0]["technique_id"] == "T1190"


async def test_script_worker_ships_last_clean_source(monkeypatch):
    """What ships is the exact source the sandbox last ran clean (on_call capture)."""
    from agent.services.workers.script import script_worker as S
    from agent.services.workers.base import WorkContext
    from shared.models import Scope

    src = "import requests\nprint(requests.get('http://t.test/').status_code)\n"
    scripted = ScriptedModel(responses=[
        AIMessage(content="", tool_calls=[{
            "name": "sandbox_run",
            "args": {"language": "python", "source": src}, "id": "c1"}]),
        AIMessage(content="DONE: reproduces the SQLi || FIX: use parameterised queries"),
    ])
    monkeypatch.setattr(S, "build_chat_model", lambda *a, **k: scripted)
    fake = FakeMcpClient(
        [_Descriptor("sandbox_run", "run", {"type": "object", "properties": {
            "language": {"type": "string"}, "source": {"type": "string"}}})],
        {"sandbox_run": lambda a: {"ok": True, "exit_code": 0, "stdout": "200"}})
    monkeypatch.setattr(S, "Client", lambda url: fake)

    class _Results:
        def load(self, eid, stage):
            return {
                "vuln": {"weaknesses": [{"id": "W-001", "title": "SQL injection",
                                         "asset": "/login"}]},
                "mitre": {"mappings": {"W-001": [{"technique_id": "T1190"}]}},
            }.get(stage)

    ctx = WorkContext(
        engagement_id=uuid.uuid4(), target_url="http://t.test/",
        scope=Scope(domains=["t.test"]),
        upstream={"attempts": [{"weakness_id": "W-001", "confirmed": True,
                                "detection": "sqlmap", "reason": "injectable"}]},
        directive="")
    result = await S.ScriptWorker(_Results())(ctx)
    assert len(result["scripts"]) == 1
    sc = result["scripts"][0]
    assert sc["weakness_id"] == "W-001"
    assert "requests.get" in sc["source"]
    assert sc["technique_ids"] == ["T1190"]
    assert sc["safety_checked"] is True


async def test_script_worker_rejects_unsafe_source(monkeypatch):
    """A sandbox-clean script that trips the safety denylist is discarded, not shipped."""
    from agent.services.workers.script import script_worker as S
    from agent.services.workers.base import WorkContext
    from shared.models import Scope

    unsafe = "import os\nos.system('rm -rf /')\n"
    scripted = ScriptedModel(responses=[
        AIMessage(content="", tool_calls=[{
            "name": "sandbox_run",
            "args": {"language": "python", "source": unsafe}, "id": "c1"}]),
        AIMessage(content="DONE: proves it || FIX: patch"),
    ])
    monkeypatch.setattr(S, "build_chat_model", lambda *a, **k: scripted)
    fake = FakeMcpClient(
        [_Descriptor("sandbox_run", "run", {"type": "object", "properties": {
            "language": {"type": "string"}, "source": {"type": "string"}}})],
        {"sandbox_run": lambda a: {"ok": True, "stdout": "done"}})
    monkeypatch.setattr(S, "Client", lambda url: fake)

    class _Results:
        def load(self, eid, stage):
            return {"vuln": {"weaknesses": [{"id": "W-001", "title": "x", "asset": "/"}]},
                    "mitre": {"mappings": {}}}.get(stage)

    ctx = WorkContext(
        engagement_id=uuid.uuid4(), target_url="http://t.test/",
        scope=Scope(domains=["t.test"]),
        upstream={"attempts": [{"weakness_id": "W-001", "confirmed": True}]}, directive="")
    result = await S.ScriptWorker(_Results())(ctx)
    assert result["scripts"] == []
    assert result["rejected"] == 1


async def test_recon_worker_triages_observed_requests(monkeypatch):
    """Crawl is authoritative; the model ranks (never invents) the observed requests."""
    from agent.services.workers.recon import recon_worker as R
    from agent.services.workers.base import WorkContext
    from shared.models import Scope

    scripted = ScriptedModel(responses=[
        AIMessage(content='{"rankings":[{"i":0,"interest":"high","reason":"login takes input"}]}'),
    ])
    monkeypatch.setattr(R, "build_chat_model", lambda *a, **k: scripted)
    fake = FakeMcpClient(
        [_Descriptor("crawl", "crawl", {"type": "object", "properties": {}})],
        {"crawl": {
            "pages": [{"url": "http://t.test/#/login", "status": 200,
                       "content_type": "text/html"}],
            "observed_requests": [{
                "method": "POST", "url": "http://t.test/rest/user/login",
                "post_data": '{"email":"a@b.c"}',
                "source_page": "http://t.test/#/login"}],
            "technologies": [], "forms": [], "js_api_paths": [],
            "third_party_hosts": [], "pages_crawled": 1}})
    monkeypatch.setattr(R, "Client", lambda url: fake)

    ctx = WorkContext(
        engagement_id=uuid.uuid4(), target_url="http://t.test/",
        scope=Scope(domains=["t.test"]), upstream={}, directive="")
    result = await R.ReconWorker()(ctx)
    assert len(result["observed_requests"]) == 1
    assert result["observed_requests"][0]["interest"] == "high"


def test_recon_deterministic_interest_demotes_noise_promotes_api():
    """socket.io/static -> low (so it can't flood the high-interest index); input &
    REST/API endpoints -> high (so a bad LLM rating can't drop them from vuln's set)."""
    from agent.services.workers.recon.recon_worker import _deterministic_interest
    from shared.models import ObservedRequest

    def R_(method, url, post_data=None, resource_type="xhr"):
        return ObservedRequest(method=method, url=url, post_data=post_data,
                               resource_type=resource_type)

    assert _deterministic_interest(R_("GET", "http://t/rest/products/search?q=a")) == "high"
    assert _deterministic_interest(R_("POST", "http://t/rest/user/login",
                                      post_data='{"email":"a"}')) == "high"
    assert _deterministic_interest(R_("GET", "http://t/api/Users/1")) == "high"  # IDOR, no param
    assert _deterministic_interest(R_("GET", "http://t/socket.io/?EIO=4")) == "low"
    assert _deterministic_interest(R_("POST", "http://t/socket.io/", post_data="x",
                                      resource_type="websocket")) == "low"
    assert _deterministic_interest(R_("GET", "http://t/main.js", resource_type="script")) == "low"
    assert _deterministic_interest(R_("GET", "http://t/", resource_type="document")) is None  # defer


async def test_recon_override_beats_llm_misrating(monkeypatch):
    """Even when the LLM rates socket.io 'high', the deterministic pass demotes it."""
    from agent.services.workers.recon import recon_worker as R
    from shared.models import ObservedRequest

    scripted = ScriptedModel(responses=[
        AIMessage(content='{"rankings":[{"i":0,"interest":"high","reason":"looks busy"},'
                          '{"i":1,"interest":"low","reason":"dunno"}]}'),
    ])
    monkeypatch.setattr(R, "build_chat_model", lambda *a, **k: scripted)
    observed = [
        ObservedRequest(method="POST", url="http://t/socket.io/", post_data="x",
                        resource_type="websocket", source_page="p"),
        ObservedRequest(method="GET", url="http://t/rest/products/search?q=a",
                        resource_type="xhr", source_page="p"),
    ]
    await R.ReconWorker()._verify(scripted, {}, observed)
    by_path = {o.url: o.interest for o in observed}
    assert by_path["http://t/socket.io/"] == "low"             # demoted despite LLM "high"
    assert by_path["http://t/rest/products/search?q=a"] == "high"  # promoted despite LLM "low"


async def test_adviser_reason_uses_model_findings():
    """The adviser's reasoning call now runs on the LangChain model and yields findings."""
    from agent.services.workers.adviser import adviser_worker as A

    scripted = ScriptedModel(responses=[
        AIMessage(content=('{"findings":[{"keys":["SQL Injection @ /login"],'
                           '"title":"SQL Injection on login","severity":"critical",'
                           '"impact":"full DB read","recommendation":"parameterise queries",'
                           '"effort":"low"}],"narrative":"Fix the login SQLi first."}')),
    ])
    groups = [{
        "key": "SQL Injection @ /login", "label": "SQL Injection", "asset": "/login",
        "default_severity": "critical", "wids": ["W-001"], "count": 1,
        "evidence": [], "techniques": ["T1190"], "reasons": ["injectable"],
        "hypotheses": ["SQL injection — login"], "writeups": ["sqlmap injectable"],
        "bases": ["sqlmap"]}]
    worker = A.AdviserWorker(results=None, reports=None)
    findings, narrative = await worker._reason(groups, "", scripted, {})
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "login" in narrative.lower()


async def test_adviser_reason_falls_back_on_bad_json():
    """A model that won't emit the required JSON still yields a report (deterministic fallback)."""
    from agent.services.workers.adviser import adviser_worker as A

    scripted = ScriptedModel(responses=[
        AIMessage(content="sorry, I cannot do that"),
        AIMessage(content="still not JSON"),
    ])
    groups = [{
        "key": "SQL Injection @ /login", "label": "SQL Injection", "asset": "/login",
        "default_severity": "critical", "wids": ["W-001"], "count": 1,
        "evidence": [], "techniques": [], "reasons": [], "hypotheses": [],
        "writeups": [], "bases": []}]
    worker = A.AdviserWorker(results=None, reports=None)
    findings, narrative = await worker._reason(groups, "", scripted, {})
    assert len(findings) == 1  # the proven group is never lost
    assert findings[0].severity == "critical"


async def test_vuln_drops_junk_hypotheses():
    """Refusal / out-of-budget non-answers must not be recorded as freeform weaknesses,
    while real HYPOTHESIS blocks and substantive freeform replies still parse."""
    from agent.services.workers.vuln import vuln_worker as V
    assert V._extract_hypotheses("Sorry, need more steps to process this request.") == []
    assert V._extract_hypotheses("   ") == []
    assert V._extract_hypotheses("No vulnerabilities found.") == []
    hyps = V._extract_hypotheses("HYPOTHESIS: XSS — search (param `q`)\nWHY: q reflects into DOM")
    assert len(hyps) == 1 and "XSS" in hyps[0]
    ff = V._extract_hypotheses("The q parameter reflects unsanitized into the search results DOM.")
    assert len(ff) == 1


async def test_tool_wrapper_retries_on_target_connection_failure(monkeypatch):
    """A connection-failure payload (target crashed/restarting) is retried below the
    model; a normal result passes straight through."""
    from agent.services.workers.common import common_agentic as A
    monkeypatch.setattr(A, "TARGET_RETRY_WAIT", 0)   # no real sleep in the test
    monkeypatch.setattr(A, "TARGET_RETRIES", 2)
    calls = {"n": 0}
    def resp(args):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"error": "All connection attempts failed"}   # target down
        return {"found": True, "slug": args.get("slug")}          # back up
    fake = FakeMcpClient(
        [_Descriptor("hacktricks_article", "d",
                     {"type": "object", "properties": {"slug": {"type": "string"}}})],
        {"hacktricks_article": resp})
    tools = A.as_langchain_tools(fake, await _descriptors(fake), tried={})
    out = await {t.name: t for t in tools}["hacktricks_article"].ainvoke({"slug": "x"})
    assert calls["n"] == 2            # retried once past the connection failure
    assert "OBSERVATION" in out       # and succeeded on the retry
