"""Shared plumbing for the agentic worker loops (Vulnerability, Exploitation).

Both stages are genuine tool-driving loops: the model thinks, calls an MCP tool
on the native MCP server, reads the result, and decides the next move. This
module holds only what they share — where the model and the MCP server live, how
one chat/completions turn is sent (auth, hosted-vs-local quirks, keeping
tool-call arguments valid for strict endpoints), and how a running conversation
is compacted when it grows too large. The stage-specific prompts, guards and
control flow live in the worker modules themselves, next to the agent.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlparse

import httpx

# The native MCP server (tools) and the model endpoint. Same env the stack uses.
MCP_URL = os.environ.get("APTS_MCP_URL", "http://mcp-native:9000/mcp")
LLM_URL = os.environ.get("APTS_LOOP_LLM_URL",
                         "http://localhost:18080/v1/chat/completions")
LLM_MODEL = os.environ.get("APTS_LOOP_LLM_MODEL", "qwen3-8b")
LLM_TIMEOUT = float(os.environ.get("APTS_LOOP_LLM_TIMEOUT", "300"))
CONTEXT_BUDGET_CHARS = int(os.environ.get("APTS_LOOP_CONTEXT_CHARS", "16000"))


def _api_key() -> str:
    """Bearer token for a hosted endpoint (empty for local llama). Env first,
    then the mounted secret so the in-container workers need no extra env."""
    key = os.environ.get("APTS_LOOP_LLM_KEY")
    if key:
        return key
    try:
        with open(os.environ.get("APTS_LLM_KEY_FILE",
                                 "/run/secrets/llm_api_key")) as fh:
            return fh.read().strip()
    except OSError:
        return ""


LLM_KEY = _api_key()
HEADERS = {"Authorization": f"Bearer {LLM_KEY}"} if LLM_KEY else {}
# llama.cpp honours chat_template_kwargs to disable thinking; a hosted endpoint
# rejects unknown fields, so send it only when talking to local llama (no key).
LLAMA_EXTRA = {} if LLM_KEY else {"chat_template_kwargs": {"enable_thinking": False}}


def mcp_tools_to_openai(tools) -> list[dict]:
    """Convert MCP tool descriptors to OpenAI function-tool schemas."""
    return [
        {"type": "function", "function": {
            "name": t.name,
            "description": t.description or "",
            "parameters": t.input_schema or {"type": "object", "properties": {}},
        }}
        for t in tools
    ]


def sig(name: str, args: dict) -> str:
    """Stable signature for a tool call, to detect exact repeats."""
    return name + ":" + json.dumps(args, sort_keys=True, default=str)


# --------------------------------------------------------------------------- #
# Authenticated runs — carry the engagement's credentials onto tool requests.
# Generic: credentials are {headers, cookies, basic_auth}; nothing here knows or
# cares what any value *is* (a token is just a header/cookie value).
# --------------------------------------------------------------------------- #

def auth_headers(credentials: dict | None) -> dict[str, str]:
    """Turn engagement credentials into request headers (incl. a Cookie header).

    ``headers`` pass through as-is; ``cookies`` ([{name,value},...]) become one
    ``Cookie`` header. ``basic_auth`` is left to the caller. Empty dict when there
    are no credentials, so callers can merge unconditionally."""
    creds = credentials or {}
    out: dict[str, str] = dict(creds.get("headers") or {})
    cookies = creds.get("cookies") or []
    pairs = [f"{c.get('name')}={c.get('value')}" for c in cookies
             if isinstance(c, dict) and c.get("name")]
    if pairs:
        out["Cookie"] = "; ".join(pairs)
    return out


def host_in_scope(url: str, domains, target_url: str = "") -> bool:
    """True if ``url``'s host is the target host or matches an in-scope domain.

    So credentials are only ever attached to hosts the engagement is allowed to
    touch — a token is never sent off-target. Supports a leading-wildcard domain
    (``*.example.com``) and a bare host (``juice-shop``)."""
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    if target_url and host == (urlparse(target_url).hostname or "").lower():
        return True
    for d in (domains or []):
        d = str(d).lstrip("*.").lower()
        if d and (host == d or host.endswith("." + d)):
            return True
    return False


def directive_block(directive: str) -> str:
    """Format the orchestrator's start prompt for prepending to a worker's first
    user message. Empty string when there is no directive (agent-driven mode), so
    every worker can prepend it unconditionally without changing its prompt."""
    directive = (directive or "").strip()
    if not directive:
        return ""
    return ("ORCHESTRATOR DIRECTIVE (guidance for this stage; the structured data "
            "below is still authoritative):\n" + directive + "\n\n")


def _canonicalise_tool_args(msg: dict) -> dict:
    """Re-dump each tool-call's arguments as valid JSON before it is echoed back.

    Hosted endpoints (Bedrock) re-parse the arguments string and 400 on empty or
    malformed JSON, which the model occasionally emits. Mutates and returns msg.
    """
    for tc in (msg.get("tool_calls") or []):
        fn = tc.get("function") or {}
        raw = (fn.get("arguments") or "").strip()
        try:
            fn["arguments"] = json.dumps(json.loads(raw)) if raw else "{}"
        except (json.JSONDecodeError, TypeError):
            fn["arguments"] = "{}"
    return msg


async def chat(llm: httpx.AsyncClient, messages: list[dict], *,
               tools: list[dict] | None = None, tool_choice=None,
               max_tokens: int | None = None) -> dict:
    """Send one chat/completions turn and return the assistant message.

    Adds the auth header, the local-only fields, the tools/tool_choice and an
    optional token cap; canonicalises any tool-call arguments on the way out.
    Raises httpx.HTTPError on a transport/HTTP error (the caller decides how to
    report it — see :func:`err_body`).
    """
    body: dict = {"model": LLM_MODEL, "messages": messages, "stream": False,
                  **LLAMA_EXTRA}
    if tools is not None:
        body["tools"] = tools
        body["tool_choice"] = tool_choice or "auto"
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    resp = await llm.post(LLM_URL, headers=HEADERS, json=body)
    resp.raise_for_status()
    return _canonicalise_tool_args(resp.json()["choices"][0]["message"])


def err_body(exc: httpx.HTTPError) -> str:
    """The response body from an HTTP error, for diagnostics."""
    return getattr(getattr(exc, "response", None), "text", "") or ""


def compact(messages: list[dict], tried: dict[str, str]) -> list[dict]:
    """Shrink the conversation without discarding progress.

    Collapse the middle into a 'progress so far' note built from what was tried,
    keeping the system prompt, the task turn, and the last (assistant, tool) pair
    so tool-call/response pairing stays valid.
    """
    size = sum(len(str(m.get("content") or "")) for m in messages)
    if size <= CONTEXT_BUDGET_CHARS or len(messages) <= 4:
        return messages
    system, task = messages[0], messages[1]
    tail = messages[-2:]
    progress = "PROGRESS SO FAR (compacted to save context):\n" + "\n".join(
        f"- {s} -> {o}" for s, o in tried.items())
    return [system, task, {"role": "user", "content": progress}, *tail]
