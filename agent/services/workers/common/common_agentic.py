"""LangGraph plumbing shared by the agentic worker loops.

The vuln/mitre/exploit/script loops are genuine tool-driving loops: the model
thinks, calls an MCP tool on the native MCP server, reads the result, and decides
the next move. This module holds only what they share — the pure helpers
(repeat-call signatures, scope checks, directive framing) and the LangGraph glue:
wrapping the native MCP-v2 tools as LangChain tools and bounding a running
conversation. Loop-wide config lives in :mod:`.constants`; the stage-specific
prompts, guards and control flow live in each worker next to the agent.

Two deliberate choices
----------------------
* **We do NOT use ``langchain-mcp-adapters``.** That package targets the MCP v1
  SDK (``mcp.shared.session`` / ``mcp.server.fastmcp``); this repo pins the MCP v2
  SDK and its workers already speak ``mcp.Client`` (v2). Rather than fork the whole
  stack back to v1, we wrap the v2 ``Client`` ourselves — a StructuredTool per MCP
  tool whose coroutine calls ``client.call_tool``. Fewer dependencies, and it
  composes with ``create_react_agent`` exactly the same way.

* **The domain guards stay.** The repeat-call guard, the credential injection for
  in-scope proving tools, and the evidence capture the exploit loop depends on are
  preserved as hooks on the tool wrapper (``transform`` / ``on_call`` / ``observe``),
  not lost to a prebuilt agent.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any, Awaitable, Callable  # noqa: F401 (Awaitable re-exported for hooks)
from urllib.parse import urlparse

from langchain_core.messages import (AIMessage, BaseMessage, HumanMessage,
                                      SystemMessage, ToolMessage)
from langchain_core.tools import StructuredTool

from agent.services.workers.common.common_constants import (CONTEXT_BUDGET_CHARS,
                                                      MCP_URL)

log = logging.getLogger("agent.workers.agentic")

# Target-resilience: a flaky/overloaded target can crash and restart mid-proof (a
# fragile training app under fuzzing does this; so can a rate-limited real target).
# When a tool call comes back looking like a connection failure, wait briefly and
# retry the SAME call a few times rather than handing the model a false dead end —
# the target is usually back within seconds. A normal result (even "not injectable")
# never matches, so non-target tools (knowledge base) are unaffected.
TARGET_RETRIES = int(os.environ.get("APTS_TOOL_CONN_RETRIES", "3"))
TARGET_RETRY_WAIT = float(os.environ.get("APTS_TOOL_CONN_RETRY_WAIT", "3"))
_CONN_FAIL_MARKERS = (
    "connection refused", "connection_refused", "econnrefused", "err_connection",
    "connection reset", "econnreset", "all connection attempts failed",
    "max retries exceeded", "failed to establish", "connection aborted",
    "socket hang up", "connection error", "remotedisconnected", "server disconnect")


def _looks_like_conn_failure(payload: Any) -> bool:
    """True if a tool payload looks like the target dropped the connection."""
    try:
        s = json.dumps(payload, default=str).lower()
    except Exception:  # noqa: BLE001
        s = str(payload).lower()
    return any(m in s for m in _CONN_FAIL_MARKERS)


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def sig(name: str, args: dict) -> str:
    """Stable signature for a tool call, to detect exact repeats."""
    return name + ":" + json.dumps(args, sort_keys=True, default=str)


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


# --------------------------------------------------------------------------- #
# MCP-v2 → LangChain tools
# --------------------------------------------------------------------------- #

# Type aliases for the tool-wrapper hooks.
Transform = Callable[[str, dict], dict]              # (name, args) -> args actually sent
OnCall = Callable[[str, dict, Any], None]            # (name, orig_args, payload) -> None
Observe = Callable[[str, Any, dict[str, str]], str]  # (name, payload, tried) -> obs text


def _default_observe(name: str, payload: Any, tried: dict[str, str]) -> str:
    """Compact default observation: the tool payload plus what has been tried.

    Workers with richer coaching (vuln, exploit) pass their own ``observe``.
    """
    body = json.dumps(payload, default=str)[:3000]
    tried_lines = "; ".join(f"{s} -> {o}" for s, o in tried.items()) or "(none yet)"
    return f"OBSERVATION from {name}:\n{body}\n---\nAlready tried: {tried_lines}"


def _payload_of(result: Any) -> Any:
    """Extract the structured payload from an MCP call result (v2 Client).

    Mirrors every worker's ``out.structured_content or {...content...}`` line.
    """
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        return structured
    content = getattr(result, "content", None) or []
    return {"content": [getattr(b, "text", str(b)) for b in content]}


def _schema_of(descriptor: Any) -> dict:
    """The tool's JSON input schema, tolerant of v1/v2 attribute spelling."""
    schema = (getattr(descriptor, "input_schema", None)
              or getattr(descriptor, "inputSchema", None))
    return schema or {"type": "object", "properties": {}}


def as_langchain_tools(client: Any, descriptors: list, *,
                       tried: dict[str, str] | None = None,
                       outcome: Callable[[str, Any], str] | None = None,
                       observe: Observe = _default_observe,
                       transform: Transform | None = None,
                       on_call: OnCall | None = None) -> list[StructuredTool]:
    """Wrap MCP tool descriptors as LangChain tools bound to ``client``.

    ``tried`` is the shared repeat-call ledger (signature -> one-line outcome); an
    exact repeat short-circuits with a nudge instead of re-running the tool, the
    same guard every hand-rolled loop implemented. ``transform`` may rewrite the
    args actually sent (the exploit loop uses it to attach the engagement session
    to in-scope calls); ``on_call`` sees the *original* args and the raw payload
    for evidence capture. ``observe`` formats the ToolMessage the model reads.
    """
    ledger = tried if tried is not None else {}

    def _make(descriptor: Any) -> StructuredTool:
        name = descriptor.name

        async def _run(**kwargs: Any) -> str:
            args = dict(kwargs)
            key = sig(name, args)
            if key in ledger:
                return (f"You already ran this exact call: {name} -> {ledger[key]}. "
                        f"Change the arguments or use a different tool, or conclude now.")
            sent = transform(name, args) if transform else args
            # Absorb transient target-connection failures (target crashed/restarting)
            # below the model: wait and retry the same call a few times. Only
            # connection-shaped failures retry; any real result passes straight through.
            payload = None
            for _try in range(TARGET_RETRIES + 1):
                result = await client.call_tool(name, sent)
                payload = _payload_of(result)
                if _try < TARGET_RETRIES and _looks_like_conn_failure(payload):
                    log.warning("%s: target connection failure, retry %d/%d in %.0fs",
                                name, _try + 1, TARGET_RETRIES, TARGET_RETRY_WAIT)
                    await asyncio.sleep(TARGET_RETRY_WAIT)
                    continue
                break
            # The bookkeeping callbacks (on_call/outcome) are side effects — a bug
            # in one must never turn a successful tool result into a model-facing
            # error (that once happened via a callback arity mismatch). Guard them.
            if on_call:
                try:
                    on_call(name, args, payload)
                except Exception as exc:  # noqa: BLE001
                    log.warning("on_call failed for %s: %s", name, exc)
            try:
                ledger[key] = outcome(name, payload) if outcome else "ok"
            except Exception as exc:  # noqa: BLE001
                log.warning("outcome() failed for %s: %s", name, exc)
                ledger[key] = "ok"
            try:
                return observe(name, payload, ledger)
            except Exception as exc:  # noqa: BLE001 — fall back to the default format
                log.warning("observe() failed for %s: %s", name, exc)
                return _default_observe(name, payload, ledger)

        return StructuredTool.from_function(
            coroutine=_run, name=name,
            description=(descriptor.description or "")[:1024],
            args_schema=_schema_of(descriptor))

    return [_make(d) for d in descriptors]


# --------------------------------------------------------------------------- #
# Conversation bounding
# --------------------------------------------------------------------------- #

def _content_len(messages: list) -> int:
    return sum(len(str(getattr(m, "content", "") or "")) for m in messages)


def compacting_hook(budget_chars: int):
    """A ``create_react_agent`` ``pre_model_hook`` that bounds the running context.

    Keeps the system prompt and the task turn, collapses the middle into a note,
    and keeps the largest recent suffix that fits — **without ever splitting an
    ``AIMessage`` that carries ``tool_calls`` from its ``ToolMessage`` replies.**
    A model that emits *parallel* tool calls (DeepSeek does) produces one
    assistant turn with several tool_calls followed by several ToolMessages;
    cutting between them makes the next model call fail with
    ``INVALID_CHAT_HISTORY``. So after trimming from the front we drop any leading
    orphan ``ToolMessage`` whose assistant turn was trimmed away.

    Returns ``{"llm_input_messages": [...]}`` so it trims what the model sees
    without rewriting graph state (the LangGraph contract for a non-destructive
    hook).
    """
    def _hook(state: dict) -> dict:
        messages: list[BaseMessage] = state.get("messages", [])
        if _content_len(messages) <= budget_chars or len(messages) <= 3:
            return {"llm_input_messages": messages}
        # Always keep the system prompt (if present) and the task (first human).
        prefix: list[BaseMessage] = []
        i = 0
        if messages and isinstance(messages[0], SystemMessage):
            prefix.append(messages[0]); i = 1
        if i < len(messages) and isinstance(messages[i], HumanMessage):
            prefix.append(messages[i]); i += 1
        rest = list(messages[i:])
        budget_left = budget_chars - _content_len(prefix)
        # Drop from the front until the recent suffix fits...
        while rest and _content_len(rest) > budget_left:
            rest.pop(0)
        # ...then drop any leading orphan ToolMessages (their AIMessage is gone).
        while rest and isinstance(rest[0], ToolMessage):
            rest.pop(0)
        note = ([HumanMessage(content="(earlier steps omitted to save context)")]
                if len(rest) < len(messages) - len(prefix) else [])
        return {"llm_input_messages": [*prefix, *note, *rest]}
    return _hook


def to_lc_messages(system: str, user: str) -> list[BaseMessage]:
    """The opening two-turn conversation as LangChain messages."""
    return [SystemMessage(content=system), HumanMessage(content=user)]


def final_text(result: dict) -> str:
    """The assistant's final text from a ``create_react_agent`` result."""
    for msg in reversed(result.get("messages", [])):
        if isinstance(msg, AIMessage):
            content = msg.content
            if isinstance(content, list):  # some providers return content blocks
                return "".join(b.get("text", "") for b in content
                               if isinstance(b, dict)).strip()
            return (content or "").strip()
    return ""


def message_text(msg: Any) -> str:
    """Flatten a single chat message's content to text (string or block list)."""
    content = getattr(msg, "content", msg)
    if isinstance(content, list):
        return "".join(b.get("text", "") for b in content
                       if isinstance(b, dict)).strip()
    return (content or "").strip() if isinstance(content, str) else str(content)


__all__ = [
    "MCP_URL", "CONTEXT_BUDGET_CHARS",
    "sig", "host_in_scope", "directive_block",
    "as_langchain_tools", "compacting_hook", "to_lc_messages", "final_text",
    "message_text",
    "AIMessage", "HumanMessage", "SystemMessage", "ToolMessage",
]
