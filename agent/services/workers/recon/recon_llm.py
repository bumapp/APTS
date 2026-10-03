"""LLM adapter for the phased recon loop.

Our recon drives an OpenAI-style loop (``{role, content, tool_calls}`` dicts +
OpenAI function-tool schemas). This project standardises on a LangChain chat model
(``shared.llm.build_chat_model`` → ChatOpenAI) so every call is traced by Langfuse.

This module bridges the two: it converts our dict messages ↔ LangChain messages and
runs each turn through the project's model with ``run_config`` (Langfuse callbacks +
engagement session). The recon graph still OWNS tool execution — the model only
proposes tool calls, which we read back as our dict format.
"""
from __future__ import annotations

import json
import os

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from shared.llm import build_chat_model, run_config

CONTEXT_BUDGET_CHARS = int(os.environ.get("APTS_RECON_CONTEXT_CHARS", "18000"))


def mcp_tools_to_openai(tools) -> list[dict]:
    """MCP tool descriptors → OpenAI function-tool schemas (ChatOpenAI.bind_tools)."""
    return [
        {"type": "function", "function": {
            "name": t.name,
            "description": t.description or "",
            "parameters": t.input_schema or {"type": "object", "properties": {}},
        }}
        for t in tools
    ]


def compact(messages: list[dict], tried: dict[str, str]) -> list[dict]:
    """Shrink the conversation without discarding progress: keep system + task + the
    last (assistant, tool) pair, collapse the middle into a 'progress so far' note."""
    size = sum(len(str(m.get("content") or "")) for m in messages)
    if size <= CONTEXT_BUDGET_CHARS or len(messages) <= 4:
        return messages
    system, task = messages[0], messages[1]
    tail = messages[-2:]
    progress = "PROGRESS SO FAR (compacted to save context):\n" + "\n".join(
        f"- {s} -> {o}" for s, o in tried.items())
    return [system, task, {"role": "user", "content": progress}, *tail]


def _to_lc(messages: list[dict]):
    out = []
    for m in messages:
        role, content = m.get("role"), m.get("content") or ""
        if role == "system":
            out.append(SystemMessage(content=content))
        elif role == "user":
            out.append(HumanMessage(content=content))
        elif role == "assistant":
            tcs = []
            for i, tc in enumerate(m.get("tool_calls") or []):
                fn = tc.get("function", {})
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except json.JSONDecodeError:
                    args = {}
                tcs.append({"name": fn.get("name", ""), "args": args,
                            "id": tc.get("id") or f"call_{i}"})
            out.append(AIMessage(content=content, tool_calls=tcs))
        elif role == "tool":
            out.append(ToolMessage(content=content, tool_call_id=m.get("tool_call_id") or "call_0"))
    return out


def _from_lc(msg) -> dict:
    tcs = []
    for i, tc in enumerate(getattr(msg, "tool_calls", None) or []):
        tcs.append({"id": tc.get("id") or f"call_{i}",
                    "function": {"name": tc.get("name", ""),
                                 "arguments": json.dumps(tc.get("args") or {}, default=str)}})
    content = msg.content if isinstance(msg.content, str) else str(msg.content or "")
    return {"role": "assistant", "content": content, "tool_calls": tcs or None}


class ReconLLM:
    """One per engagement. ``chat`` runs a turn on the project's LangChain model with
    Langfuse config; pass ``tools`` (OpenAI schemas) on the loop turns, omit for grading."""

    def __init__(self, engagement_id: str) -> None:
        self._cfg = run_config(engagement_id=engagement_id, agent="recon")

    async def chat(self, messages: list[dict], *, tools: list[dict] | None = None,
                   max_tokens: int | None = None) -> dict:
        model = build_chat_model("recon", max_tokens=max_tokens)
        if tools:
            model = model.bind_tools(tools)
        resp = await model.ainvoke(_to_lc(messages), config=self._cfg)
        return _from_lc(resp)
