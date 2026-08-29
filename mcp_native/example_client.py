"""How to drive the standalone MCP server — two ways.

    pip install mcp httpx
    python -m mcp_native.example_client            # (A) plain MCP client
    python -m mcp_native.example_client --loop      # (B) AI tool-calling loop

(A) is the raw protocol: connect, discover tools, call one.
(B) wires the MCP tool into an LLM tool-calling loop against the project's local
    llama.cpp server (host.docker.internal:18080 / localhost:18080). The model
    decides the request; MCP executes it; the result is fed back; repeat until
    the model answers. This is the "agent loop" the current pipeline does NOT do.

Nothing here touches the six-agent pipeline — it is a self-contained demo.
"""
from __future__ import annotations

import asyncio
import json
import sys

import httpx
from mcp import Client

from mcp_native.server import mcp as server

LLM_URL = "http://localhost:18080/v1/chat/completions"
LLM_MODEL = "qwen3-8b"


# --------------------------------------------------------------------------- #
# (A) Plain MCP usage — connect, list, call.
# --------------------------------------------------------------------------- #
async def plain_usage() -> None:
    # `Client` accepts the server object (in-process), a StdioServerParameters
    # (subprocess), or a URL string (streamable-HTTP). Same API either way.
    async with Client(server) as client:
        tools = await client.list_tools()
        print("Discovered tools:", [t.name for t in tools.tools])

        result = await client.call_tool(
            "http_request",
            {"url": "http://localhost:18080/health", "method": "GET"},
        )
        print("Tool result:", result.structured_content)


# --------------------------------------------------------------------------- #
# (B) AI tool-calling loop — MCP tools handed to the model, model drives them.
# --------------------------------------------------------------------------- #
def _mcp_tools_to_openai(mcp_tools) -> list[dict]:
    """Convert MCP tool definitions into the OpenAI `tools` schema the llama.cpp
    server understands. This is the whole bridge: MCP describes the tools, the
    model's chat API consumes that same description."""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description or "",
                "parameters": t.input_schema or {"type": "object", "properties": {}},
            },
        }
        for t in mcp_tools
    ]


async def ai_loop(goal: str) -> None:
    async with Client(server) as client:
        tools = (await client.list_tools()).tools
        openai_tools = _mcp_tools_to_openai(tools)

        messages = [
            {"role": "system", "content":
                "You are an agent with one tool: http_request. Use it to achieve "
                "the user's goal, then answer. Call tools; do not guess responses."},
            {"role": "user", "content": goal},
        ]

        async with httpx.AsyncClient(timeout=300) as llm:
            for step in range(6):  # bounded loop — never spin forever
                resp = await llm.post(LLM_URL, json={
                    "model": LLM_MODEL,
                    "messages": messages,
                    "tools": openai_tools,
                    "tool_choice": "auto",
                    "stream": False,
                    "chat_template_kwargs": {"enable_thinking": False},
                })
                msg = resp.json()["choices"][0]["message"]
                messages.append(msg)

                calls = msg.get("tool_calls")
                if not calls:
                    print(f"\n[final answer after {step} tool calls]\n{msg.get('content')}")
                    return

                # The model asked to call the tool(s). Execute each via MCP and
                # feed the result back as a `tool` message, then loop.
                for call in calls:
                    name = call["function"]["name"]
                    args = json.loads(call["function"]["arguments"] or "{}")
                    print(f"[step {step}] model -> {name}({args})")
                    out = await client.call_tool(name, args)
                    payload = out.structured_content or {
                        "content": [b.text for b in out.content]}
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "content": json.dumps(payload)[:4000],
                    })
            print("\n[stopped: hit the step limit]")


def main() -> None:
    if "--loop" in sys.argv:
        asyncio.run(ai_loop(
            "Fetch http://localhost:18080/v1/models and tell me the model id served."))
    else:
        asyncio.run(plain_usage())


if __name__ == "__main__":
    main()
