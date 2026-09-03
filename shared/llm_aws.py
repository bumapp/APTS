"""OpenAI-compatible LLM controller for a hosted model (e.g. AWS Bedrock).

Selected with ``APTS_LLM_PROVIDER=aws`` (also ``bedrock`` / ``openai``). It is a
thin specialisation of :class:`shared.llm.LlmClient` — the same chat-completions
protocol DeepSeek/vLLM/OpenAI all speak — with two conveniences for a hosted
endpoint like Bedrock's ``/openai/v1``:

* the model defaults to the Bedrock Qwen id, and
* the API key may come straight from an environment variable
  (``APTS_LLM_API_KEY`` or ``OPENAI_API_KEY``) instead of a mounted secret file,
  so it works the same on the host and in a container.

Configure with:
    APTS_LLM_PROVIDER=aws
    APTS_LLM_BASE_URL=https://bedrock-runtime.<region>.amazonaws.com/openai/v1
    APTS_LLM_MODEL=qwen.qwen3-coder-480b-a35b-instruct   # the default
    APTS_LLM_API_KEY=<bearer token>                       # or mount llm_api_key

The rest — retries, JSON extraction, per-agent token accounting — is inherited
unchanged, so every agent worker uses it exactly like the other backends.
"""
from __future__ import annotations

import os

import httpx

from shared.llm import BASE_URL, LlmClient, REQUEST_TIMEOUT, load_api_key

# Bedrock's OpenAI-compatible Qwen3-Coder MoE (480B total / 35B active).
AWS_MODEL = os.environ.get("APTS_LLM_MODEL", "qwen.qwen3-coder-480b-a35b-instruct")


def _key_from_env() -> str | None:
    """Prefer an env-supplied bearer token; fall back to the mounted secret."""
    return os.environ.get("APTS_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY")


class AwsLlmClient(LlmClient):
    """LlmClient pinned to the hosted OpenAI-compatible model."""

    def __init__(self, agent_name: str, client: httpx.AsyncClient | None = None,
                 api_key: str | None = None, model: str = AWS_MODEL,
                 base_url: str = BASE_URL) -> None:
        super().__init__(agent_name, client=client,
                         api_key=api_key or _key_from_env(),
                         model=model, base_url=base_url)

    async def __aenter__(self) -> "AwsLlmClient":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
        # Env key first (Bedrock bearer token); mounted secret file as a fallback.
        if self._api_key is None:
            self._api_key = _key_from_env() or load_api_key()
        return self
