"""Third LLM backend: a local OpenAI-compatible server (llama.cpp) on the host.

A drop-in for :class:`shared.llm.LlmClient` — same async context manager plus
``complete_json(system, user) -> dict`` — selected with ``APTS_LLM_PROVIDER=local``.
It points at a server running on the machine hosting Docker, reached from inside
the agent containers as ``host.docker.internal``. Today that is a llama.cpp
server serving ``qwen3-8b`` at ``:18080``.

Three things differ from the DeepSeek client (:mod:`shared.llm`) and shape this
file:

* **No API key.** A local server needs none, so there is no mounted-secret file
  and no ``Authorization`` header.
* **Host networking.** The default base URL is ``host.docker.internal`` — the
  address a container uses to reach a port on the Docker host — not a public API.
* **Thinking is disabled.** qwen3 defaults to a reasoning pass that, under a
  small token budget, spends the whole completion thinking and returns empty
  ``content`` (verified against this very server). The request sends
  ``chat_template_kwargs.enable_thinking = false`` so the model answers directly;
  any ``<think>`` block that still slips through is stripped before parsing, and
  an empty answer is retried rather than returned as empty JSON.

It is otherwise the ordinary OpenAI ``/v1/chat/completions`` shape, so it stays a
thin ``httpx`` POST with no client library.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx

from shared import trace
from shared.llm import LlmError
from shared.llm_hf import _extract_json  # reuse the tolerant JSON extractor

log = logging.getLogger("shared.llm_local")

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# Default points at the in-project llama.cpp service (docker-compose service
# "llama", profile "localllm") reached over apts-net. Override with
# host.docker.internal:18080 to talk to a llama.cpp server on the host instead.
BASE_URL = os.environ.get("APTS_LOCAL_LLM_BASE_URL", "http://llama:8080/v1")
MODEL = os.environ.get("APTS_LOCAL_LLM_MODEL", "qwen3-8b")
# The server reports n_ctx=4096, so keep the output budget well under it to leave
# room for the prompt. Raise if a stage's JSON is being truncated mid-object.
MAX_TOKENS = int(os.environ.get("APTS_LOCAL_LLM_MAX_TOKENS", "2048"))
TEMPERATURE = float(os.environ.get("APTS_LOCAL_LLM_TEMPERATURE", "0.2"))
# Generous: a quantized 8B on CPU is slow, and a stage's single call must not be
# cut off mid-generation by the client.
REQUEST_TIMEOUT = float(os.environ.get("APTS_LOCAL_LLM_TIMEOUT", "300"))


class LocalLlmClient:
    """Chat-completions JSON client for a local OpenAI-compatible server.

    Interface-compatible with :class:`shared.llm.LlmClient`. ``agent_name`` only
    labels log and trace rows.
    """

    def __init__(self, agent_name: str, client: httpx.AsyncClient | None = None,
                 model: str = MODEL, base_url: str = BASE_URL) -> None:
        self._agent = agent_name
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "LocalLlmClient":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
        log.info("[%s] local LLM client ready (%s @ %s)",
                 self._agent, self._model, self._base_url)
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def complete_json(self, system: str, user: str,
                            max_tokens: int = MAX_TOKENS,
                            retries: int = 1) -> dict[str, Any]:
        """Ask the local server for a JSON object and return it parsed.

        Mirrors :meth:`shared.llm.LlmClient.complete_json`: ``system`` carries
        the schema, the reply is expected to be one JSON object, and the call is
        retried once on empty/unparseable output before the stage is failed.
        """
        if self._client is None:
            raise LlmError(
                "LocalLlmClient used outside its async context; "
                "use 'async with LocalLlmClient(...) as llm:'")

        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": int(max_tokens),
            "temperature": TEMPERATURE,
            "stream": False,
            # qwen3: no reasoning pass, so the whole budget is not spent thinking.
            "chat_template_kwargs": {"enable_thinking": False},
        }

        last_error = ""
        for attempt in range(retries + 1):
            started = time.perf_counter()
            try:
                content = await self._post(payload)
            except LlmError as exc:
                self._trace(system, user, "", attempt, started, error=str(exc))
                raise
            self._trace(system, user, content, attempt, started)
            log.info("[%s] local call model=%s attempt=%d reply_chars=%d",
                     self._agent, self._model, attempt + 1, len(content or ""))

            if not (content or "").strip():
                last_error = "model returned empty content (thinking budget?)"
                continue
            parsed = _extract_json(content)
            if parsed is None:
                last_error = "model reply contained no parseable JSON object"
                continue
            if not isinstance(parsed, dict):
                last_error = f"expected a JSON object, got {type(parsed).__name__}"
                continue
            return parsed

        raise LlmError(f"[{self._agent}] {last_error}")

    # ----------------------------------------------------------------- #

    async def _post(self, payload: dict[str, Any]) -> str:
        try:
            response = await self._client.post(
                f"{self._base_url}/chat/completions",
                headers={"Content-Type": "application/json"},
                json=payload,
            )
        except httpx.HTTPError as exc:
            raise LlmError(
                f"[{self._agent}] local LLM request failed: {exc}") from exc

        if response.status_code != 200:
            raise LlmError(
                f"[{self._agent}] local LLM returned HTTP {response.status_code}: "
                f"{response.text[:200]}")

        body = response.json()
        try:
            return body["choices"][0]["message"].get("content") or ""
        except (KeyError, IndexError) as exc:
            raise LlmError(f"[{self._agent}] malformed local LLM response") from exc

    def _trace(self, system: str, user: str, content: str, attempt: int,
               started: float, error: str = "") -> None:
        trace.record(
            "llm_call",
            {
                "backend": "local_openai",
                "base_url": self._base_url,
                "model": self._model,
                "attempt": attempt + 1,
                "system_prompt": system,
                "user_prompt": user,
                "raw_response": content,
                **({"error": error} if error else {}),
            },
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
