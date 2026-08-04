"""LLM access for the agents.

One client, shared by every agent, deliberately written against the
OpenAI-compatible chat-completions shape rather than any vendor SDK. DeepSeek,
Hugging Face TGI, vLLM, and OpenAI itself all speak it, so switching provider is
a base-URL and model-name change in ``config/`` — no agent code moves. The PRD
names Hugging Face Inference Endpoints as the target stack; DeepSeek is what
this is pointed at today, and the abstraction is what keeps that a deployment
detail instead of a rewrite.

Plain ``httpx`` rather than the ``openai`` package: the request is one JSON POST,
httpx is already pinned for every service, and a vendor SDK would pull a
dependency tree into a container that needs none of it.

Secret handling follows the same rule as the database password (see
``shared/db.py``) — the key is read from a mounted file, never from an
environment variable, so it stays out of ``docker inspect`` and out of any crash
dump that prints the environment.

Three behaviours worth knowing about, all verified against the live API:

* **Thinking is on by default.** ``deepseek-v4-flash`` spends completion tokens
  on hidden reasoning before it writes anything. With a small ``max_tokens`` the
  budget is consumed entirely by reasoning and ``content`` comes back *empty*
  with ``finish_reason="length"`` — a silent empty result, not an error.
  :data:`REASONING_EFFORT` defaults to ``"none"`` for that reason.
* **JSON mode is honoured** via ``response_format``, but the model still has to
  be told the schema in the prompt; the flag only constrains syntax.
* **Reasoning tokens are billed as output.** They are reported separately in
  ``usage`` and logged below, because otherwise a thinking model's true cost is
  invisible.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger("shared.llm")


class LlmError(Exception):
    """Raised when the model cannot be reached or will not answer usefully."""


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

BASE_URL = os.environ.get("APTS_LLM_BASE_URL", "https://api.deepseek.com")
MODEL = os.environ.get("APTS_LLM_MODEL", "deepseek-v4-flash")
KEY_FILE = os.environ.get("APTS_LLM_KEY_FILE", "/run/secrets/llm_api_key")

# "none" disables the model's hidden reasoning pass. Agents ask for structured
# JSON against a fixed schema, which is not work that benefits from chain of
# thought — and leaving it on makes token spend, latency, and the empty-content
# failure above all unpredictable. Set to "low"/"medium"/"high" for an agent
# that genuinely needs deliberation (Exploitation is the plausible candidate).
REASONING_EFFORT = os.environ.get("APTS_LLM_REASONING_EFFORT", "none")

REQUEST_TIMEOUT = float(os.environ.get("APTS_LLM_TIMEOUT", "120"))
MAX_TOKENS = int(os.environ.get("APTS_LLM_MAX_TOKENS", "4000"))


def load_api_key(path: str | None = None) -> str:
    """Read the provider API key from its mounted secret file."""
    path = path or KEY_FILE
    try:
        with open(path, "r", encoding="utf-8") as fh:
            key = fh.read().strip()
    except FileNotFoundError as exc:
        raise LlmError(
            f"LLM API key file not found at {path!r}. Was the secret mounted? "
            f"See docker-compose.yml and bootstrap/."
        ) from exc
    if not key:
        raise LlmError(f"LLM API key file {path!r} is empty")
    return key


@dataclass(frozen=True)
class Usage:
    """Token accounting for one call, so cost stays visible per agent."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0
    cached_tokens: int = 0

    @classmethod
    def from_response(cls, usage: dict[str, Any]) -> "Usage":
        details = usage.get("completion_tokens_details") or {}
        prompt_details = usage.get("prompt_tokens_details") or {}
        return cls(
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            reasoning_tokens=details.get("reasoning_tokens") or 0,
            cached_tokens=prompt_details.get("cached_tokens") or 0,
        )


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

class LlmClient:
    """Chat-completions client scoped to one agent.

    ``agent_name`` only labels log lines, but it is what makes per-agent token
    spend legible when six of these are running at once.
    """

    def __init__(self, agent_name: str, client: httpx.AsyncClient | None = None,
                 api_key: str | None = None, model: str = MODEL,
                 base_url: str = BASE_URL) -> None:
        self._agent = agent_name
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "LlmClient":
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
        if self._api_key is None:
            self._api_key = load_api_key()
        return self

    async def __aexit__(self, *exc_info) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def complete_json(self, system: str, user: str,
                            max_tokens: int = MAX_TOKENS,
                            retries: int = 1) -> dict[str, Any]:
        """Ask for a JSON object and return it parsed.

        ``system`` must describe the expected schema. JSON mode constrains the
        model to emit syntactically valid JSON; it does not tell it what shape
        to use, and a schema-less prompt in JSON mode reliably produces
        well-formed objects with the wrong keys.

        Retries once on unparseable output — a rare but real failure that is
        cheaper to retry than to escalate. Structural validation against the
        agent's artifact schema is a separate concern and happens at the
        Guardrails output checkpoint, not here.
        """
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": max_tokens,
            "stream": False,
        }
        if REASONING_EFFORT:
            payload["reasoning_effort"] = REASONING_EFFORT

        last_error: str = ""
        for attempt in range(retries + 1):
            content, usage = await self._post(payload)
            self._log_usage(usage, attempt)

            if not content.strip():
                # Almost always the thinking-mode budget exhaustion described in
                # the module docstring. Say so, rather than reporting empty JSON.
                last_error = (
                    f"model returned empty content "
                    f"(reasoning_tokens={usage.reasoning_tokens}, "
                    f"max_tokens={max_tokens}); raise max_tokens or set "
                    f"APTS_LLM_REASONING_EFFORT=none")
                continue

            try:
                parsed = json.loads(content)
            except json.JSONDecodeError as exc:
                last_error = f"model returned unparseable JSON: {exc}"
                log.warning("[%s] %s", self._agent, last_error)
                continue

            if not isinstance(parsed, dict):
                last_error = f"expected a JSON object, got {type(parsed).__name__}"
                continue

            return parsed

        raise LlmError(f"[{self._agent}] {last_error}")

    # ----------------------------------------------------------------- #

    async def _post(self, payload: dict[str, Any]) -> tuple[str, Usage]:
        if self._client is None or self._api_key is None:
            raise LlmError(
                "LlmClient used outside its async context; "
                "use 'async with LlmClient(...) as llm:'")

        try:
            response = await self._client.post(
                f"{self._base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}",
                         "Content-Type": "application/json"},
                json=payload,
            )
        except httpx.HTTPError as exc:
            raise LlmError(f"[{self._agent}] LLM request failed: {exc}") from exc

        if response.status_code != 200:
            # Deliberately does not include the response body verbatim in the
            # exception message beyond a short prefix — provider errors can echo
            # request content, and agent prompts carry engagement detail.
            raise LlmError(
                f"[{self._agent}] LLM returned HTTP {response.status_code}: "
                f"{response.text[:200]}")

        body = response.json()
        try:
            message = body["choices"][0]["message"]
        except (KeyError, IndexError) as exc:
            raise LlmError(f"[{self._agent}] malformed LLM response") from exc

        return message.get("content") or "", Usage.from_response(body.get("usage", {}))

    def _log_usage(self, usage: Usage, attempt: int) -> None:
        log.info(
            "[%s] llm call model=%s attempt=%d tokens in=%d (cached=%d) "
            "out=%d (reasoning=%d)",
            self._agent, self._model, attempt + 1,
            usage.prompt_tokens, usage.cached_tokens,
            usage.completion_tokens, usage.reasoning_tokens,
        )
