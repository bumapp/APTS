"""Alternative LLM backend: a Hugging Face Space reached over gradio_client.

A drop-in for :class:`shared.llm.LlmClient`. It exposes the same surface — an
async context manager plus :meth:`complete_json(system, user) -> dict` — so any
worker that holds an ``LlmClient`` works unchanged with this instead. Which one
an agent gets is decided once, in ``agent.main``, by ``APTS_LLM_PROVIDER``.

Why a second file rather than a branch inside ``shared.llm``: the two backends
share almost nothing at the wire level. The OpenAI-compatible client speaks a
chat API with roles, a JSON-mode flag, and structured token accounting. A Space
exposes one text-in/text-out function — ``predict(prompt, max_new_tokens,
temperature)`` returning a bare string — with no roles, no JSON mode, and no
usage numbers. Three consequences shape everything here:

* **System and user are folded into one prompt.** There is no role separation to
  preserve, so they are concatenated with the same "reply with ONLY JSON"
  contract the workers already put in their system text, reinforced once more at
  the end.

* **JSON is recovered from free text, defensively.** Without a JSON-mode flag the
  reply is whatever the model emitted. In practice this Space returns clean JSON,
  but a reasoning model (Qwen3) can wrap an answer in a ``<think>`` block or a
  Markdown fence, so both are stripped and the first balanced ``{...}`` object is
  extracted before parsing. A reply with no object fails the stage the same way
  malformed JSON does in the other client — never silently.

* **gradio_client is synchronous.** ``predict`` and even client construction do
  blocking network I/O, so both run in a worker thread; the event loop the agent
  serves its HTTP surface on is never blocked on the model.

Token accounting is absent because the Space does not report it; the trace still
records the full prompt and raw reply, which is what the flow file needs.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any

from shared import trace
from shared.llm import MAX_TOKENS, LlmError

log = logging.getLogger("shared.llm_hf")

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

HF_SPACE = os.environ.get("APTS_HF_SPACE", "Er33k/HIT")
HF_API_NAME = os.environ.get("APTS_HF_API_NAME", "/generate")
HF_TEMPERATURE = float(os.environ.get("APTS_HF_TEMPERATURE", "0.2"))

# The Space's slider maxes out somewhere; and a 14B model generating thousands of
# tokens is slow. The workers ask for up to MAX_TOKENS, but that is a ceiling on
# an OpenAI-style completion — here it is capped to something a Space can produce
# in a reasonable time. Raise APTS_HF_MAX_NEW_TOKENS if a stage's JSON is being
# truncated mid-object.
HF_MAX_NEW_TOKENS = int(os.environ.get("APTS_HF_MAX_NEW_TOKENS", "2048"))

# Optional — a public Space needs no token. Read from the environment only; unlike
# the provider API key this is not required, so there is no mounted-secret path.
HF_TOKEN = os.environ.get("APTS_HF_TOKEN") or os.environ.get("HF_TOKEN")

_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE_OPEN = re.compile(r"^```(?:json)?\s*", re.IGNORECASE)
_FENCE_CLOSE = re.compile(r"\s*```$")


def _extract_json(text: str) -> Any:
    """Pull the first JSON value out of a model reply, tolerating wrapping.

    Handles, in order: a ``<think>…</think>`` reasoning preamble, a Markdown code
    fence, and leading/trailing prose around a single ``{…}`` object. Returns the
    parsed value, or ``None`` if nothing parseable is found — the caller treats
    ``None`` as a failed generation, never as an empty result.
    """
    if not text:
        return None
    text = _THINK_BLOCK.sub("", text).strip()
    text = _FENCE_CLOSE.sub("", _FENCE_OPEN.sub("", text)).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Fall back to scanning for the first balanced object. String-aware so a brace
    # inside a JSON string value does not throw the depth count off.
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


class HuggingFaceLlmClient:
    """Chat-shaped JSON client backed by a Hugging Face Space.

    Interface-compatible with :class:`shared.llm.LlmClient`: build it with an
    agent name, enter it as an async context manager, and call
    :meth:`complete_json`. ``agent_name`` only labels logs and trace rows.
    """

    def __init__(self, agent_name: str, space: str = HF_SPACE,
                 api_name: str = HF_API_NAME, token: str | None = HF_TOKEN,
                 temperature: float = HF_TEMPERATURE,
                 max_new_tokens: int = HF_MAX_NEW_TOKENS,
                 client: Any | None = None) -> None:
        self._agent = agent_name
        self._space = space
        self._api_name = api_name
        self._token = token
        self._temperature = temperature
        self._max_new_tokens = max_new_tokens
        self._client = client
        self._owns_client = client is None

    async def __aenter__(self) -> "HuggingFaceLlmClient":
        if self._client is None:
            # Client construction handshakes with the Space over the network.
            self._client = await asyncio.to_thread(self._build_client)
        log.info("[%s] HF space client ready (%s)", self._agent, self._space)
        return self

    async def __aexit__(self, *exc_info) -> None:
        # gradio_client holds no long-lived connection to close; drop the handle.
        if self._owns_client:
            self._client = None

    def _build_client(self) -> Any:
        from gradio_client import Client
        if not self._token:
            return Client(self._space)
        # The auth-token keyword was renamed between gradio_client versions
        # (``hf_token`` in the 0.x line, ``token`` since). Try the current name,
        # fall back to the old one, so this survives a dependency bump.
        try:
            return Client(self._space, token=self._token)
        except TypeError:
            return Client(self._space, hf_token=self._token)

    async def complete_json(self, system: str, user: str,
                            max_tokens: int = MAX_TOKENS,
                            retries: int = 1) -> dict[str, Any]:
        """Ask the Space for a JSON object and return it parsed.

        Mirrors :meth:`shared.llm.LlmClient.complete_json`: ``system`` describes
        the schema, the reply is expected to be one JSON object, and the call is
        retried once on an unparseable answer before the stage is failed. The
        ``max_tokens`` argument is honoured as an upper bound but capped to the
        Space's configured ``max_new_tokens`` budget.
        """
        if self._client is None:
            raise LlmError(
                "HuggingFaceLlmClient used outside its async context; "
                "use 'async with HuggingFaceLlmClient(...) as llm:'")

        prompt = self._compose(system, user)
        max_new = min(int(max_tokens), self._max_new_tokens)

        last_error = ""
        for attempt in range(retries + 1):
            started = time.perf_counter()
            try:
                raw = await asyncio.to_thread(self._predict, prompt, max_new)
            except Exception as exc:  # noqa: BLE001 — any client/transport fault
                self._trace(prompt, "", attempt, started, error=str(exc))
                raise LlmError(f"[{self._agent}] HF space call failed: {exc}") from exc

            self._trace(prompt, raw, attempt, started)
            log.info("[%s] hf call space=%s attempt=%d reply_chars=%d",
                     self._agent, self._space, attempt + 1, len(raw or ""))

            parsed = _extract_json(raw or "")
            if parsed is None:
                last_error = "model reply contained no parseable JSON object"
                continue
            if not isinstance(parsed, dict):
                last_error = f"expected a JSON object, got {type(parsed).__name__}"
                continue
            return parsed

        raise LlmError(f"[{self._agent}] {last_error}")

    # ----------------------------------------------------------------- #

    @staticmethod
    def _compose(system: str, user: str) -> str:
        return (
            f"{system}\n\n{user}\n\n"
            "Return ONLY the JSON object described above. Do not wrap it in "
            "Markdown, do not add commentary, and do not include a <think> block."
        )

    def _predict(self, prompt: str, max_new_tokens: int) -> str:
        result = self._client.predict(
            prompt=prompt,
            max_new_tokens=max_new_tokens,
            temperature=self._temperature,
            api_name=self._api_name,
        )
        return str(result)

    def _trace(self, prompt: str, raw: str, attempt: int, started: float,
               error: str = "") -> None:
        trace.record(
            "llm_call",
            {
                "backend": "huggingface_space",
                "space": self._space,
                "attempt": attempt + 1,
                # Folded prompt kept under the same key the flow renderer reads;
                # there is no separate system/user role at this backend.
                "system_prompt": "",
                "user_prompt": prompt,
                "raw_response": raw,
                "temperature": self._temperature,
                **({"error": error} if error else {}),
            },
            duration_ms=int((time.perf_counter() - started) * 1000),
        )
