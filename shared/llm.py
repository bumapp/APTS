"""LangChain chat-model factory + Langfuse wiring for the agentic loops.

This is the single LLM access module for the stack. Every agentic loop
(recon/vuln/mitre/exploit/script/adviser) drives its model through the
``BaseChatModel`` this builds, so the loop can run on LangGraph and every model +
tool call is observable in Langfuse.

Why one class covers every backend
-----------------------------------
Every runtime backend this stack targets — AWS Bedrock's OpenAI surface, a local
llama.cpp server, DeepSeek, OpenAI itself — speaks the OpenAI
``/v1/chat/completions`` protocol. A single :class:`~langchain_openai.ChatOpenAI`
configured from the same environment variables therefore covers all of them;
there is no per-provider subclass. (A non-OpenAI backend such as a Hugging Face
Space would need its own ``BaseChatModel`` — there is none wired in today.)

Provider quirks preserved from the old hand-rolled loop
-------------------------------------------------------
* **enable_thinking=false for a keyless local llama.** llama.cpp honours
  ``chat_template_kwargs`` to disable the reasoning pass; a hosted endpoint 400s
  on the unknown field. So it is sent via ``extra_body`` only when there is no
  bearer token.
* **The bearer token comes from a file, not a baked-in env var.** Read from
  ``APTS_LOOP_LLM_KEY`` or the mounted secret, never from the image — same rule
  as the DB password (see ``shared/db.py``).

Langfuse is optional and fails open
-----------------------------------
:func:`langfuse_callbacks` returns an empty list unless Langfuse is both installed
and configured (``LANGFUSE_PUBLIC_KEY`` / ``LANGFUSE_SECRET_KEY`` present). A
missing package or missing keys must never break a stage that did its work — the
same rule the Postgres trace (``shared/trace.py``) already follows.
"""
from __future__ import annotations

import contextlib
import logging
import os
import re
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

from shared import settings

log = logging.getLogger("shared.llm")


# --------------------------------------------------------------------------- #
# Configuration — validated once at boot (shared/settings.py), not scattered env.
# Secrets (the API key) are the exception: they stay read from env/secret file at
# point of use, never through the settings object.
# --------------------------------------------------------------------------- #

def _base_url(chat_url: str | None = None) -> str:
    """Strip a trailing ``/chat/completions`` so ChatOpenAI can append its own.

    Defaults to the configured loop LLM URL (``APTS_LOOP_LLM_URL``).
    """
    if chat_url is None:
        chat_url = settings.load().loop.llm_url
    parts = urlsplit(chat_url)
    path = parts.path
    for suffix in ("/chat/completions", "/chat/completions/"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    return urlunsplit((parts.scheme, parts.netloc, path or "/v1", "", ""))


def _api_key() -> str:
    """Bearer token for a hosted endpoint (empty string for a local llama).

    Env first (``APTS_LOOP_LLM_KEY``), then the mounted secret so in-container
    workers need no extra env. Kept out of the settings schema on purpose: a
    secret must not live in a config object.
    """
    key = os.environ.get("APTS_LOOP_LLM_KEY")
    if key:
        return key
    try:
        with open(os.environ.get("APTS_LLM_KEY_FILE",
                                 "/run/secrets/llm_api_key")) as fh:
            return fh.read().strip()
    except OSError:
        return ""


# --------------------------------------------------------------------------- #
# Chat model
# --------------------------------------------------------------------------- #

def build_chat_model(agent_name: str, *, max_tokens: int | None = None,
                     temperature: float | None = None):
    """Return a LangChain chat model for one agent's loop.

    ``agent_name`` is attached as OpenAI ``metadata``/tags so Langfuse and any
    other callback can attribute spend per agent. ``max_tokens`` mirrors the
    per-loop cap the workers pass.

    The import is local so that importing this module (e.g. in a unit test that
    only exercises URL/key resolution) does not require ``langchain_openai`` to be
    installed.
    """
    from langchain_openai import ChatOpenAI

    cfg = settings.load().loop
    key = _api_key()
    extra_body: dict = {}
    if not key:
        # Keyless == local llama: disable its reasoning pass.
        extra_body["chat_template_kwargs"] = {"enable_thinking": False}

    # Temperature is DELIBERATELY unset unless APTS_LOOP_LLM_TEMPERATURE is given:
    # several newer reasoning models reject it, and the old httpx loop never sent
    # one. cfg.temperature is None when unset.
    resolved_temp = cfg.temperature if temperature is None else temperature
    kwargs: dict = dict(
        model=cfg.model,
        base_url=_base_url(),
        # ChatOpenAI requires a non-empty key; a keyless local server ignores the
        # Authorization header, so a placeholder is harmless and keeps the client
        # from raising before the first call.
        api_key=key or "not-needed",
        timeout=cfg.timeout,
        # Absorb TRANSIENT gateway failures (HTTP 429/500/502/503/504, connection
        # drops) with the SDK's exponential backoff. These are retried only when the
        # request did not complete, so no tool side-effect is duplicated. Without
        # this a single transient 500 killed a whole proof (caught as a loop error →
        # not confirmed) — and at exploit concurrency 10 we hit the gateway hard.
        # Logic the AGENT loop owns (bad verdict, step budget) is unaffected: those
        # are successful responses, not retryable errors. Tune APTS_LLM_MAX_RETRIES.
        max_retries=int(os.environ.get("APTS_LLM_MAX_RETRIES", "4")),
        max_tokens=max_tokens,
        extra_body=extra_body or None,
        metadata={"agent": agent_name},
        tags=[f"agent:{agent_name}"],
    )
    # store=false: the hosted Bedrock/OpenAI-compatible endpoints otherwise retain
    # request/response payloads server-side (~30 days). This stack drives a target
    # with attacker payloads and extracts loot/credentials, so opt out of retention.
    # `store` is a first-class ChatOpenAI param (pass it top-level, not via
    # model_kwargs). Sent only to a keyed (hosted) endpoint — a local llama has no
    # such retention and may reject it. Set APTS_LLM_STORE=1 to opt back in.
    if key and not cfg.store_opt_in:
        kwargs["store"] = False
    if resolved_temp is not None:
        kwargs["temperature"] = resolved_temp
    return ChatOpenAI(**kwargs)


# --------------------------------------------------------------------------- #
# Langfuse — optional observability, fails open.
# --------------------------------------------------------------------------- #

def langfuse_enabled() -> bool:
    """True only if Langfuse credentials are present in the environment.

    ``APTS_LANGFUSE_DISABLED=1`` forces it off regardless — an operator switch
    for a run that must send no prompt text off-box, mirroring
    ``APTS_TRACE_ENABLED=0`` for the Postgres trace.
    """
    if settings.load().langfuse.disabled:
        return False
    return bool(os.environ.get("LANGFUSE_PUBLIC_KEY")
                and os.environ.get("LANGFUSE_SECRET_KEY"))


# --------------------------------------------------------------------------- #
# Payload masking — this is a pentest stack: tool calls carry the engagement
# session (auth cookies), attacker payloads, and extracted loot/credentials. The
# LangChain→Langfuse integration would otherwise serialise all of that verbatim
# into traces. A ``mask`` on the Langfuse client scrubs every input/output/
# metadata value before it leaves the process.
#
# This is key-based + pattern-based redaction, not a full "lengths-only" rebuild:
# it redacts values under sensitive keys in structured tool args, and secret-
# shaped substrings in serialised strings. It does NOT strip a credential the
# model happens to write into free-form reasoning text — for a hard guarantee,
# follow the monorepo's approach of emitting diagnostics with values dropped
# (see docs/langgraph-migration.md). Tune with APTS_LANGFUSE_EXTRA_MASK_KEYS.
# --------------------------------------------------------------------------- #

_SENSITIVE_KEYS = {
    "cookie", "cookies", "set-cookie", "authorization", "auth", "token", "tokens",
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "x-api-key",
    "credential", "credentials", "bearer", "session", "headers", "loot",
}
_SENSITIVE_KEYS |= set(settings.load().langfuse.extra_mask_keys)
_REDACTED = "***REDACTED***"
_SECRET_LINE = re.compile(
    r"(?i)\b(cookie|set-cookie|authorization|token|password|passwd|pwd|secret|"
    r"api[-_]?key|bearer)\b\s*[:=]\s*\S+")


def _scrub_str(value: str) -> str:
    return _SECRET_LINE.sub(lambda m: f"{m.group(1)}: {_REDACTED}", value)


def _redact(value, depth: int = 0):
    """Recursively redact sensitive keys (in dicts) and secret-shaped strings."""
    if depth > 8:
        return value
    if isinstance(value, dict):
        return {k: (_REDACTED if str(k).lower() in _SENSITIVE_KEYS
                    else _redact(v, depth + 1)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v, depth + 1) for v in value]
    if isinstance(value, str):
        return _scrub_str(value)
    return value


def _mask(data=None, **_):
    """Langfuse ``mask`` callback: applied to every traced value before export."""
    try:
        return _redact(data)
    except Exception:  # noqa: BLE001 — a mask error must never leak the raw value
        return "***REDACTED (mask error)***"


@lru_cache(maxsize=1)
def _client():
    """The Langfuse client, built once with the masking function, or None.

    Constructing it also registers the process-singleton the CallbackHandler
    reads via ``get_client()``, so the handler inherits the mask. Any failure
    (not installed, misconfigured) degrades to None — tracing never breaks a stage.
    """
    if not langfuse_enabled():
        return None
    try:
        from langfuse import Langfuse
        return Langfuse(mask=_mask)
    except Exception as exc:  # noqa: BLE001
        log.warning("Langfuse client unavailable: %s", exc)
        return None


@lru_cache(maxsize=1)
def _handler():
    """Build the Langfuse callback handler once, or None if unavailable.

    Cached because the handler holds a flush thread; one per process is correct.
    Depends on :func:`_client` having registered the masked singleton first.
    """
    if _client() is None:
        return None
    try:
        from langfuse.langchain import CallbackHandler
        return CallbackHandler()
    except Exception as exc:  # noqa: BLE001 — observability must never break a stage
        log.warning("Langfuse callback disabled: %s", exc)
        return None


def langfuse_callbacks() -> list:
    """Callbacks to pass as ``config={"callbacks": langfuse_callbacks()}``.

    Empty list when Langfuse is off, so every ``ainvoke`` can pass it
    unconditionally. Combine with per-run metadata at the call site.
    """
    handler = _handler()
    return [handler] if handler is not None else []


def run_config(engagement_id: str = "", agent: str = "", **metadata) -> dict:
    """A LangChain ``RunnableConfig`` carrying the Langfuse callback + trace tags.

    Threads the engagement and agent into Langfuse as a session id / tags so a
    run's traces group the way the Postgres ``agent_trace`` rows already do.
    """
    meta = {k: v for k, v in {"engagement_id": engagement_id, "agent": agent,
                              **metadata}.items() if v}
    cfg: dict = {"callbacks": langfuse_callbacks()}
    if meta:
        cfg["metadata"] = meta
    if engagement_id:
        # Langfuse reads these reserved metadata keys to group a trace.
        cfg["metadata"]["langfuse_session_id"] = str(engagement_id)
    if agent:
        cfg["run_name"] = f"{agent}-loop"
    return cfg


# --------------------------------------------------------------------------- #
# One run = one trace.
# --------------------------------------------------------------------------- #

@contextlib.contextmanager
def trace_run(name: str, run_input=None, prompt=None, engagement_id: str = ""):
    """Open ONE Langfuse root span for the duration of a multi-turn run.

    Our loops make several model calls per run (a react graph invoke, then a
    reflection turn, or a per-weakness proof loop). Without a root span each of
    those bare ``model.ainvoke`` calls becomes its own trace, so a run fragments
    into one-trace-per-turn with blank top-level I/O. Wrapping the whole run in an
    active observation makes every callback-created span nest under it — one run,
    one trace — and gives the trace list its Input/Output (set input here, call
    :func:`set_run_output` before the block exits).

    Yields the span (or None when Langfuse is off) and never raises: a failure to
    open the span degrades to an un-nested run rather than breaking the stage.
    Session/user grouping still rides the ``metadata`` set by :func:`run_config`.
    """
    client = _client()
    span_cm = None
    if client is not None:
        obs_kwargs = {"name": name, "as_type": "span", "input": run_input}
        if prompt is not None:
            # Links every generation in the run to this prompt version, so a
            # "which prompt version regressed?" question is answerable from traces.
            obs_kwargs["prompt"] = prompt
        if engagement_id:
            # One tree for the WHOLE engagement: seed a deterministic trace id from
            # the engagement id so every stage — each a separate process — writes
            # its spans into the SAME Langfuse trace instead of one trace per loop.
            # The per-stage span opened here becomes a top-level node of that single
            # tree, and the per-request spans nest under it.
            try:
                obs_kwargs["trace_context"] = {
                    "trace_id": client.create_trace_id(seed=str(engagement_id))}
            except Exception as exc:  # noqa: BLE001 — fall back to an un-seeded trace
                log.debug("trace_id seed failed: %s", exc)
        try:
            span_cm = client.start_as_current_observation(**obs_kwargs)
        except Exception as exc:  # noqa: BLE001
            log.warning("Langfuse trace_run(%s) failed to start: %s", name, exc)
            span_cm = None
    if span_cm is None:
        yield None
        return
    with span_cm as span:
        yield span


def set_run_output(span, output) -> None:
    """Set the root span's output (→ the trace's Output column). None-safe."""
    if span is None:
        return
    try:
        span.update(output=output)
    except Exception as exc:  # noqa: BLE001
        log.debug("Langfuse set_run_output failed: %s", exc)


def flush() -> None:
    """Flush pending Langfuse spans. Call in a stage's ``finally``.

    Agent stages are short-lived tasks; without an explicit flush the exporter's
    background batch can be lost when the task ends. No-op when Langfuse is off.
    """
    client = _client()
    if client is None:
        return
    try:
        client.flush()
    except Exception as exc:  # noqa: BLE001
        log.debug("Langfuse flush failed: %s", exc)
