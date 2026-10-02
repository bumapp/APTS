"""Central prompt registry — prompts by id, Langfuse-backed with in-repo fallback.

Best practice (per KELA's `platform-ai-monorepo`): prompt text lives in a store
(Langfuse), fetched by label, linked to the trace so a regression is traceable to
a prompt version — never inlined in worker code. This module is that seam.

Transitional design: each prompt id is registered with an in-repo default so the
stack runs unchanged before anything is published to Langfuse. Resolution order:

1. Langfuse configured and the id exists there under the active label → that
   version wins, and its prompt object is returned for trace-linking.
2. Langfuse configured but the id is missing / fetch fails → the in-repo default
   (Langfuse's own ``fallback`` path; never raises, never links).
3. Langfuse off → the in-repo default.
4. No default registered and nothing to fall back to → :class:`KeyError` (a
   fail-closed readiness gate: a required prompt with no source must not run).

End state: publish these prompts to Langfuse under the label, then the defaults
become pure fallbacks. See docs/langgraph-migration.md.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from shared import settings
from shared.llm import _client

log = logging.getLogger("shared.prompts")

_DEFAULTS: dict[str, str] = {}


def register(prompt_id: str, default_text: str) -> str:
    """Register a prompt's in-repo default. Returns the text (for one-line use)."""
    _DEFAULTS[prompt_id] = default_text
    return default_text


@dataclass(frozen=True)
class ResolvedPrompt:
    """A resolved prompt: its text, and (when live) the object to link to a trace."""
    id: str
    text: str
    trace_prompt: object | None  # langfuse prompt object, or None for a default


def get(prompt_id: str) -> ResolvedPrompt:
    """Resolve a prompt by id (see module docstring for the resolution order)."""
    default = _DEFAULTS.get(prompt_id)
    client = _client()  # None when Langfuse is off / unavailable
    if client is None:
        if default is None:
            raise KeyError(
                f"prompt {prompt_id!r} is not registered and Langfuse is off")
        return ResolvedPrompt(prompt_id, default, None)
    lf = settings.load().langfuse
    try:
        prompt = client.get_prompt(
            prompt_id, label=lf.prompt_label, fallback=default,
            cache_ttl_seconds=lf.prompt_ttl_seconds, max_retries=lf.prompt_max_retries)
    except Exception as exc:  # noqa: BLE001 — get_prompt with no fallback raises
        if default is None:
            raise KeyError(
                f"required prompt {prompt_id!r} is not published in Langfuse "
                f"under label {lf.prompt_label!r} and has no default") from exc
        log.warning("prompt %s fetch failed, using default: %s", prompt_id, exc)
        return ResolvedPrompt(prompt_id, default, None)

    text = prompt.prompt if isinstance(getattr(prompt, "prompt", None), str) else default
    # Don't link a fallback (network-miss) prompt object to the trace — it isn't a
    # real published version. Only link a genuinely-fetched prompt.
    is_fallback = getattr(prompt, "is_fallback", False)
    return ResolvedPrompt(prompt_id, text or default or "",
                          None if is_fallback else prompt)
