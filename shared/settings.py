"""Validated, boot-time configuration — one schema instead of scattered os.environ.

Best practice (per KELA's `platform-ai-monorepo`): read config once, validate it
at boot, fail fast on a bad value, and keep the knobs a component reads in one
typed place rather than sprinkled through modules. This is the Python equivalent:
a pydantic model whose fields map to the ``APTS_*`` environment variables, loaded
once via :func:`load` and cached.

Two rules it follows deliberately:

* **Non-secret only.** API keys and tokens are NOT here — they stay read from
  their mounted secret files / env at the point of use (see ``shared/llm.py``).
  "A secret settable from a config object ends up logged"; the monorepo keeps
  secrets out of the config schema for the same reason.
* **Backward compatible.** The env var names and defaults are unchanged, so
  compose files and ``.env`` keep working. A malformed value (e.g.
  ``APTS_LOOP_LLM_TIMEOUT=abc``) now raises one clear aggregated error at load
  time instead of an obscure ``ValueError`` deep inside a request.

Scope: this centralises the LLM / agentic-loop / Langfuse / trace groups that the
LangGraph path reads. Per-tool knobs (sqlmap paths, per-worker step counts) fold
in the same way over time — see docs/langgraph-migration.md.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from pydantic import BaseModel, Field, ValidationError


# --------------------------------------------------------------------------- #
# Env parsing helpers — an empty string counts as "unset" (shadows a fallback),
# matching how the modules read env today.
# --------------------------------------------------------------------------- #

def _raw(name: str):
    v = os.environ.get(name)
    return None if v is None or v == "" else v


def _bool(name: str, default: bool) -> bool:
    v = _raw(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _present(mapping: dict) -> dict:
    """Drop keys whose value is None so pydantic falls back to the field default."""
    return {k: v for k, v in mapping.items() if v is not None}


# --------------------------------------------------------------------------- #
# Grouped settings
# --------------------------------------------------------------------------- #

class LoopSettings(BaseModel):
    """The agentic tool-loop / LangGraph model config (agentic.py, shared/llm.py)."""
    llm_url: str = "http://localhost:18080/v1/chat/completions"
    model: str = "qwen3-8b"
    timeout: float = Field(300, gt=0)
    # None = unset → provider default (never forced; several models reject it).
    temperature: Optional[float] = Field(None, ge=0, le=2)
    # None = unset → build_chat_model applies the key-dependent default
    # (store=false for a hosted/keyed endpoint). True = opt back in to retention.
    store_opt_in: bool = False
    context_chars: int = Field(16000, gt=0)
    prompt_chars: int = Field(6000, gt=0)
    mcp_url: str = "http://mcp-native:9000/mcp"


class LangfuseSettings(BaseModel):
    """Langfuse observability (non-secret knobs; keys stay in env/secret files)."""
    disabled: bool = False
    prompt_label: str = "production"
    prompt_ttl_seconds: int = Field(60, ge=0)
    prompt_max_retries: int = Field(2, ge=0)
    extra_mask_keys: tuple[str, ...] = ()


class TraceSettings(BaseModel):
    """Postgres execution-trace caps (shared/trace.py)."""
    enabled: bool = True
    max_field_chars: int = Field(8000, gt=0)
    max_items: int = Field(200, gt=0)
    max_depth: int = Field(6, gt=0)


class Settings(BaseModel):
    """The composed, validated configuration for this process."""
    loop: LoopSettings = Field(default_factory=LoopSettings)
    langfuse: LangfuseSettings = Field(default_factory=LangfuseSettings)
    trace: TraceSettings = Field(default_factory=TraceSettings)

    @classmethod
    def from_env(cls) -> "Settings":
        """Build from the ``APTS_*`` environment, validating types and ranges.

        Raises :class:`RuntimeError` (not a raw ``ValidationError``) with every
        bad key listed, so a misconfigured deploy fails fast and legibly at boot.
        """
        extra_mask = tuple(
            k.strip().lower()
            for k in (os.environ.get("APTS_LANGFUSE_EXTRA_MASK_KEYS", "").split(","))
            if k.strip())
        try:
            return cls(
                loop=LoopSettings(**_present({
                    "llm_url": _raw("APTS_LOOP_LLM_URL"),
                    "model": _raw("APTS_LOOP_LLM_MODEL"),
                    "timeout": _raw("APTS_LOOP_LLM_TIMEOUT"),
                    "temperature": _raw("APTS_LOOP_LLM_TEMPERATURE"),
                    "store_opt_in": _bool("APTS_LLM_STORE", False),
                    "context_chars": _raw("APTS_LOOP_CONTEXT_CHARS"),
                    "prompt_chars": _raw("APTS_LOOP_PROMPT_CHARS"),
                    "mcp_url": _raw("APTS_MCP_URL"),
                })),
                langfuse=LangfuseSettings(**_present({
                    "disabled": _bool("APTS_LANGFUSE_DISABLED", False),
                    "prompt_label": _raw("APTS_LANGFUSE_PROMPT_LABEL"),
                    "prompt_ttl_seconds": _raw("APTS_LANGFUSE_PROMPT_TTL"),
                    "prompt_max_retries": _raw("APTS_LANGFUSE_PROMPT_RETRIES"),
                    "extra_mask_keys": extra_mask,
                })),
                trace=TraceSettings(**_present({
                    "enabled": _bool("APTS_TRACE_ENABLED", True),
                    "max_field_chars": _raw("APTS_TRACE_MAX_FIELD_CHARS"),
                    "max_items": _raw("APTS_TRACE_MAX_ITEMS"),
                    "max_depth": _raw("APTS_TRACE_MAX_DEPTH"),
                })),
            )
        except ValidationError as exc:
            problems = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
                for e in exc.errors())
            raise RuntimeError(
                f"invalid APTS_* configuration: {problems}") from exc


@lru_cache(maxsize=1)
def load() -> Settings:
    """The process's settings, parsed and validated once."""
    return Settings.from_env()
