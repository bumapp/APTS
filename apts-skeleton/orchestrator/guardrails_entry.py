"""Entry-checkpoint Guardrails — Characterization §7.1.

Skeleton implementation: these checks are *placeholders*.  They do enough to
demonstrate the pattern (rejecting obviously malformed input, blocking a target
that is not on the allowlist) and to make sure the request flow reaches the
right place, but they do not yet plug in the ``guardrails-ai`` library or a
proper prompt-injection classifier.  That is a follow-up for the modelling
phase.
"""
from __future__ import annotations

import logging
import os
import re
from urllib.parse import urlparse

from shared.models import EngagementSpec

log = logging.getLogger(__name__)


class GuardrailsEntryBlocked(Exception):
    """Raised when the entry checkpoint rejects an engagement request."""


# --------------------------------------------------------------------------- #
# Allowlist — read from an env var or file at startup.  Empty means "allow any"
# for skeleton convenience; the real system MUST populate it.
# --------------------------------------------------------------------------- #

def _load_allowlist() -> list[str]:
    raw = os.environ.get("APTS_TARGET_ALLOWLIST", "").strip()
    if not raw:
        log.warning("APTS_TARGET_ALLOWLIST is empty — every target will be accepted "
                    "(skeleton only; DO NOT run this way in production).")
        return []
    return [entry.strip().lower() for entry in raw.split(",") if entry.strip()]


ALLOWLIST = _load_allowlist()

# Injection patterns the entry checkpoint strips before the Orchestrator sees
# the input.  This is a stub — real work happens in the modelling phase.
_INJECTION_PATTERNS = [
    re.compile(r"ignore (?:all )?(?:previous|prior) instructions", re.IGNORECASE),
    re.compile(r"disregard the (?:system|above)", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
]


# --------------------------------------------------------------------------- #
# The three checks (per §7.1)
# --------------------------------------------------------------------------- #

def _check_target_allowed(target_url: str) -> None:
    if not ALLOWLIST:                            # skeleton: allow anything
        return
    host = urlparse(target_url).hostname or ""
    host = host.lower()
    for entry in ALLOWLIST:
        if entry.startswith("*."):
            suffix = entry[1:]
            if host.endswith(suffix):
                return
        elif host == entry:
            return
    raise GuardrailsEntryBlocked(
        f"target {host!r} is not on the approved allowlist")


def _check_scope_well_formed(spec: EngagementSpec) -> None:
    if not spec.scope.domains and not spec.scope.allow_paths:
        raise GuardrailsEntryBlocked(
            "scope must include at least one domain or allow_path")


def _strip_injection(spec: EngagementSpec) -> EngagementSpec:
    """Remove suspicious sequences from the target URL string.

    Extremely conservative: an operator supplying a legitimate URL will never
    have these patterns in it.
    """
    stripped = spec.target_url
    for pat in _INJECTION_PATTERNS:
        stripped = pat.sub("", stripped)
    if stripped != spec.target_url:
        log.warning("entry: prompt-injection pattern removed from target_url")
        spec = spec.model_copy(update={"target_url": stripped})
    return spec


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def check_engagement_spec(spec: EngagementSpec) -> EngagementSpec:
    """Validate the operator-submitted spec.

    Returns a (possibly sanitised) copy of the spec.  Raises
    :class:`GuardrailsEntryBlocked` on rejection.
    """
    _check_target_allowed(spec.target_url)
    _check_scope_well_formed(spec)
    return _strip_injection(spec)
