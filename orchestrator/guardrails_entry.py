"""Entry-checkpoint Guardrails — Characterization §7.1.

Validates what the operator submits before an engagement row exists.

Beyond rejecting unauthorised targets, this checkpoint is responsible for a
subtler guarantee: **an engagement that starts must be able to do its work.**
The MCP checkpoint enforces scope on every outbound tool call and fails closed,
so a spec that is merely *accepted* rather than *coherent* produces the worst
possible outcome — the pipeline starts, Recon's first request is blocked, the
agent retries three times, and a critical-agent failure kills the run. The
operator sees a dead engagement and no obvious cause.

So the checks below reject any spec whose own target lies outside its own
scope, rather than discovering that contradiction six HTTP calls later. Scope
decisions come from ``shared.scope_match``, the same module the MCP checkpoint
uses, so the two cannot disagree about what a pattern means.

Still a placeholder: the prompt-injection handling is a small regex list, not
the ``guardrails-ai`` library or a real classifier. That remains a modelling-
phase follow-up.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from shared.models import EngagementSpec
from shared.scope_match import (
    host_matches,
    matching_deny_path,
    normalise_host,
    path_allowed,
)

log = logging.getLogger(__name__)

ALLOWLIST_FILE = "/etc/apts/config/target_allowlist"


class GuardrailsEntryBlocked(Exception):
    """Raised when the entry checkpoint rejects an engagement request."""


# --------------------------------------------------------------------------- #
# Allowlist — read at startup from the mounted config file.  Empty means
# "allow any" for skeleton convenience; a real deployment MUST populate it.
# --------------------------------------------------------------------------- #

def _load_allowlist() -> list[str]:
    try:
        with open(ALLOWLIST_FILE, "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
    except (FileNotFoundError, OSError):
        raw = ""
    if not raw:
        log.warning("%s is empty — every target will be accepted "
                    "(skeleton only; DO NOT run this way in production).",
                    ALLOWLIST_FILE)
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
    """Reject a target the deployment has not authorised at all.

    This is the operator-independent boundary: ``config/target_allowlist`` is
    set by whoever runs the deployment, and no engagement spec can widen it.
    An empty allowlist accepts anything, which is a skeleton convenience the
    README already warns about.
    """
    if not ALLOWLIST:                            # skeleton: allow anything
        return
    host = normalise_host(urlparse(target_url).hostname)
    if not host_matches(host, ALLOWLIST):
        raise GuardrailsEntryBlocked(
            f"target {host!r} is not on the approved allowlist")


def _check_scope_well_formed(spec: EngagementSpec) -> None:
    """Reject a scope the agents could not actually operate inside.

    Three ways a spec can be self-defeating, all of which used to be accepted:

    *No domains.*  ``allow_paths`` alone was previously enough, but paths do
    not tell the MCP checkpoint which *hosts* are permitted, and it treats an
    empty domain list as authorising nothing. Every network tool call would be
    blocked. Domains are now mandatory.

    *Unparseable target.*  A ``target_url`` with no hostname cannot be matched
    against anything downstream.

    *Target outside its own scope.*  The most common real mistake — submitting
    ``https://app.example.com/`` scoped to ``*.example.org``, or forgetting the
    wildcard on a subdomain. Recon would be blocked on its first request.
    """
    if not spec.scope.domains:
        raise GuardrailsEntryBlocked(
            "scope must include at least one domain; agents cannot make any "
            "network request without one (allow_paths alone is not enough)")

    host = normalise_host(urlparse(spec.target_url).hostname)
    if not host:
        raise GuardrailsEntryBlocked(
            f"could not parse a hostname out of target_url {spec.target_url!r}")

    if not host_matches(host, spec.scope.domains):
        raise GuardrailsEntryBlocked(
            f"target host {host!r} is not covered by its own scope "
            f"({', '.join(spec.scope.domains)}); the engagement would be "
            f"blocked on its first request")

    _check_target_path_reachable(spec, host)


def _check_target_path_reachable(spec: EngagementSpec, host: str) -> None:
    """Reject a target URL whose path its own scope excludes.

    Same failure as an out-of-scope host, one level down: scoping an
    engagement to ``allow_paths=['/app/']`` while pointing it at
    ``https://target/`` means the entry point itself is unreachable.
    """
    path = urlparse(spec.target_url).path or "/"

    denied = matching_deny_path(path, spec.scope.deny_paths)
    if denied:
        raise GuardrailsEntryBlocked(
            f"target path {path!r} on {host!r} is excluded by its own "
            f"deny_paths entry {denied!r}")

    if not path_allowed(path, spec.scope.allow_paths):
        raise GuardrailsEntryBlocked(
            f"target path {path!r} on {host!r} is outside its own allow_paths "
            f"({', '.join(spec.scope.allow_paths)})")


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
