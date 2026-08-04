"""Scope matching primitives, shared by every checkpoint that enforces scope.

There are two places that decide whether something is in scope — the entry
checkpoint (``orchestrator/guardrails_entry.py``, screening what the operator
submits) and the MCP outbound checkpoint (``mcp_tools/guardrails_mcp.py``,
screening what agents actually send).  They had separate implementations with
*different* semantics: one treated ``*.example.com`` as excluding the apex and
the other did not.  That disagreement is worse than either behaviour on its
own, because an engagement could pass intake and then have every request
blocked mid-run, or vice versa.

These are pure predicates with no exception types of their own.  Each
checkpoint raises its own error with its own wording; only the *decision* is
shared, so the two can no longer drift apart.
"""
from __future__ import annotations


def normalise_host(host: str | None) -> str:
    """Lower-case a hostname and drop the root label's trailing dot.

    ``EXAMPLE.com.`` and ``example.com`` are the same host; DNS says so and a
    scope check that disagrees is a bypass.
    """
    return (host or "").strip().lower().rstrip(".")


def host_matches(host: str, patterns: list[str]) -> bool:
    """True if ``host`` is covered by any entry in ``patterns``.

    Two pattern forms are supported:

    ``example.com``
        Exact match on that host and nothing else.

    ``*.example.com``
        The apex ``example.com`` *and* any subdomain beneath it.  Including the
        apex is deliberate: operators write the wildcard meaning "this site and
        everything under it", and excluding it rejects the very target URL they
        submitted alongside the pattern.

    An empty pattern list matches nothing — callers that want "allow any" have
    to say so themselves, because silently defaulting to open is how a scope
    check stops being one.
    """
    host = normalise_host(host)
    if not host:
        return False

    for raw in patterns:
        pattern = normalise_host(raw)
        if not pattern:
            continue
        if pattern.startswith("*."):
            apex = pattern[2:]
            if apex and (host == apex or host.endswith(f".{apex}")):
                return True
        elif host == pattern:
            return True
    return False


def matching_deny_path(path: str, deny_paths: list[str]) -> str | None:
    """Return the ``deny_paths`` prefix that excludes ``path``, else ``None``."""
    for denied in deny_paths:
        if denied and path.startswith(denied):
            return denied
    return None


def path_allowed(path: str, allow_paths: list[str]) -> bool:
    """True if ``path`` is permitted by ``allow_paths``.

    An empty ``allow_paths`` means the whole host is in play.  A non-empty one
    is exhaustive: anything not under one of those prefixes is out of scope.
    Note this says nothing about ``deny_paths`` — check
    :func:`matching_deny_path` as well, and let deny win.
    """
    if not allow_paths:
        return True
    return any(path.startswith(allowed) for allowed in allow_paths if allowed)
