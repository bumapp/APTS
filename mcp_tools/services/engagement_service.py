"""Engagement scope resolution.

Sits between the provider and the repository, and owns the one decision the
repository deliberately does not: how long a scope may be held in memory.

Caching is sound because an engagement's scope is immutable — written once by
``POST /engagements/start`` and never updated. If that ever stops being true,
this cache has to go with it.

Only successful lookups are cached. A failure — missing row, database down — is
retried on the next call rather than memoised into a permanent block on an
engagement that may be perfectly valid.
"""
from __future__ import annotations

import logging
from collections import OrderedDict
from typing import Protocol
from uuid import UUID

from shared.models import Scope

from mcp_tools.config import SCOPE_CACHE_SIZE
from mcp_tools.repositories.engagement_repository import (
    EngagementRepository,
    ScopeUnavailable,
)

log = logging.getLogger("mcp.services.engagement")


class ScopeSource(Protocol):
    """What the provider needs in order to resolve an engagement's boundary."""

    def get_scope(self, engagement_id: UUID) -> Scope: ...


class EngagementService:
    """Scope lookup with a bounded LRU in front of the repository."""

    def __init__(self, repository: EngagementRepository | None = None,
                 cache_size: int = SCOPE_CACHE_SIZE) -> None:
        self._repository = repository or EngagementRepository()
        self._cache: OrderedDict[str, Scope] = OrderedDict()
        self._cache_size = max(0, cache_size)

    def get_scope(self, engagement_id: UUID) -> Scope:
        """Return the approved scope, from cache when possible.

        Propagates :class:`ScopeUnavailable` unchanged — the caller must treat
        an unresolvable scope as a denial, and softening it here into a default
        or an empty scope would turn a fail-closed path into a fail-open one.
        """
        key = str(engagement_id)
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return cached

        scope = self._repository.get_scope(key)
        self._remember(key, scope)
        return scope

    def _remember(self, key: str, scope: Scope) -> None:
        if self._cache_size == 0:
            return
        self._cache[key] = scope
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_size:
            self._cache.popitem(last=False)


__all__ = ["EngagementService", "ScopeSource", "ScopeUnavailable"]
