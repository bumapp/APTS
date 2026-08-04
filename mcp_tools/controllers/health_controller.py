"""Liveness probe.

Unauthenticated by design: Compose's healthcheck has no bearer token, and the
response carries nothing an unauthenticated caller could not already infer from
the port being open.
"""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
