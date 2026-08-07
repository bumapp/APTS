"""Bearer-token authentication used by every APTS component.

The token *format* and hashing scheme live in :mod:`shared.tokens`, which has no
third-party imports so the host-side bootstrap script can mint tokens without
FastAPI installed. This module is the verification half: it needs a database and
an HTTP framework, and nothing that mints tokens should have to carry either.

Comparison uses :func:`hmac.compare_digest` so timing does not leak the hash.

The primitives are re-exported below, so ``from shared.auth import hash_token``
keeps working for the services that already do it.
"""
from __future__ import annotations

import hmac
import logging
import os
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from .db import get_conn
from .tokens import (
    SALT_BYTES,
    TOKEN_PREFIX,
    generate_token,
    hash_token,
    parse_token,
)

log = logging.getLogger(__name__)

__all__ = [
    "TOKEN_PREFIX", "SALT_BYTES", "generate_token", "hash_token", "parse_token",
    "Caller", "verify_token_value", "require_auth", "load_own_token",
    "bearer_headers",
]


# --------------------------------------------------------------------------- #
# Server-side verification (used by every FastAPI endpoint that requires auth)
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Caller:
    """Identity of an authenticated caller, exposed to endpoint handlers."""
    component: str


def _extract_bearer(auth_header: str | None) -> str:
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "missing or malformed Authorization header",
                            headers={"WWW-Authenticate": "Bearer"})
    return auth_header.split(" ", 1)[1].strip()


def verify_token_value(token: str) -> Caller:
    """Look up the token's component in the DB and compare hashes.

    Raises :class:`HTTPException` on any failure so it can be dropped directly
    into a FastAPI dependency.
    """
    try:
        component = parse_token(token)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token format")

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT salt, digest FROM token_hashes WHERE component = %s",
            (component,),
        )
        row = cur.fetchone()

    if row is None:
        log.warning("auth: unknown component %r", component)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown component")

    salt, expected_digest = row
    salt_bytes = bytes(salt)
    expected_bytes = bytes(expected_digest)
    _, actual_digest = hash_token(token, salt=salt_bytes)

    if not hmac.compare_digest(actual_digest, expected_bytes):
        log.warning("auth: token mismatch for component %r", component)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")

    return Caller(component=component)


# --------------------------------------------------------------------------- #
# FastAPI dependencies
# --------------------------------------------------------------------------- #

def require_auth(authorization: str | None = Header(default=None)) -> Caller:
    """FastAPI dependency: authenticates any caller.

    Usage::

        @app.post("/progress")
        def progress(update: ProgressUpdate, caller: Caller = Depends(require_auth)):
            ...
    """
    token = _extract_bearer(authorization)
    return verify_token_value(token)


# Per-endpoint component allowlisting is *not* a dependency factory here. Both
# places that need it — ``run_controller.allowed_callers`` and the orchestrator's
# ``/progress`` check — compare against a set derived from the pipeline shape at
# request time, which a ``Depends(...)`` argument bound at import time cannot do.
# A generic ``require_one_of`` existed for this and was never called by either.


# --------------------------------------------------------------------------- #
# Client-side token loading (each component reads its own token at startup)
# --------------------------------------------------------------------------- #

def load_own_token() -> str:
    """Read this component's own bearer token from its mounted secret file.

    The path defaults to ``/run/secrets/token`` (Docker-secrets convention) but
    can be overridden with ``APTS_TOKEN_FILE`` for local testing.
    """
    path = os.environ.get("APTS_TOKEN_FILE", "/run/secrets/token")
    with open(path, "r", encoding="utf-8") as fh:
        token = fh.read().strip()
    if not token:
        raise RuntimeError(f"token file {path!r} is empty")
    return token


def bearer_headers(token: str, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return the HTTP headers a client should send with each authenticated call."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if extra:
        headers.update(extra)
    return headers
