"""Bearer-token authentication used by every APTS component.

Token format is ``apts_<component>_<random-hex>``, e.g.
``apts_orchestrator_a1b2c3...``.  The component prefix tells the receiving side
which entry in the ``token_hashes`` table to check the token against.

Storage.
  Each row in ``token_hashes`` holds a per-token 16-byte salt and the value
  ``sha256(salt || token)`` — the raw token itself is never stored.  Comparison
  uses :func:`hmac.compare_digest` so timing does not leak the hash.

Why not bcrypt/argon2?
  Tokens are 32-byte random values (256 bits of entropy) — a password KDF is
  designed to slow down attacks on low-entropy secrets and would add ~100 ms
  per authenticated request for no security gain here.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from dataclasses import dataclass
from typing import Iterable

import psycopg
from fastapi import Header, HTTPException, status

from .db import get_conn

log = logging.getLogger(__name__)

TOKEN_PREFIX = "apts"
SALT_BYTES = 16


# --------------------------------------------------------------------------- #
# Token generation & hashing (used by the bootstrap script)
# --------------------------------------------------------------------------- #

def generate_token(component: str) -> str:
    """Return a fresh token for ``component`` (32 bytes of hex-encoded entropy)."""
    random_part = secrets.token_hex(32)
    return f"{TOKEN_PREFIX}_{component}_{random_part}"


def hash_token(token: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Return ``(salt, digest)``.  Generates a fresh salt if none is supplied."""
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.sha256(salt + token.encode("utf-8")).digest()
    return salt, digest


def parse_token(token: str) -> str:
    """Extract the component name embedded in a token, or raise ``ValueError``."""
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise ValueError("malformed token")
    return parts[1]


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


def require_one_of(*allowed_components: str):
    """Dependency factory that restricts an endpoint to a set of components.

    Usage::

        @app.post("/run")
        def run(handoff: ChainHandoff,
                caller: Caller = Depends(require_one_of("orchestrator", "agent-recon"))):
            ...
    """
    allowed_set = frozenset(allowed_components)

    def _dep(authorization: str | None = Header(default=None)) -> Caller:
        caller = require_auth(authorization)
        if caller.component not in allowed_set:
            log.warning("auth: %r not permitted (allowed=%s)",
                        caller.component, sorted(allowed_set))
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"{caller.component!r} not permitted here")
        return caller

    return _dep


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
