"""Bearer-token format and hashing — the primitives, with no dependencies.

Split out of :mod:`shared.auth` because there are two callers with
irreconcilable dependency budgets:

* every service, which verifies tokens and already has FastAPI and psycopg;
* ``bootstrap/generate_tokens.py``, which *mints* them and runs on the host
  before any container exists, with nothing but the standard library.

The bootstrap script previously reimplemented the format and the salt+hash
scheme with a comment reading "same scheme as shared/auth.py". Two
implementations of a token format is exactly the duplication that drifts: change
the prefix or the salt length in one place and authentication fails everywhere
with an error that points at the database rather than at the mismatch.

This module imports only ``hashlib`` and ``secrets``, so the host script can use
it directly and there is one definition of the scheme.

Format
------
``apts_<component>_<64 hex chars>``. The component prefix is what tells the
receiving side which ``token_hashes`` row to check against, so it is part of the
token rather than a separate header.

Storage
-------
``sha256(salt || token)`` with a fresh 16-byte salt per token; the raw token is
never stored. Not bcrypt or argon2: tokens carry 256 bits of entropy, and a
password KDF exists to slow attacks on low-entropy secrets. It would add ~100 ms
to every authenticated request for no gain here.
"""
from __future__ import annotations

import hashlib
import secrets

TOKEN_PREFIX = "apts"
SALT_BYTES = 16
TOKEN_ENTROPY_BYTES = 32


def generate_token(component: str) -> str:
    """Return a fresh token for ``component``."""
    return f"{TOKEN_PREFIX}_{component}_{secrets.token_hex(TOKEN_ENTROPY_BYTES)}"


def hash_token(token: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Return ``(salt, digest)``. Generates a fresh salt if none is supplied.

    Pass the stored salt to verify; omit it to enrol a new token.
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.sha256(salt + token.encode("utf-8")).digest()
    return salt, digest


def parse_token(token: str) -> str:
    """Extract the component name embedded in a token, or raise ``ValueError``.

    Splits at most twice: the random tail cannot contain an underscore, but a
    component name could gain one, and ``maxsplit=2`` keeps that from silently
    truncating it.
    """
    parts = token.split("_", 2)
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise ValueError("malformed token")
    return parts[1]
