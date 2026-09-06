"""Postgres connection helpers.

Every component builds its own DSN at startup from a small set of pieces:

  * connection target and database — hard-coded defaults (``database:5432``,
    user ``apts``, database ``apts``) that can be overridden with env vars
    ``APTS_DB_HOST``, ``APTS_DB_PORT``, ``APTS_DB_USER``, ``APTS_DB_NAME``;
  * the trust bundle path — hard-coded default that can be overridden with
    ``APTS_TRUST_BUNDLE``;
  * the password — read from a mounted file, path defaults to
    ``/run/secrets/db_password`` (the Docker-secrets convention) and can be
    overridden with ``APTS_DB_PASSWORD_FILE``.

This design keeps the raw password out of ``docker inspect`` output — no
environment variable ever holds it — while still letting the DSN assemble
cleanly at runtime.  The database itself uses PostgreSQL's own
authentication (scram-sha-256) with the same password file mounted as
``POSTGRES_PASSWORD_FILE`` on the DB container.
"""
from __future__ import annotations

import contextlib
import logging
import os
from typing import Iterator

import psycopg

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# DSN construction
# --------------------------------------------------------------------------- #

def _read_password() -> str:
    """Read the DB password from the mounted secret file.

    The file is written once by ``bootstrap/generate_password.sh`` and mounted
    read-only into the container at ``/run/secrets/db_password``.
    """
    path = os.environ.get("APTS_DB_PASSWORD_FILE", "/run/secrets/db_password")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            pw = fh.read().strip()
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"DB password file not found at {path!r}. "
            f"Was the secret mounted? See docker-compose.yml.") from exc
    if not pw:
        raise RuntimeError(f"DB password file {path!r} is empty")
    return pw


def _dsn() -> str:
    host   = os.environ.get("APTS_DB_HOST", "database")
    port   = os.environ.get("APTS_DB_PORT", "5432")
    user   = os.environ.get("APTS_DB_USER", "apts")
    dbname = os.environ.get("APTS_DB_NAME", "apts")
    trust  = os.environ.get("APTS_TRUST_BUNDLE", "/etc/apts/trust-bundle.pem")
    password = _read_password()
    return (f"postgresql://{user}:{password}@{host}:{port}/{dbname}"
            f"?sslmode=verify-full&sslrootcert={trust}")


# --------------------------------------------------------------------------- #
# Connection + audit helpers (unchanged from prior version)
# --------------------------------------------------------------------------- #

def strip_nul(value):
    """Recursively remove NUL (U+0000) bytes from strings in a JSON-able value.

    Postgres text/JSONB cannot store ``\\u0000`` — a write containing one fails
    the whole statement. Agent artifacts legitimately capture attacker-style
    payloads (null-byte injection: ``email=x\\x00``) and raw response bytes, so
    this is a real, recurring case, not a corner one. NULs are replaced with a
    visible ``<NUL>`` marker rather than dropped, so the evidence that a null byte
    was present survives. Generic: it does not care what any value means."""
    if isinstance(value, str):
        return value.replace("\x00", "<NUL>") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: strip_nul(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [strip_nul(v) for v in value]
    return value


@contextlib.contextmanager
def get_conn() -> Iterator[psycopg.Connection]:
    """Yield a short-lived DB connection.

    Keeps things simple for the skeleton — a real deployment should use a
    connection pool (``psycopg_pool.ConnectionPool``).
    """
    conn = psycopg.connect(_dsn(), autocommit=False)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def audit(component: str, event_type: str,
          engagement_id: str | None = None,
          detail: dict | None = None) -> None:
    """Append one row to the audit log.  Non-fatal on failure."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """INSERT INTO audit_log (engagement_id, component, event_type, detail)
                   VALUES (%s, %s, %s, %s::jsonb)""",
                (engagement_id, component, event_type,
                 psycopg.types.json.Json(detail or {})),
            )
    except Exception as exc:                                     # pragma: no cover
        log.error("audit write failed: %s", exc)
