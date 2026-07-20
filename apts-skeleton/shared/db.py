"""Postgres connection helpers.

All components use the same ``psycopg`` (v3) connection string, read from the
``APTS_DB_DSN`` environment variable, e.g.::

    postgresql://apts@database:5432/apts?sslmode=verify-full&sslrootcert=/etc/apts/trust-bundle.pem

Note that the database *does not* use bearer-token auth for connections — it
uses PostgreSQL's own authentication (a scram-sha-256 password mounted from a
Docker secret).  The bearer-token model applies to the HTTP-level components.
The rationale is spelled out in the README §"Why does the DB have its own
password?".
"""
from __future__ import annotations

import contextlib
import logging
import os
from typing import Iterator

import psycopg

log = logging.getLogger(__name__)


def _dsn() -> str:
    dsn = os.environ.get("APTS_DB_DSN")
    if not dsn:
        raise RuntimeError("APTS_DB_DSN is not set")
    return dsn


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
