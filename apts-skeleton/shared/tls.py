"""TLS context helpers.

Each APTS component has:
  * its own private key at ``/run/secrets/tls.key`` (mounted read-only),
  * its own certificate at ``/etc/apts/tls.crt``,
  * a trust bundle at ``/etc/apts/trust-bundle.pem`` containing every
    component's certificate — used to verify outbound TLS connections.

For the skeleton we do *server-side* TLS with bearer-token authentication for
the client (rather than full mTLS).  A future hardening step is to require
client certificates as well, but tokens are already sufficient to authenticate
which component made a request.
"""
from __future__ import annotations

import os
import ssl
from pathlib import Path

DEFAULT_KEY = Path("/run/secrets/tls.key")
DEFAULT_CRT = Path("/etc/apts/tls.crt")
DEFAULT_TRUST = Path("/etc/apts/trust-bundle.pem")


def _override(env_var: str, default: Path) -> Path:
    return Path(os.environ.get(env_var, str(default)))


# --------------------------------------------------------------------------- #
# Server side
# --------------------------------------------------------------------------- #

def server_ssl_context() -> ssl.SSLContext:
    """Return an SSLContext suitable for uvicorn / hypercorn / FastAPI."""
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(
        certfile=_override("APTS_TLS_CERT_FILE", DEFAULT_CRT),
        keyfile=_override("APTS_TLS_KEY_FILE", DEFAULT_KEY),
    )
    return ctx


def uvicorn_ssl_kwargs() -> dict:
    """Return the ``ssl_*`` keyword arguments for ``uvicorn.run``."""
    return {
        "ssl_certfile": str(_override("APTS_TLS_CERT_FILE", DEFAULT_CRT)),
        "ssl_keyfile": str(_override("APTS_TLS_KEY_FILE", DEFAULT_KEY)),
    }


# --------------------------------------------------------------------------- #
# Client side (used by httpx.AsyncClient)
# --------------------------------------------------------------------------- #

def client_ssl_context() -> ssl.SSLContext:
    """Return an SSLContext that verifies servers against the APTS trust bundle."""
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    trust = _override("APTS_TRUST_BUNDLE", DEFAULT_TRUST)
    ctx.load_verify_locations(cafile=str(trust))
    return ctx
