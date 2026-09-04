#!/usr/bin/env python3
"""Generate one bearer token per component and seed the DB with salted hashes.

Runs on the *host*, not inside a container.  Reads its DB connection settings
from environment variables (or ``.env`` if you use ``docker compose --env-file``),
writes the raw tokens to ``./tokens/<component>.token`` — those files are
mounted read-only into each container as ``/run/secrets/token`` by
``docker-compose.yml``.  The raw tokens are then never needed again unless a
component is rebuilt.

Usage::

    ./bootstrap/generate_tokens.py                     # normal run
    ./bootstrap/generate_tokens.py --rotate <comp>     # rotate one token
    ./bootstrap/generate_tokens.py --print-only        # print, don't write

Requires the database container to be running.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Runs from the repository root, on the host, outside any container — so the
# package has to be put on the path explicitly. ``shared.tokens`` is
# stdlib-only by design (see its docstring), which is what makes importing it
# here possible without installing the service dependencies.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared.tokens import generate_token, hash_token          # noqa: E402

COMPONENTS = [
    "orchestrator",
    "agent-recon",
    "agent-vuln",
    "agent-mitre",
    "agent-exploit",
    "agent-script",
    "agent-adviser",
    "database",
    "mcp-tools",
    # mcp-native drives the sandbox tool, so it authenticates to the sandbox
    # container with its own bearer token like mcp-tools does.
    "mcp-native",
    "sandbox",
]

TOKEN_DIR = Path(os.environ.get("APTS_TOKEN_DIR", "./tokens"))


def _sh(cmd: list[str], input_: str | None = None) -> str:
    """Run ``cmd`` and return its stdout as text."""
    return subprocess.run(cmd, check=True, capture_output=True,
                          text=True, input=input_).stdout


def _hash_and_upsert(component: str, token: str) -> None:
    """Salt+hash the token and UPSERT it into ``token_hashes`` via psql.

    Everything happens through the ``database`` container so we don't need
    Postgres or Python-psycopg on the host. The hashing itself comes from
    ``shared.tokens`` — the same function the services verify against, so the
    two cannot disagree about the scheme.
    """
    salt, digest = hash_token(token)

    sql = f"""
        INSERT INTO token_hashes (component, salt, digest)
        VALUES ('{component}', decode('{salt.hex()}','hex'), decode('{digest.hex()}','hex'))
        ON CONFLICT (component) DO UPDATE
            SET salt = EXCLUDED.salt,
                digest = EXCLUDED.digest,
                created_at = NOW();
    """
    _sh(["docker", "compose", "exec", "-T", "database",
         "psql", "-U", "apts", "-d", "apts", "-v", "ON_ERROR_STOP=1"],
        input_=sql)


def _write_token_file(component: str, token: str) -> None:
    TOKEN_DIR.mkdir(parents=True, exist_ok=True)
    path = TOKEN_DIR / f"{component}.token"
    path.write_text(token + "\n")
    path.chmod(0o600)


def _generate_one(component: str, *, print_only: bool) -> None:
    token = generate_token(component)
    if print_only:
        print(f"{component}: {token}")
        return
    _write_token_file(component, token)
    _hash_and_upsert(component, token)
    print(f"    {component}: generated + upserted")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rotate", metavar="COMPONENT",
                        help="Rotate one token; otherwise all tokens are generated")
    parser.add_argument("--print-only", action="store_true",
                        help="Print tokens to stdout without writing files or DB")
    args = parser.parse_args(argv)

    if args.rotate:
        if args.rotate not in COMPONENTS:
            print(f"unknown component {args.rotate!r}. "
                  f"Valid: {', '.join(COMPONENTS)}", file=sys.stderr)
            return 2
        targets = [args.rotate]
        print(f"==> rotating token for {args.rotate}")
    else:
        targets = COMPONENTS
        print("==> generating tokens for all components")

    for c in targets:
        _generate_one(c, print_only=args.print_only)

    if not args.print_only:
        print()
        print(f"tokens written to {TOKEN_DIR}/")
        print("hashes upserted into token_hashes table")
    return 0


if __name__ == "__main__":
    sys.exit(main())
