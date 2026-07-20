"""Operator command-line interface.

Runs inside the orchestrator container.  Example::

    docker exec -it apts-orchestrator python -m orchestrator.cli start \\
        --target=https://juice-shop.test/ --domain='*.juice-shop.test'

    docker exec -it apts-orchestrator python -m orchestrator.cli status <id>

    docker exec -it apts-orchestrator python -m orchestrator.cli watch <id>

Talks to the orchestrator's *admin* HTTP port on ``127.0.0.1:8080`` — that
port is bound to the container's loopback interface only, so no bearer token
is required for these calls.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

import httpx

ADMIN = "http://127.0.0.1:8080"


# --------------------------------------------------------------------------- #

def cmd_start(args: argparse.Namespace) -> int:
    spec: dict[str, Any] = {
        "target_url": args.target,
        "scope": {
            "domains": args.domain or [],
            "allow_paths": args.allow_path or [],
            "deny_paths": args.deny_path or [],
        },
    }
    r = httpx.post(f"{ADMIN}/engagements/start", json=spec, timeout=30.0)
    if r.status_code != 200:
        print(f"error: {r.status_code} {r.text}", file=sys.stderr)
        return 1
    body = r.json()
    print(f"engagement_id: {body['engagement_id']}")
    print(f"status:        {body['status']}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    r = httpx.get(f"{ADMIN}/engagements/{args.engagement_id}", timeout=10.0)
    if r.status_code != 200:
        print(f"error: {r.status_code} {r.text}", file=sys.stderr)
        return 1
    print(json.dumps(r.json(), indent=2, default=str))
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    """Poll the status endpoint and print any change until the engagement ends."""
    last: dict[str, str] = {}
    while True:
        r = httpx.get(f"{ADMIN}/engagements/{args.engagement_id}", timeout=10.0)
        if r.status_code != 200:
            print(f"error: {r.status_code} {r.text}", file=sys.stderr)
            return 1
        body = r.json()
        for agent, info in body.get("per_agent", {}).items():
            state = info["status"]
            if last.get(agent) != state:
                print(f"[{agent:>8}]  {state}")
                last[agent] = state
        if body["status"] in ("complete", "failed"):
            print(f"\n== engagement {body['status']} ==")
            return 0
        time.sleep(args.interval)


# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apts")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_start = sub.add_parser("start", help="Start a new engagement")
    p_start.add_argument("--target", required=True, help="Target URL, e.g. https://example.com/")
    p_start.add_argument("--domain", action="append", default=[],
                         help="Domain in scope (repeatable), e.g. '*.example.com'")
    p_start.add_argument("--allow-path", action="append", default=[],
                         help="Allowed path prefix (repeatable)")
    p_start.add_argument("--deny-path", action="append", default=[],
                         help="Denied path prefix (repeatable)")
    p_start.set_defaults(func=cmd_start)

    p_status = sub.add_parser("status", help="Print engagement status once")
    p_status.add_argument("engagement_id")
    p_status.set_defaults(func=cmd_status)

    p_watch = sub.add_parser("watch", help="Follow an engagement until it finishes")
    p_watch.add_argument("engagement_id")
    p_watch.add_argument("--interval", type=float, default=2.0)
    p_watch.set_defaults(func=cmd_watch)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
