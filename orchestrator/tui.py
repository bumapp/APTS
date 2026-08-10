"""Interactive terminal UI for setting up and running an engagement.

Invoked via ``docker exec -it apts-orchestrator python -m orchestrator.cli tui``.

Design goals (Characterization \u00a78 lifecycle step 1):
  * Prompt for target URL, scope, optional time window, and view mode.
  * Validate client-side where cheap; let entry Guardrails validate the rest.
  * Stream every audit_log event for the engagement as it happens.
  * Print a final summary when the engagement reaches a terminal state.
"""
from __future__ import annotations

import sys
import time
from datetime import datetime
from typing import Any
from uuid import UUID

import httpx

from shared.db import get_conn

ADMIN_URL = "http://127.0.0.1:8080"
POLL_INTERVAL_SECONDS = 0.5

CHAIN = ["recon", "vuln", "mitre", "exploit", "script", "adviser"]

TERMINAL_EVENTS = {
    "engagement_complete",
    "engagement_failed",
    "engagement_complete_with_warnings",
}

# Events considered "noise" in brief mode \u2014 routine chain movement without
# decision content.  Everything not in this set is shown even in brief mode.
BRIEF_HIDE = {
    "handoff_received",
    "pushed_to_next",
    "kickoff_launched",
    "kickoff_recorded",
    "result_written",
}


# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #

def _banner() -> None:
    print()
    print("=" * 62)
    print("  APTS \u2014 Autonomous Penetration Testing System")
    print("  Interactive engagement setup")
    print("=" * 62)


# --------------------------------------------------------------------------- #
# Form: collect the engagement spec
# --------------------------------------------------------------------------- #

def _collect_spec() -> dict[str, Any]:
    """Prompt the operator for every field the TUI needs.

    Returns a dict combining the server-side EngagementSpec fields
    (target_url, scope, time_window) with the client-side ``_brief``
    key.  Underscore-prefixed keys are stripped before submitting.
    """
    print("\n--- Engagement setup ---\n")

    # Target URL (required, must look like a URL)
    while True:
        target = input("  Target URL: ").strip()
        if not target:
            print("  (a target URL is required)")
            continue
        if not (target.startswith("http://") or target.startswith("https://")):
            print("  (must start with 'http://' or 'https://')")
            continue
        break

    # Scope fields (all optional; empty defaults to permissive)
    print("\n  Scope (leave blank to skip a field):")
    domains     = _ask_list("    Allowed domains (comma-separated)")
    allow_paths = _ask_list("    Allow paths (comma-separated)")
    deny_paths  = _ask_list("    Deny paths (comma-separated)")

    # Time window (optional)
    print("\n  Time window (leave blank to omit):")
    tw_start = _ask_time("    Start (YYYY-MM-DD HH:MM)")
    tw_end   = _ask_time("    End   (YYYY-MM-DD HH:MM)")

    time_window: dict[str, Any] | None = None
    if tw_start or tw_end:
        time_window = {"starts_at": tw_start, "ends_at": tw_end}

    # View mode for the live event stream (client-side only)
    print("\n  Output:")
    brief = _ask_view_mode()

    return {
        "target_url": target,
        "scope": {
            "domains":     domains,
            "allow_paths": allow_paths,
            "deny_paths":  deny_paths,
        },
        "time_window": time_window,
        "_brief": brief,   # UI-only field; stripped before submitting
    }


def _ask_list(prompt: str) -> list[str]:
    raw = input(f"{prompt}: ").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _ask_time(prompt: str) -> str | None:
    """Return an ISO-8601 timestamp, or None if the user left it blank."""
    while True:
        raw = input(f"{prompt}: ").strip()
        if not raw:
            return None
        for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M"):
            try:
                return datetime.strptime(raw, fmt).isoformat()
            except ValueError:
                continue
        print(f"    (couldn't parse {raw!r} \u2014 try YYYY-MM-DD HH:MM)")


def _ask_view_mode() -> bool:
    """Ask whether to show all events or only decision points.

    Returns True for brief mode, False for full mode (the default).
    """
    while True:
        raw = input("    View mode [all/brief] (default: all): ").strip().lower()
        if raw in ("", "a", "all"):
            return False
        if raw in ("b", "brief"):
            return True
        print("    (please answer 'all' or 'brief')")


# --------------------------------------------------------------------------- #
# Review and confirmation
# --------------------------------------------------------------------------- #

def _confirm(spec: dict[str, Any]) -> bool:
    print("\n--- Review ---\n")
    print(f"  Target URL:  {spec['target_url']}")
    scope = spec["scope"]
    print(f"  Domains:     {scope['domains'] or '(any)'}")
    print(f"  Allow paths: {scope['allow_paths'] or '(any)'}")
    print(f"  Deny paths:  {scope['deny_paths'] or '(none)'}")
    tw = spec.get("time_window")
    if tw:
        print(f"  Time window: {tw.get('starts_at') or '(now)'} "
              f"\u2192 {tw.get('ends_at') or '(no end)'}")
    else:
        print( "  Time window: (none)")
    print(f"  View mode:   {'brief' if spec.get('_brief') else 'all'}")
    print()
    answer = input("  Start engagement? [Y/n]: ").strip().lower()
    return answer in ("", "y", "yes")


# --------------------------------------------------------------------------- #
# Submit to the admin API
# --------------------------------------------------------------------------- #

def _submit(spec: dict[str, Any]) -> UUID:
    """POST the spec to the admin API.

    Strips underscore-prefixed keys first \u2014 those are client-side UI state
    (currently just ``_brief``) that has no meaning to the server and
    would fail EngagementSpec validation if sent.
    """
    server_spec = {k: v for k, v in spec.items() if not k.startswith("_")}
    r = httpx.post(f"{ADMIN_URL}/engagements/start",
                   json=server_spec, timeout=30.0)
    r.raise_for_status()
    body = r.json()
    return UUID(body["engagement_id"])


# --------------------------------------------------------------------------- #
# Stream audit-log events for the engagement
# --------------------------------------------------------------------------- #

def _stream_events(engagement_id: UUID, brief: bool = False) -> None:
    """Tail audit_log for this engagement until a terminal event lands.

    When ``brief`` is True, filters out routine chain-movement events
    (handoffs, pushes, kickoff notifications, result writes) and keeps
    only decision points: progress_received, retry_launched,
    minor_agent_skipped, chain_forwarded_past_skip, stall_detected, and
    the engagement_* terminal events.
    """
    last_id = 0
    while True:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT id, logged_at, component, event_type, detail
                   FROM audit_log
                   WHERE engagement_id = %s AND id > %s
                   ORDER BY id ASC""",
                (str(engagement_id), last_id),
            )
            rows = cur.fetchall()

        terminal_seen = False
        for row_id, logged_at, component, event_type, detail in rows:
            last_id = row_id
            if not (brief and event_type in BRIEF_HIDE):
                print(_format_event(logged_at, component, event_type, detail or {}))
            if event_type in TERMINAL_EVENTS:
                terminal_seen = True

        if terminal_seen:
            return
        time.sleep(POLL_INTERVAL_SECONDS)


def _format_event(logged_at, component: str, event_type: str,
                  detail: dict[str, Any]) -> str:
    """One-line rendering of an audit-log row."""
    ts = logged_at.strftime("%H:%M:%S")

    # If the event names an agent, use that as the prefix
    agent = detail.get("agent") if isinstance(detail, dict) else None
    prefix_raw = f"agent-{agent}" if agent else component
    prefix = f"[{prefix_raw:<16}]"

    # Surface the most useful keys inline
    extras = []
    for key in ("status", "attempt", "next", "skipped", "input_from",
                "reason", "error"):
        val = detail.get(key)
        if val is not None:
            extras.append(f"{key}={val}")
    tail = ("  " + " ".join(extras)) if extras else ""

    return f"  {ts}  {prefix}  {event_type}{tail}"


# --------------------------------------------------------------------------- #
# Summary at the end
# --------------------------------------------------------------------------- #

def _summary(engagement_id: UUID) -> None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT target_url, status, created_at, completed_at "
            "FROM engagements WHERE id = %s",
            (str(engagement_id),),
        )
        target_url, status, started_at, completed_at = cur.fetchone()

        cur.execute(
            """SELECT agent, status, retry_count, last_error
               FROM engagement_state
               WHERE engagement_id = %s""",
            (str(engagement_id),),
        )
        state = {a: (st, rc, err) for a, st, rc, err in cur.fetchall()}

    print()
    print("=" * 62)
    print("  Engagement summary")
    print("=" * 62)
    print(f"  ID:       {engagement_id}")
    print(f"  Target:   {target_url}")
    print(f"  Status:   {status}")
    if completed_at and started_at:
        elapsed = (completed_at - started_at).total_seconds()
        print(f"  Elapsed:  {elapsed:.1f}s")
    print()
    print(f"  {'Agent':<10} {'Final state':<20} {'Attempts':<10} Note")
    print(f"  {'-' * 10:<10} {'-' * 20:<20} {'-' * 8:<10} {'-' * 30}")
    for agent in CHAIN:
        st, rc, err = state.get(agent, ("(missing)", 0, None))
        # attempts = initial + retries; if it never ran, 0
        if st == "pending":
            attempts = "0"
        else:
            attempts = str(rc + 1)
        note = (err or "")[:40]
        print(f"  {agent:<10} {st:<20} {attempts:<10} {note}")
    print()


# --------------------------------------------------------------------------- #
# Entry point (called from orchestrator/cli.py)
# --------------------------------------------------------------------------- #

def run_tui(args) -> int:
    _banner()

    engagement_id: UUID | None = None
    brief = False   # updated from the spec once the operator has answered

    try:
        # Setup loop: form \u2192 review \u2192 submit \u2192 break on success
        while True:
            spec = _collect_spec()
            if not _confirm(spec):
                print("\n(cancelled \u2014 starting over)\n")
                continue
            brief = bool(spec.get("_brief"))
            try:
                engagement_id = _submit(spec)
            except httpx.HTTPStatusError as exc:
                print(f"\n  [!] server rejected the spec: "
                      f"{exc.response.status_code} {exc.response.text}")
                print("      returning to the form...\n")
                continue
            except httpx.RequestError as exc:
                print(f"\n  [!] cannot reach the orchestrator: {exc}")
                print("      is the admin API up on 127.0.0.1:8080?")
                return 1
            break

        assert engagement_id is not None
        print(f"\n  Engagement started: {engagement_id}")
        print(f"  Streaming events (Ctrl-C to detach)...\n")
        print("-" * 62)
        _stream_events(engagement_id, brief=brief)
        print("-" * 62)
        _summary(engagement_id)
        return 0

    except (KeyboardInterrupt, EOFError):
        print()
        if engagement_id is not None:
            print(f"\n  [!] Detached. Engagement {engagement_id} continues "
                  f"in the background.")
            print(f"      Check later with: python -m orchestrator.cli "
                  f"status {engagement_id}")
        else:
            print("\n  [!] Aborted before submitting.")
        return 130
