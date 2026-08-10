# Orchestrator TUI Step-by-Step Implementation

An interactive, form-driven interface for setting up an engagement and
watching it run. Invoked from the host with a single command:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli tui
```

The `start`, `watch`, and `status` subcommands stay as they are, unchanged 
they're still useful for scripts and CI. This adds a fourth subcommand
`tui` for interactive use.

## What the TUI does

1. Prints a banner.
2. Prompts for engagement inputs one field at a time (target URL, scope,
   optional time window, view mode). Client-side validation for the
   target URL.
3. Shows a review of what will be submitted; asks Y/n to proceed.
4. If the server rejects the spec (entry Guardrails), shows the reason
   and returns to the form.
5. Once accepted, streams every `audit_log` event for the engagement as
   it happens (event stream, not aggregated state). In `brief` view mode,
   filters out routine chain-movement events.
6. On terminal state (`engagement_complete`, `engagement_failed`, or
   `engagement_complete_with_warnings`), prints a summary table with
   per-agent final status.
7. Ctrl-C during streaming detaches the TUI; the engagement keeps
   running in the background. Re-attach with `status` later.


---

## Section 1: Create `orchestrator/tui.py`

Create a new file at `orchestrator/tui.py` with the exact contents below.

```python
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
```

Save the file. Nothing else in the project changes yet \u2014 this new module
isn't reachable from anywhere until Section 2 wires it in.

---

## Section 2: Register the `tui` subcommand in `orchestrator/cli.py`

Open `orchestrator/cli.py`. You need to add two small pieces: a handler
function and a subparser registration.

### 2.1 Add the handler function

Find the existing handler functions (`cmd_start`, `cmd_status`,
`cmd_watch`). **Add** this new one right after `cmd_watch`:

```python
def cmd_tui(args: argparse.Namespace) -> int:
    """Launch the interactive TUI."""
    from orchestrator.tui import run_tui
    return run_tui(args)
```

The lazy import (inside the function, not at module top) means
`cli.py` doesn't pay the import cost for `tui.py` unless the user
actually invokes the TUI subcommand.

### 2.2 Register the subparser

Find the block in `main()` that registers the other subparsers:

```python
    p_watch = sub.add_parser("watch", help="Follow an engagement until it finishes")
    p_watch.add_argument("engagement_id")
    p_watch.add_argument("--interval", type=float, default=2.0)
    p_watch.set_defaults(func=cmd_watch)
```

**Add** immediately after that block:

```python
    p_tui = sub.add_parser("tui",
        help="Interactive engagement setup with live event streaming")
    p_tui.set_defaults(func=cmd_tui)
```

The subparser takes no arguments everything the TUI needs is asked
for interactively, including the view-mode choice.

That's the entire wiring change.

---

## Section 3: Rebuild and smoke-test

```bash
docker compose build orchestrator
docker compose up -d --force-recreate orchestrator
```

Confirm the container is running:

```bash
docker compose ps orchestrator     # STATUS should be Up
```

Verify the subcommand is registered by asking for help:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli --help
```

You should see `tui` listed among the subcommands.

Ask for the TUI's own help no flags, no arguments:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli tui --help
```

Expected output:

```
usage: apts tui [-h]

options:
  -h, --help  show this help message and exit
```

If it errors with `ModuleNotFoundError: orchestrator.tui`, you didn't
rebuild the image after adding `tui.py` `docker compose build
orchestrator` picks up new source files.

---

## Section 4: Run through a real engagement (full stream)

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli tui
```

You'll see:

```
==============================================================
  APTS \u2014 Autonomous Penetration Testing System
  Interactive engagement setup
==============================================================

--- Engagement setup ---

  Target URL:
```

Type at each prompt (blank inputs are legal for scope and time-window
fields). At the last prompt, press Enter (or type `all`) for the full
event stream:

```
  Target URL: https://juice-shop.test/

  Scope (leave blank to skip a field):
    Allowed domains (comma-separated): *.juice-shop.test
    Allow paths (comma-separated):
    Deny paths (comma-separated):

  Time window (leave blank to omit):
    Start (YYYY-MM-DD HH:MM):
    End   (YYYY-MM-DD HH:MM):

  Output:
    View mode [all/brief] (default: all):
```

The review appears:

```
--- Review ---

  Target URL:  https://juice-shop.test/
  Domains:     ['*.juice-shop.test']
  Allow paths: (any)
  Deny paths:  (none)
  Time window: (none)
  View mode:   all

  Start engagement? [Y/n]:
```

Press Enter (or type `y`). Then the event stream starts. In full mode
you get around 30-40 lines for a normal happy-path run:

```
  Engagement started: 8b25...
  Streaming events (Ctrl-C to detach)...

--------------------------------------------------------------
  12:34:56  [orchestrator    ]  engagement_created
  12:34:56  [orchestrator    ]  kickoff_launched
  12:34:56  [agent-recon     ]  handoff_received
  12:34:56  [agent-recon     ]  progress_received  status=started
  12:35:00  [agent-recon     ]  result_written
  12:35:00  [agent-recon     ]  pushed_to_next  next=vuln
  12:35:00  [agent-recon     ]  progress_received  status=done
  12:35:00  [agent-vuln      ]  handoff_received
  ...
  12:35:32  [orchestrator    ]  engagement_complete
--------------------------------------------------------------

==============================================================
  Engagement summary
==============================================================
  ID:       8b25...
  Target:   https://juice-shop.test/
  Status:   complete
  Elapsed:  36.0s

  Agent      Final state          Attempts   Note
  ---------- -------------------- ---------- ------------------------------
  recon      done                 1
  vuln       done                 1
  mitre      done                 1
  exploit    done                 1
  script     done                 1
  adviser    done                 1
```

The command exits (returns to shell) when the engagement reaches a
terminal state.

---

## Section 5: Same engagement in brief mode

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli tui
```

Fill in the form the same way, but at the last prompt type `brief`
(or `b`):

```
  Output:
    View mode [all/brief] (default: all): brief
```

The review acknowledges it:

```
--- Review ---
  ...
  View mode:   brief
```

Confirm with Y. The event stream now shows ~10-15 lines for a
happy-path run:

```
--------------------------------------------------------------
  12:36:00  [orchestrator    ]  engagement_created
  12:36:00  [agent-recon     ]  progress_received  status=started
  12:36:04  [agent-recon     ]  progress_received  status=done
  12:36:04  [agent-vuln      ]  progress_received  status=started
  12:36:07  [agent-vuln      ]  progress_received  status=done
  12:36:07  [agent-mitre     ]  progress_received  status=started
  12:36:09  [agent-mitre     ]  progress_received  status=done
  12:36:09  [agent-exploit   ]  progress_received  status=started
  12:36:14  [agent-exploit   ]  progress_received  status=done
  12:36:14  [agent-script    ]  progress_received  status=started
  12:36:17  [agent-script    ]  progress_received  status=done
  12:36:17  [agent-adviser   ]  progress_received  status=started
  12:36:19  [agent-adviser   ]  progress_received  status=done
  12:36:19  [orchestrator    ]  engagement_complete
--------------------------------------------------------------
```

Same engagement, quieter output. Brief mode is useful when the run is
going well and you just want progress markers; full mode is useful when
something goes wrong and you want the whole story.

**Validation test at the view-mode prompt.** Bad input reprompts:

```
    View mode [all/brief] (default: all): xyz
    (please answer 'all' or 'brief')
    View mode [all/brief] (default: all):
```

Empty picks the default (all). Any of `a`, `all`, `A`, `ALL` full mode.
Any of `b`, `brief`, `B`, `BRIEF` brief mode. Anything else \u2192 reprompt.

---

## Section 6: Test the interesting cases

### 6.1 A server-rejected spec

Enter a malformed target and see the loop return to the form:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli tui
# Target URL: ftp://example.com/        client-side rejects, asks again
# Target URL: https://example.com/      accepted
# ...
```

Client-side validation catches the wrong-scheme case before it even
reaches the server. For a server-side rejection, populate the entry
allowlist so a specific host is required:

```bash
echo "juice-shop.test" > config/target_allowlist
docker compose up -d --force-recreate orchestrator
```

Then run the TUI with a target that's not on the list:

```
  Target URL: https://not-allowed.example/
  ...
  Start engagement? [Y/n]: y

  [!] server rejected the spec: 400 {"detail":"guardrails entry: target 'not-allowed.example' is not on the approved allowlist"}
      returning to the form...

--- Engagement setup ---
  Target URL:
```

Loops back cleanly. Reset:

```bash
: > config/target_allowlist
docker compose up -d --force-recreate orchestrator
```

### 6.2 A minor-agent skip case (best demonstration for the writeup)

Trigger the MITRE-skipped path from your earlier Section D testing. Run
with brief mode so the interesting events stand out:

```bash
echo "1.0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-mitre

docker exec -it apts-orchestrator python -m orchestrator.cli tui
# fill in the form as normal
# at the view mode prompt, type: brief
# confirm
```

Expected brief-mode transcript:

```
--------------------------------------------------------------
  12:40:12  [orchestrator    ]  engagement_created
  12:40:12  [agent-recon     ]  progress_received  status=started
  12:40:16  [agent-recon     ]  progress_received  status=done
  12:40:16  [agent-vuln      ]  progress_received  status=started
  12:40:19  [agent-vuln      ]  progress_received  status=done
  12:40:19  [agent-mitre     ]  progress_received  status=started
  12:40:21  [agent-mitre     ]  progress_received  status=failed
  12:40:21  [orchestrator    ]  retry_launched  attempt=1
  12:40:21  [agent-mitre     ]  progress_received  status=started
  12:40:23  [agent-mitre     ]  progress_received  status=failed
  12:40:23  [orchestrator    ]  retry_launched  attempt=2
  12:40:23  [agent-mitre     ]  progress_received  status=started
  12:40:25  [agent-mitre     ]  progress_received  status=failed
  12:40:25  [orchestrator    ]  retries_exhausted
  12:40:25  [orchestrator    ]  minor_agent_skipped
  12:40:25  [orchestrator    ]  chain_forwarded_past_skip  next=exploit input_from=vuln
  12:40:25  [agent-exploit   ]  progress_received  status=started
  12:40:30  [agent-exploit   ]  progress_received  status=done
  ...
  12:40:34  [orchestrator    ]  engagement_complete
--------------------------------------------------------------
```

Every design decision from v3-annotated \u00a72.2.4 is visible: three retry
attempts, exhaustion, skip decision, chain forwarded past the skipped
agent, and the chain resuming from Exploit with Vuln's data as input.

This is the transcript to include in your writeup as evidence that
\u00a72.2.4-annotated works end-to-end. Copy the exact terminal output.

Reset:

```bash
echo "0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-mitre
```

### 6.3 Ctrl-C during streaming

Start an engagement and hit Ctrl-C while events are still coming in:

```
  ... event stream ...
^C

  [!] Detached. Engagement 8b25... continues in the background.
      Check later with: python -m orchestrator.cli status 8b25...
```

The engagement is unaffected the TUI just stopped observing it. You
can re-attach later:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli status <ID>
```

Or run `watch` if the engagement is still ongoing.

---

## Section 7: Design notes for the writeup

Four points worth calling out in the project report:

**Two views of engagement state, one authoritative source.**
The orchestrator exposes engagement state in two shapes: an aggregated
snapshot via `GET /engagements/{id}` (per-agent status, retry counts) and
an unbounded event log in the `audit_log` table (every state transition,
with timestamp and structured payload). The `status` and `watch`
subcommands consume the snapshot; the `tui` subcommand tails the log.
Splitting the two lets each stay simple: the API returns a small object
in constant time; the log accumulates history that operators or
post-incident review can replay any time.

**Two verbosity levels selected in-form, not by CLI flag.**
The TUI asks `View mode [all/brief]` as part of the setup form rather
than exposing verbosity through a command-line switch. This keeps the
CLI signature minimal, and it makes both modes discoverable at first
use operators don't need to know a flag exists in order to switch
modes. Full mode shows every internal transition (useful when a run has
gone wrong and you want the full trace); brief mode filters routine
chain-movement events and shows only decision points (progress
transitions, retries, skips, terminal events). Same underlying data,
two views.

**Client-side UI state stays client-side.**
The form's view-mode choice is stored in the collected spec under an
underscore-prefixed key (`_brief`), and stripped by the submit function
before the POST to the orchestrator. Server-side validation
(`EngagementSpec`) never sees the field. This is a small piece of the
same principle the Characterization applies to Guardrails and to
tokens: information about how a client wants to display things is not
information the server needs to process.

**No new server code.**
The TUI is a pure CLI addition. It uses the existing `admin` API on
port 8080 to create engagements, and reads the existing `audit_log`
table to stream events. No orchestrator behaviour changed which
means the TUI is fully interchangeable with any other client (`curl`,
scripts, a future Web UI) that hits the same API.

---

## Section 8: Small future improvements

- **Per-agent colour or icon in the event stream.** Would need `rich` or
  ANSI escape codes. Improves scanability but not information content.
- **Cancel action.** Ctrl-C currently detaches without cancelling; the
  engagement continues in the background. A cancel action would require
  a new `POST /engagements/{id}/cancel` endpoint on the orchestrator
  plus cooperative-cancellation checks inside `_handle_agent_failure`
  and `_handle_minor_exhausted`.
- **History browser.** Optional subcommand to list past engagements and
  replay their audit logs. Every piece of data already exists in the DB;
  it just needs a `list` and a `replay` command.
- **A configurable brief-mode filter.** Currently `BRIEF_HIDE` is a
  hard-coded set at the top of `tui.py`. Could be exposed as an
  additional prompt (`Hide event types [default/custom]`) or read from
  a config file.

Each of these belongs to "future work" rather than "skeleton complete."
