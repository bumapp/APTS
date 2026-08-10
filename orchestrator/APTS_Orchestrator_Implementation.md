# Orchestrator Implementation — Step by Step

Complete the four remaining orchestrator gaps by editing
`orchestrator/main.py` in place. Every step includes exact code to type,
where it goes, and how to verify it worked before moving on.

## What you're implementing

| # | Gap | §Ref | Complexity |
|---|-----|------|------------|
| 1 | Stall detection — retry agents that hang without posting progress | §8 | medium |
| 2 | Minor-agent backup path — skip a failed minor agent, continue chain | §2.2.4 annotated | medium |
| 3 | Adviser exhaustion — complete engagement even if Adviser failed 3× | §2.2.4 annotated | small |
| 4 | Kickoff-failure cleanup — no orphaned "running" engagement rows | §3, §8 | small |

Plus two small fixes: an off-by-one in the retry check, and introducing a
`kicked_off` state that lets the stall scanner tell "not yet reached" apart
from "should be running by now."

## Prerequisites

* Skeleton is deployed and healthy (`docker compose ps` shows all 10
  services `Up`).
* A prior smoke test worked end-to-end (§6 of the deployment runbook).
* You're editing on the host in `~/apts/apts-skeleton/orchestrator/main.py`.


---

## Section A — Baseline

### A.1 Confirm current state works

Before touching anything, verify the current orchestrator is functional.

```bash
cd ~/apts/apts-skeleton
docker compose ps
```

Every service should show STATUS `Up`. If any are restarting, fix that
first — the changes below assume a working baseline.

Run one full engagement to confirm behaviour before changes:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
```

Copy the engagement ID and watch:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli watch <ENGAGEMENT_ID>
```

You should see the six agents transition `started → done` in order,
ending with `== engagement complete ==`. This is your baseline.

### A.2 Backup the current file

Small safety net — you can always diff against this if things get
confusing:

```bash
cp orchestrator/main.py orchestrator/main.py.baseline
```

---

## Section B — Helpers and small fixes

Three small changes that add nothing new visible from the outside but
set up the ground for everything after.

### B.1 Add new constants and helper

Open `orchestrator/main.py`.

Find the constants block near the top:

```python
CHAIN = ["recon", "vuln", "mitre", "exploit", "script", "adviser"]
CRITICAL_AGENTS = {"recon", "vuln", "exploit"}
MAX_RETRIES = 3
```

**Replace** that block with:

```python
CHAIN = ["recon", "vuln", "mitre", "exploit", "script", "adviser"]
CRITICAL_AGENTS = {"recon", "vuln", "exploit"}
MINOR_AGENTS   = {"mitre", "script", "adviser"}
MAX_RETRIES    = 3      # total attempts allowed per agent (initial + retries)

# Stall detection (Section E).  An agent that was kicked off but has not
# posted progress for STALL_TIMEOUT_SECONDS is treated as failed.
STALL_TIMEOUT_SECONDS = 60
STALL_SCAN_INTERVAL   = 10
```

Now find the existing helper:

```python
def _previous_agent(agent: str) -> str | None:
    idx = CHAIN.index(agent)
    return CHAIN[idx - 1] if idx > 0 else None
```

**Add** this helper immediately after it:

```python
def _next_agent(agent: str) -> str | None:
    """Return the next agent in the chain, or None if this is the Adviser."""
    idx = CHAIN.index(agent)
    return CHAIN[idx + 1] if idx < len(CHAIN) - 1 else None
```

### B.2 Fix the off-by-one retry check

Find, inside `_handle_agent_failure`:

```python
    if retry_count > MAX_RETRIES:
```

**Replace** with:

```python
    if retry_count >= MAX_RETRIES:
```

The comment above it needs updating too, but we'll rewrite the whole
function later in Section D — leave it for now.

### B.3 Introduce the `kicked_off` state

Find the existing `_kickoff_agent` function:

```python
async def _kickoff_agent(agent: str, handoff: ChainHandoff) -> None:
    assert _client is not None
    assert _OWN_TOKEN is not None
    url = f"https://agent-{agent}:8443/run"
    try:
        resp = await _client.post(
            url,
            content=handoff.model_dump_json(),
            headers=bearer_headers(_OWN_TOKEN),
        )
        resp.raise_for_status()
    except Exception as exc:
        log.error("failed to kick off %s: %s", agent, exc)
        audit("orchestrator", "kickoff_failed",
              engagement_id=str(handoff.engagement_id),
              detail={"agent": agent, "error": str(exc)})
        # We don't retry the kickoff itself here; the failure will surface when
        # the agent's status stays 'pending'.  Stall detection is a TODO.
        raise
```

**Replace** the whole function with:

```python
async def _kickoff_agent(agent: str, handoff: ChainHandoff) -> None:
    """Post the initial handoff to an agent's /run endpoint.

    On success, arm the stall timer for this agent by recording
    ``kicked_off`` in ``engagement_state``.  On failure, raise — the caller
    is responsible for routing the failure through the retry path.
    """
    assert _client is not None
    assert _OWN_TOKEN is not None
    url = f"https://agent-{agent}:8443/run"
    resp = await _client.post(
        url,
        content=handoff.model_dump_json(),
        headers=bearer_headers(_OWN_TOKEN),
    )
    resp.raise_for_status()

    _record_kickoff(handoff.engagement_id, agent)
    audit("orchestrator", "kickoff_launched",
          engagement_id=str(handoff.engagement_id),
          detail={"agent": agent})


def _record_kickoff(engagement_id: UUID, agent: str) -> None:
    """Mark an agent's state as kicked_off, arming the stall timer."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE engagement_state
               SET status = 'kicked_off',
                   updated_at = NOW()
               WHERE engagement_id = %s AND agent = %s""",
            (str(engagement_id), agent),
        )
```

Two behaviour changes here:
- The audit is moved to the success path (was previously only on failure).
- We no longer log-and-reraise; we just raise. Callers now handle the
  failure explicitly (Section C).

### B.4 Test what you've done so far

Rebuild the image and restart just the orchestrator:

```bash
docker compose build orchestrator
docker compose up -d --force-recreate orchestrator
docker compose ps orchestrator     # STATUS should be Up
docker compose logs --tail=10 orchestrator
```

You should see the usual startup lines, no errors.

Run a smoke test — behaviour should be identical to baseline:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
docker exec -it apts-orchestrator python -m orchestrator.cli watch <ENGAGEMENT_ID>
```

Six agents `started → done`, engagement complete. No visible change.

Verify the new state is being recorded:

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT event_type, count(*) FROM audit_log
        GROUP BY event_type ORDER BY count(*) DESC;"
```

You should see `kickoff_launched` events among the counts.

---

## Section C — Gap 4: Kickoff-failure cleanup

If a kickoff fails (agent unreachable, TLS error, whatever), the current
code raises the exception and leaves the engagement stuck in `running`
state forever. Fix by routing all kickoff failures through the retry
path, and cleaning up if the very first kickoff fails.

### C.1 Add the safe-kickoff wrapper

Find `_kickoff_agent` (the one you just rewrote in B.3).

**Add** this function immediately after it:

```python
async def _kickoff_agent_or_fail(agent: str, handoff: ChainHandoff) -> bool:
    """Call ``_kickoff_agent`` and route any exception through the retry path.

    Returns True on success, False if the failure was handled by the retry
    logic (which may have re-kicked the agent, exhausted it, or aborted the
    engagement).
    """
    try:
        await _kickoff_agent(agent, handoff)
        return True
    except Exception as exc:
        log.error("kickoff of %s failed: %s", agent, exc)
        audit("orchestrator", "kickoff_failed",
              engagement_id=str(handoff.engagement_id),
              detail={"agent": agent, "error": str(exc)})
        synthetic = ProgressUpdate(
            engagement_id=handoff.engagement_id,
            agent=agent,
            status="failed",
            message=f"kickoff failed: {exc}",
        )
        _record_progress(synthetic)
        await _handle_agent_failure(synthetic)
        return False
```

### C.2 Use it from `admin_start`

Find, inside `admin_start`:

```python
    await _kickoff_agent("recon", handoff)
    return StartEngagementResponse(engagement_id=engagement_id, status="running")
```

**Replace** with:

```python
    ok = await _kickoff_agent_or_fail("recon", handoff)
    if not ok:
        # The retry path handled it — either a retry was launched or the
        # engagement was marked failed.  Either way, tell the operator the
        # engagement was created; they can watch its state to see what
        # happened next.
        pass
    return StartEngagementResponse(engagement_id=engagement_id, status="running")
```

### C.3 Use it from `_handle_agent_failure` too

Find, at the very end of `_handle_agent_failure`:

```python
    log.info("retry #%d for agent %s (engagement %s)", retry_count, agent, update.engagement_id)
    audit("orchestrator", "retry_launched",
          engagement_id=str(update.engagement_id),
          detail={"agent": agent, "attempt": retry_count})
    await _kickoff_agent(agent, handoff)
```

**Replace** the last line with:

```python
    log.info("retry #%d for agent %s (engagement %s)", retry_count, agent, update.engagement_id)
    audit("orchestrator", "retry_launched",
          engagement_id=str(update.engagement_id),
          detail={"agent": agent, "attempt": retry_count})
    await _kickoff_agent_or_fail(agent, handoff)
```

Now every kickoff failure — initial or retry — flows through the retry
path instead of raising.

### C.4 Test

Rebuild and restart:

```bash
docker compose build orchestrator
docker compose up -d --force-recreate orchestrator
```

**Happy-path test** — normal engagement should still work:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
# should print engagement_id + status: running
```

Watch it complete normally.

**Failure-path test** — stop recon before starting an engagement, so its
kickoff fails:

```bash
docker compose stop agent-recon

# Try to start an engagement
docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
# prints an engagement_id (creation succeeded)

# Check what the engagement's state is
docker exec -it apts-orchestrator python -m orchestrator.cli status <ENGAGEMENT_ID>
```

You'll see `recon` in `failed` state with the kickoff-failed message. The
retry logic will keep trying (up to `MAX_RETRIES` = 3 total attempts).
Each attempt fails the same way, so eventually the engagement is marked
`failed`:

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT status FROM engagements ORDER BY created_at DESC LIMIT 1;"
# should show: failed
```

Bring recon back for the next tests:

```bash
docker compose start agent-recon
```

---

## Section D — Gaps 2 & 3: Minor-agent backup + Adviser exhaustion

The v3-annotated §2.2.4 says minor agents (MITRE, Script, Adviser)
letting the chain continue after exhausting retries. The backup paths:

- **MITRE exhausted** → skip MITRE, kick off Exploit with **Vuln's**
  weakness list as input.
- **Script exhausted** → skip Script, kick off Adviser with **Exploit's**
  evidence as input (Adviser reads from DB anyway, so it will find
  everything).
- **Adviser exhausted** → engagement is marked complete-with-warnings.
  No final report was generated, but stored results are preserved.

### D.1 Add helpers for skipped-state and partial completion

Find, in the DB helpers section:

```python
def _mark_engagement_complete(engagement_id: UUID) -> None:
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE engagements SET status = 'complete', completed_at = NOW()
               WHERE id = %s""",
            (str(engagement_id),),
        )
    log.info("engagement %s complete", engagement_id)
    audit("orchestrator", "engagement_complete", engagement_id=str(engagement_id))
```

**Add** these two functions right after it:

```python
def _mark_engagement_complete_partial(engagement_id: UUID, reason: str) -> None:
    """Mark an engagement complete despite one or more minor agents having failed.

    Used when a minor agent (MITRE, Script, Adviser) exhausted its retries
    and the chain either continued with a backup path or ended without a
    final report from the Adviser.  The engagement is still 'complete' from
    the operator's point of view — only the record notes what was skipped.
    """
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE engagements SET status = 'complete_with_warnings',
                                       completed_at = NOW()
               WHERE id = %s""",
            (str(engagement_id),),
        )
    log.warning("engagement %s complete with warnings: %s", engagement_id, reason)
    audit("orchestrator", "engagement_complete_with_warnings",
          engagement_id=str(engagement_id), detail={"reason": reason})


def _mark_agent_skipped(engagement_id: UUID, agent: str) -> None:
    """Record that a minor agent was skipped after retries exhausted."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE engagement_state
               SET status = 'skipped', updated_at = NOW()
               WHERE engagement_id = %s AND agent = %s""",
            (str(engagement_id), agent),
        )
    audit("orchestrator", "minor_agent_skipped",
          engagement_id=str(engagement_id), detail={"agent": agent})
```

### D.2 Rewrite the exhaustion branch inside `_handle_agent_failure`

Find, inside `_handle_agent_failure`, the block that currently handles
exhaustion:

```python
    if retry_count >= MAX_RETRIES:
        log.error("%s exhausted retries (%d) for engagement %s",
                  agent, MAX_RETRIES, update.engagement_id)
        audit("orchestrator", "retries_exhausted",
              engagement_id=str(update.engagement_id),
              detail={"agent": agent, "retry_count": retry_count})
        if agent in CRITICAL_AGENTS:
            _mark_engagement_failed(update.engagement_id, reason=f"{agent} failed 3 times")
        return
```

**Replace** with:

```python
    if retry_count >= MAX_RETRIES:
        log.error("%s exhausted retries (%d) for engagement %s",
                  agent, MAX_RETRIES, update.engagement_id)
        audit("orchestrator", "retries_exhausted",
              engagement_id=str(update.engagement_id),
              detail={"agent": agent, "retry_count": retry_count})

        if agent in CRITICAL_AGENTS:
            # §2.2.4 (annotated): a critical agent that cannot produce output
            # ends the run — no downstream agent can proceed without it.
            _mark_engagement_failed(update.engagement_id,
                                    reason=f"{agent} failed {MAX_RETRIES} times")
            return

        # Minor agent — skip it and continue the chain from the next stage.
        await _handle_minor_exhausted(update.engagement_id, agent)
        return
```

### D.3 Add the minor-exhausted handler

**Add** this new function immediately after `_handle_agent_failure`:

```python
async def _handle_minor_exhausted(engagement_id: UUID, agent: str) -> None:
    """A minor agent exhausted its retries.  Skip it, continue the chain.

    Backup paths (§2.2.4 annotated):
      * MITRE  → Exploit runs on Vuln's raw weakness list
      * Script → Adviser runs on Exploit's evidence (Adviser reads from DB)
      * Adviser → engagement is complete-with-warnings
    """
    _mark_agent_skipped(engagement_id, agent)

    next_agent = _next_agent(agent)
    if next_agent is None:
        # Adviser is the terminal agent — nothing to hand off to.
        _mark_engagement_complete_partial(
            engagement_id,
            reason=f"{agent} skipped after {MAX_RETRIES} retries; no final report")
        return

    # Feed the next agent the output of the stage BEFORE the failed one, so
    # it starts with the same input the failed agent would have processed.
    predecessor_of_failed = _previous_agent(agent)
    payload = _load_prev_output(engagement_id, predecessor_of_failed)

    handoff = ChainHandoff(
        engagement_id=engagement_id,
        from_component="orchestrator",
        target_url=payload["target_url"],
        scope=payload["scope"],
        time_window=payload.get("time_window"),
        results=payload.get("results", {}),
    )

    log.warning("minor agent %s skipped; forwarding to %s using %s's output",
                agent, next_agent, predecessor_of_failed)
    audit("orchestrator", "chain_forwarded_past_skip",
          engagement_id=str(engagement_id),
          detail={"skipped": agent, "next": next_agent,
                  "input_from": predecessor_of_failed})

    await _kickoff_agent_or_fail(next_agent, handoff)
```

### D.4 Handle Adviser's successful completion when Script was skipped

There's a subtle case: if Script was skipped, Adviser will still receive
its handoff and post `done` normally — the existing code marks the
engagement `complete` in that case. Good.

But if Adviser itself exhausts, we mark it `complete_with_warnings`
instead. Verify that the `progress` handler still routes Adviser's `done`
to the right place. Find:

```python
    # If the Adviser reports done, the engagement is complete.
    if update.agent == "adviser" and update.status == "done":
        _mark_engagement_complete(update.engagement_id)
```

No change needed — this is correct as-is. Adviser's `done` marks
`complete`; Adviser's exhaustion marks `complete_with_warnings` via
`_handle_minor_exhausted`. Both paths reach a terminal state.

###Open orchestrator/cli.py:

Change that line from:
```python
        if body["status"] in ("complete", "failed"):
		```
to:
```python
        if body["status"] in ("complete", "failed", "complete_with_warnings"):
		```


### D.5 Test

Rebuild:

```bash
docker compose build orchestrator
docker compose up -d --force-recreate orchestrator
```

**Test MITRE exhaustion → chain continues via backup path.**

Force MITRE to fail every time by cranking its failure rate:

```bash
# Temporarily set a 100% failure rate ONLY for MITRE by editing the
# stub_failure_rate for the mitre agent.  Since our config is global,
# we set it high and restart just MITRE.
echo "1.0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-mitre
```

Reset the other agents by setting their failure rate back to 0. Since
config is global, you need to restart the others without picking up the
new value — but they've been running with the old value, and it was
already 0. Let me instead use a different approach: only agent-mitre
will pick up the new setting because we're only restarting it.

Start an engagement:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
docker exec -it apts-orchestrator python -m orchestrator.cli watch <ENGAGEMENT_ID>
```

Expected output:

```
[   recon]  started
[   recon]  done
[    vuln]  started
[    vuln]  done
[   mitre]  started
[   mitre]  failed
[   mitre]  started
[   mitre]  failed
[   mitre]  started
[   mitre]  failed
[   mitre]  skipped        ← NEW! minor agent skipped after 3 failures
[ exploit]  started        ← chain continues!
[ exploit]  done
[  script]  started
[  script]  done
[ adviser]  started
[ adviser]  done

== engagement complete ==
```

Verify in the DB:

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT status, completed_at FROM engagements
        ORDER BY created_at DESC LIMIT 1;"
# status: complete (Adviser posted done — not complete_with_warnings,
# because Adviser succeeded)

docker compose exec -T database psql -U apts -d apts \
    -c "SELECT event_type, detail
        FROM audit_log
        WHERE engagement_id = '<ENGAGEMENT_ID>'
          AND event_type IN ('chain_forwarded_past_skip', 'minor_agent_skipped')
        ORDER BY logged_at;"
```

You should see the `minor_agent_skipped` event for `mitre` and the
`chain_forwarded_past_skip` event showing next=exploit, input_from=vuln.

**Reset for the next test:**

```bash
echo "0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-mitre
```

**Test Adviser exhaustion → engagement complete_with_warnings.**

Same approach but target the Adviser:

```bash
echo "1.0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-adviser

docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
docker exec -it apts-orchestrator python -m orchestrator.cli watch <ENGAGEMENT_ID>
```

You should see recon through script succeed normally, then Adviser fail
3 times, then:

```
[ adviser]  skipped

== engagement complete_with_warnings ==
```

Verify:

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT status FROM engagements ORDER BY created_at DESC LIMIT 1;"
# should show: complete_with_warnings
```

Reset:

```bash
echo "0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-adviser
```

---

## Section E — Gap 1: Stall detection

An agent that was kicked off but never posts progress (crashed at
startup, network broke mid-run, container killed) currently leaves the
engagement stuck forever. Detect this by periodically scanning
`engagement_state` for rows that have been in an active state too long
without an update.

### E.1 Add the stall-scanner functions

Find the section marked:

```python
# --------------------------------------------------------------------------- #
# Retry logic (§2.2.4)
# --------------------------------------------------------------------------- #
```

**Add** this new section immediately before it:

```python
# --------------------------------------------------------------------------- #
# Stall detection (§8)
# --------------------------------------------------------------------------- #

async def _stall_scanner() -> None:
    """Background task: periodically look for stalled agents.

    An agent is considered stalled if its ``engagement_state`` row is in an
    active state (``kicked_off``, ``started``, ``in_progress``) and its
    ``updated_at`` is older than ``STALL_TIMEOUT_SECONDS`` ago.  Each stall
    is treated as an implicit failure and routed through the retry path.
    """
    log.info("stall scanner started (timeout=%ds, interval=%ds)",
             STALL_TIMEOUT_SECONDS, STALL_SCAN_INTERVAL)
    try:
        while True:
            await asyncio.sleep(STALL_SCAN_INTERVAL)
            try:
                await _scan_once()
            except Exception as exc:
                log.error("stall scan raised: %s", exc)
    except asyncio.CancelledError:
        log.info("stall scanner stopping")
        raise


async def _scan_once() -> None:
    """One pass over the DB looking for stalled agents."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT es.engagement_id, es.agent, es.updated_at
               FROM engagement_state es
               JOIN engagements e ON e.id = es.engagement_id
               WHERE e.status = 'running'
                 AND es.status IN ('kicked_off', 'started', 'in_progress')
                 AND es.updated_at < NOW() - make_interval(secs => %s)""",
            (STALL_TIMEOUT_SECONDS,),
        )
        stalled = cur.fetchall()

    for engagement_id, agent, updated_at in stalled:
        log.warning("stall detected: engagement=%s agent=%s (last update %s)",
                    engagement_id, agent, updated_at)
        audit("orchestrator", "stall_detected",
              engagement_id=str(engagement_id),
              detail={"agent": agent,
                      "last_update": updated_at.isoformat(),
                      "timeout_seconds": STALL_TIMEOUT_SECONDS})

        synthetic = ProgressUpdate(
            engagement_id=engagement_id,
            agent=agent,
            status="failed",
            message=(f"stall detected: no progress for at least "
                     f"{STALL_TIMEOUT_SECONDS}s"),
        )
        _record_progress(synthetic)
        try:
            await _handle_agent_failure(synthetic)
        except Exception as exc:
            log.error("stall recovery for %s/%s raised: %s",
                      engagement_id, agent, exc)
```

### E.2 Launch the scanner from `lifespan`

Find the `lifespan` context manager near the top of the file:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _OWN_TOKEN, _client
    _OWN_TOKEN = load_own_token()
    _client = httpx.AsyncClient(
        verify=client_ssl_context(),
        timeout=httpx.Timeout(30.0, connect=5.0),
    )
    log.info("orchestrator ready (chain=%s)", CHAIN)
    audit("orchestrator", "startup")
    try:
        yield
    finally:
        await _client.aclose()
        audit("orchestrator", "shutdown")
```

**Replace** it with:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _OWN_TOKEN, _client
    _OWN_TOKEN = load_own_token()
    _client = httpx.AsyncClient(
        verify=client_ssl_context(),
        timeout=httpx.Timeout(30.0, connect=5.0),
    )
    log.info("orchestrator ready (chain=%s)", CHAIN)
    audit("orchestrator", "startup")

    # Background: stall detection (§8)
    scanner = asyncio.create_task(_stall_scanner(), name="stall_scanner")

    try:
        yield
    finally:
        scanner.cancel()
        try:
            await scanner
        except asyncio.CancelledError:
            pass
        await _client.aclose()
        audit("orchestrator", "shutdown")
```

Only the `scanner = asyncio.create_task(...)` and the corresponding
cancel-and-await block in `finally` are new. The rest is unchanged.

### E.3 Handle the scanner-only server-thread issue

**Important architectural note**: the orchestrator currently runs two
uvicorn servers, one in the main thread (`_run_public()`) and one in a
background thread (`_run_admin()`). Each has its own event loop. The
`lifespan` hook only runs on `app` (the public server), so the stall
scanner will attach to the public server's event loop. That's fine —
the scanner reads the DB and posts progress records via `_record_progress`
(sync) and calls `_handle_agent_failure` (async in the public loop).
`_handle_agent_failure` calls `_kickoff_agent_or_fail` which uses the
shared `_client` (an `httpx.AsyncClient`) — which was created on the
public loop, so it can only be used from the public loop. This is fine
because the scanner runs on that same loop.

No code change needed here — just be aware that if you ever move the
scanner elsewhere, it has to stay on the public server's event loop.

### E.4 Test the scanner in a benign case

Rebuild and start:

```bash
docker compose build orchestrator
docker compose up -d --force-recreate orchestrator
docker compose logs --tail=20 orchestrator
```

Look for the line `stall scanner started (timeout=60s, interval=10s)` —
that's the scanner announcing itself.

Run a normal engagement:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
docker exec -it apts-orchestrator python -m orchestrator.cli watch <ENGAGEMENT_ID>
```

Should complete normally, ~20 seconds. No stall detection should fire
(stub agents complete in ~4 seconds, well under the 60-second timeout).

Confirm no false positives:

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT count(*) FROM audit_log WHERE event_type = 'stall_detected';"
# should be 0
```

### E.5 Test the scanner with an actual stall

To simulate a stall, kill one of the agent containers mid-engagement.
Docker will restart it (per the compose file's `restart: unless-stopped`),
but the in-flight background task is lost.

Terminal 1: start a long-running engagement. To make the agent take
longer, temporarily bump the stub delay:

```bash
# Edit config/stub_failure_rate is not what we want — we need to bump
# the agent's delay.  For the skeleton, the cleanest way is to just
# kill agent-vuln shortly after it starts running.
```

Terminal 1:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
# note the engagement_id
```

Immediately in Terminal 2, wait a few seconds for vuln to start, then
kill it:

```bash
# Watch progress in one shell
docker exec -it apts-orchestrator python -m orchestrator.cli watch <ENGAGEMENT_ID>
```

In another shell, once `[vuln] started` appears, kill the vuln container:

```bash
docker kill apts-agent-vuln
```

Docker's restart policy will bring vuln back within a few seconds — but
the background task that was doing its stub work is gone. The
`engagement_state` row is stuck at `started` with an old `updated_at`.

Wait for the timeout (60 seconds). The scanner should detect the stall
and mark vuln as `failed`, triggering a retry:

```
[    vuln]  failed
[    vuln]  started      ← retry!
[    vuln]  done
[   mitre]  started
...
```

Verify the stall was recorded:

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT event_type, detail FROM audit_log
        WHERE engagement_id = '<ENGAGEMENT_ID>'
          AND event_type = 'stall_detected';"
```

You should see one row with `agent=vuln` and the timeout details.

### E.6 Tune the timeout for real workloads

The 60-second default is fine for stub agents but too aggressive once
real models come in. To change it:

```bash
# edit orchestrator/main.py, change STALL_TIMEOUT_SECONDS
docker compose build orchestrator
docker compose up -d --force-recreate orchestrator
```

For the modelling phase, expect model-backed agents to legitimately take
2–5 minutes each. Bump `STALL_TIMEOUT_SECONDS` to something like 600
(10 minutes) once you're running real models.

---

## Section F — Complete-engagement verification

Two more sanity checks to confirm the whole design works.

### F.1 Critical agent still stops the engagement

```bash
echo "1.0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-vuln

docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
docker exec -it apts-orchestrator python -m orchestrator.cli watch <ENGAGEMENT_ID>
```

Expected: Vuln fails 3 times, then engagement is marked `failed` (not
`complete_with_warnings`, because Vuln is critical):

```
[   recon]  started
[   recon]  done
[    vuln]  started
[    vuln]  failed
[    vuln]  started
[    vuln]  failed
[    vuln]  started
[    vuln]  failed

== engagement failed ==
```

Verify:

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT status FROM engagements ORDER BY created_at DESC LIMIT 1;"
# failed
```

Reset:

```bash
echo "0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-vuln
```

### F.2 Multiple minor failures compound

Push Script to fail always, and see the chain still complete:

```bash
echo "1.0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-script

docker exec -it apts-orchestrator python -m orchestrator.cli start \
    --target=https://juice-shop.test/ --domain='*.juice-shop.test'
docker exec -it apts-orchestrator python -m orchestrator.cli watch <ENGAGEMENT_ID>
```

Expected: Recon → Vuln → MITRE → Exploit succeed; Script fails 3 times
and is skipped; Adviser runs on Exploit's evidence and posts `done`. The
engagement ends `complete` because Adviser succeeded — the fact that
Script was skipped is recorded in the audit log but doesn't degrade the
final state (Adviser reads what it needs from the DB).

Reset:

```bash
echo "0" > config/stub_failure_rate
docker compose up -d --force-recreate agent-script
```

---

## Section G — Audit-log queries for the writeup

Useful queries to demonstrate that everything works, for your project
report:

### G.1 Timeline of one engagement

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT logged_at, component, event_type, detail
        FROM audit_log
        WHERE engagement_id = '<ENGAGEMENT_ID>'
        ORDER BY logged_at;"
```

Shows every state transition end-to-end.

### G.2 Retry statistics across all engagements

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT agent, sum(retry_count) AS total_retries
        FROM engagement_state
        WHERE retry_count > 0
        GROUP BY agent
        ORDER BY total_retries DESC;"
```

### G.3 All stall detections

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT logged_at, engagement_id, detail
        FROM audit_log
        WHERE event_type = 'stall_detected'
        ORDER BY logged_at DESC;"
```

### G.4 Skipped minor agents across engagements

```bash
docker compose exec -T database psql -U apts -d apts \
    -c "SELECT logged_at, engagement_id, detail
        FROM audit_log
        WHERE event_type IN ('minor_agent_skipped',
                             'chain_forwarded_past_skip',
                             'engagement_complete_with_warnings')
        ORDER BY logged_at DESC;"
```

---

## Section H — What's not in this implementation

For the writeup, these are the honest limits of what you've built here:

- **The scanner is single-loop.** It runs in the same event loop as the
  public HTTPS server. A very busy orchestrator could delay stall
  detection. For a skeleton this is fine; for production you'd want to
  measure scan latency and consider a dedicated worker.
- **`STALL_TIMEOUT_SECONDS` is global.** Every agent uses the same
  threshold. Real agents will need per-agent timeouts (Recon might
  legitimately take 10× as long as MITRE).
- **`_kickoff_agent_or_fail` recursion depth.** If the retry path itself
  fails, the failure re-enters `_handle_agent_failure` synchronously.
  Depth is bounded by `MAX_RETRIES`, so 3–4 levels max. Fine for now.
- **No streaming to operator.** The CLI still polls. Adequate for SSH
  use; would want SSE or WebSocket for a real UI.
- **No timeout on the HTTP client.** The httpx `AsyncClient` has a
  30-second default, but a slow agent might legitimately take longer.

Each of these is a legitimate follow-up for the modelling phase or a
"future work" bullet in the report.

---

## Section I — Rollback plan

If any step breaks the orchestrator badly and you need to reset:

```bash
cp orchestrator/main.py.baseline orchestrator/main.py
docker compose build orchestrator
docker compose up -d --force-recreate orchestrator
```

Restores the pre-implementation state.

---

## Section J — Summary

What you now have, compared to the baseline:

| Behaviour | Before | After |
|-----------|--------|-------|
| Explicit agent failure | Retried up to 3 total attempts, critical → engagement failed, minor → chain stops | Retried up to 3 total attempts (fixed off-by-one), critical → engagement failed, **minor → chain continues via backup path** |
| Agent stalls silently | Engagement hangs forever | **Detected within 60 s; treated as failure, routed through retry path** |
| Adviser exhausts retries | Engagement hangs forever | **Marked `complete_with_warnings`** |
| Kickoff fails at start | Engagement orphaned in `running` state | **Retried; if all retries fail, engagement marked failed** |
| Kickoff fails on retry | Exception escapes progress handler | **Routed through retry path** |

Every change lands in `orchestrator/main.py` alone — the shared modules,
the agents, and the MCP tools container are untouched. This is the
completed orchestrator per §2.2.4-annotated and §8 of the Characterization.
