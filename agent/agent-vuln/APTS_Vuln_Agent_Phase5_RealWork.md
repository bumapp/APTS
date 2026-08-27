# Vuln Agent — Phase 5: The Real Work Function

Fifth of six phases. Phases 1-4 built infrastructure (Ollama, Juice Shop,
MCP tools, model wrapper). This phase replaces the vuln agent's stub with
real reasoning + real probing, produces real findings, and writes them to
the DB.

Everything else stays stub. When you run an engagement after this phase:
Recon-stub → Vuln-REAL → MITRE-stub → Exploit-stub → Script-stub →
Adviser-stub. The vuln agent's findings land in `agent_results` and are
inspectable via the DB and audit log, even though downstream stubs ignore
their content.

## What this phase delivers

By the end of Phase 5 you will have:
- `STALL_TIMEOUT_SECONDS = 300` in orchestrator (was 60) — enough headroom
  for real model calls
- `AGENT_MODE=stub|real` environment variable on `agent-vuln`; defaults to
  `stub` so nothing changes unless you explicitly flip it
- A new module `agent/real_vuln.py` implementing the real reasoning loop:
  planning call, probe execution with heartbeats between probes, structured
  finding aggregation
- Prompt engineering for SQLi and XSS analysis in that module
- A full engagement against Juice Shop that produces real, inspectable
  findings written to `agent_results`
- Audit-log evidence you can point to in the writeup

Time budget: **6-10 hours**, most of it in Section D (prompt tuning against
Juice Shop's actual responses).

---

## Section A — Design decisions

Before writing code, five choices to be explicit about.

**Sequence of model calls per engagement.**

```
1. Planning call     (~155s)  Which endpoints to probe, which payloads
2. Probe 1 execution
   - MCP http_request                                  (~2s)
   - Analysis call    (~155s)  Vulnerable? Confidence? Evidence?
3. Probe 2 execution                                   (~157s)
4. Probe 3 execution                                   (~157s)
5. Probe 4 execution                                   (~157s)
Total: ~13 minutes for a 4-probe engagement
```

The planning call up front means the model's own analysis picks the
probes rather than us hard-coding them. For the skeleton, we use a
hybrid: the model reviews a small pre-defined probe menu and picks which
to run — this bounds latency and keeps prompts simple. In a follow-up
phase this could be fully open-ended.

**Heartbeats between probes.** Each probe cycle is ~157 seconds. The
orchestrator's stall scanner fires if an agent hasn't updated
`engagement_state.updated_at` for `STALL_TIMEOUT_SECONDS`. Two responses:

1. Bump `STALL_TIMEOUT_SECONDS` from 60 to 300 (5 min).
2. Post `progress: in_progress` heartbeats from the vuln agent before
   each probe. Each heartbeat resets `updated_at`.

Belt and braces. If a heartbeat is missed, the 5-minute timeout still
saves the engagement from an actual stall.

**Probe selection for Juice Shop.** Four probes, covering both target
categories from Q6:

| # | Endpoint | Payload | Tests |
|---|----------|---------|-------|
| 1 | `POST /rest/user/login` | email = tautology payload | SQLi auth bypass |
| 2 | `POST /rest/user/login` | email = UNION payload | SQLi data extraction |
| 3 | `GET /rest/products/search?q=` | q = `<script>` payload | Reflected XSS |
| 4 | `GET /rest/products/search?q=` | q = SQL error trigger | SQLi in search |

Four is a compromise between coverage and total engagement runtime
(~13 minutes at four probes). Adding more is one config-list edit if
future work wants to.

**Output shape.** The vuln agent's stub currently produces something
like `{"weaknesses": [...]}`. Real mode produces a richer object with
both probe-by-probe evidence and a summary weakness list:

```json
{
  "target_url": "http://juice-shop.test:3000/",
  "probes_executed": [
    {"probe_id": "...", "endpoint": "...", "test_type": "sqli",
     "response_status": 401, "analysis": {"vulnerable": false, ...}}
  ],
  "weaknesses": [
    {"cwe": "CWE-89", "location": "/rest/user/login", "confidence": "medium",
     "evidence": "..."}
  ]
}
```

Downstream stubs (MITRE, Exploit, etc.) don't care about the shape —
they just push their own stub outputs. The interesting data lives in
`agent_results` and the audit log.

**Bypass failure injection.** The existing stub applies `FAILURE_RATE`
to randomly fail. When `AGENT_MODE=real`, we route around this — a model
call that takes 155 seconds should not randomly be killed by simulated
failure. The dispatch check at the top of `_perform_work` handles this
cleanly.

---

## Section B — Bump the stall timeout

Open `orchestrator/main.py`. Find the constant from the orchestrator work:

```python
STALL_TIMEOUT_SECONDS = 60
```

**Replace** with:

```python
STALL_TIMEOUT_SECONDS = 300   # 5 min; sized for real model calls (Phase 5)
```

Rebuild only the orchestrator (agents are unaffected):

```bash
docker compose build orchestrator
docker compose up -d --force-recreate orchestrator
```

Verify:

```bash
docker compose logs --tail=5 orchestrator | grep "stall scanner started"
# should show: stall scanner started (timeout=300s, interval=10s)
```

No engagement runs yet — this is prep only.

---

## Section C — Add the `AGENT_MODE` toggle

Open `docker-compose.yml`. Find the `agent-vuln` service definition. Find
its `environment:` block (or add one if there isn't one).

**Add** to that `environment:` block:

```yaml
    environment:
      # ... whatever's already there ...
      AGENT_MODE: "${AGENT_MODE:-stub}"
```

The `${AGENT_MODE:-stub}` syntax means: read the `AGENT_MODE` shell
variable if set; if unset, default to `stub`. This gives you a
single-command flip without editing YAML each time.

Save. Recreate the container so it picks up the env var:

```bash
docker compose up -d --force-recreate agent-vuln
```

Verify:

```bash
docker exec apts-agent-vuln printenv AGENT_MODE
# should print: stub
```

To flip to real mode temporarily (we'll actually do this in Section F):

```bash
export AGENT_MODE=real
docker compose up -d --force-recreate agent-vuln
docker exec apts-agent-vuln printenv AGENT_MODE   # → real
```

To flip back:

```bash
unset AGENT_MODE
docker compose up -d --force-recreate agent-vuln
docker exec apts-agent-vuln printenv AGENT_MODE   # → stub
```

Keep it at `stub` for now. We'll flip in Section F when real code is
ready.

---

## Section D — Create `agent/real_vuln.py`

The main event. Before writing the file, verify one thing about your
skeleton's shared modules — the location of `client_ssl_context`:

```bash
grep -rn "def client_ssl_context\|client_ssl_context =" --include="*.py" shared/
```

Note the module it lives in (commonly `shared/tls.py`, sometimes
`shared/auth.py` or `shared/http.py`). You'll need to substitute this
into one line of the code below.

Create the file with these exact contents (adjusting the marked import
line for your skeleton):

```python
"""Real vuln agent work function (Phase 5).

Invoked from the agent's dispatch when ``AGENT_MODE=real`` is set on the
agent-vuln container.  Uses:

  * shared/model.py         -- LLM calls (Phase 4)
  * MCP /tools/http_request -- HTTP probes against the target (Phase 3)
  * MCP /tools/parse_forms  -- optional HTML form parsing (Phase 3)
  * orchestrator /progress  -- heartbeat updates (this phase)

Sequence per engagement (all timings on 8 CPU / 32 GB RAM, no GPU):

  1. Planning call (~155s):   model picks which probes to run from menu
  2. For each probe:
       heartbeat to orchestrator
       MCP http_request     (~2s)
       analysis call (~155s): model interprets the response

Four-probe engagement runs in ~13 minutes.
"""
from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlencode
from uuid import UUID

import httpx

from shared.auth import bearer_headers, load_own_token
from shared.model import reason_then_format

log = logging.getLogger(__name__)

MCP_URL          = "https://mcp-tools:8443"
ORCHESTRATOR_URL = "https://orchestrator:8443"


# --------------------------------------------------------------------------- #
# Probe menu -- the closed set the planning call chooses from.
# --------------------------------------------------------------------------- #

PROBE_MENU: list[dict[str, Any]] = [
    {
        "id":         "login_sqli_tautology",
        "name":       "Login SQL injection (tautology)",
        "endpoint":   "/rest/user/login",
        "method":     "POST",
        "test_type":  "sqli",
        "payload":    {"email": "admin' OR '1'='1--", "password": "any"},
        "purpose":    "attempt authentication bypass via tautology",
    },
    {
        "id":         "login_sqli_union",
        "name":       "Login SQL injection (UNION)",
        "endpoint":   "/rest/user/login",
        "method":     "POST",
        "test_type":  "sqli",
        "payload":    {"email": "a' UNION SELECT NULL,NULL,NULL--",
                       "password": "any"},
        "purpose":    "attempt data extraction via UNION",
    },
    {
        "id":         "search_xss_script",
        "name":       "Search reflected XSS",
        "endpoint":   "/rest/products/search",
        "method":     "GET",
        "test_type":  "xss",
        "query":      {"q": "<script>alert(1)</script>"},
        "purpose":    "check whether the search endpoint reflects HTML unescaped",
    },
    {
        "id":         "search_sqli_error",
        "name":       "Search SQL injection (error-based)",
        "endpoint":   "/rest/products/search",
        "method":     "GET",
        "test_type":  "sqli",
        "query":      {"q": "'"},
        "purpose":    "trigger a SQL error to reveal query structure",
    },
]


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

async def perform_vuln_work_real(handoff) -> dict[str, Any]:
    """Real vuln agent: plan, probe, analyze, aggregate.

    ``handoff`` is the ChainHandoff object the agent received.  Returns a
    dict that gets written to agent_results and pushed to the next agent.
    """
    target_url    = handoff.target_url
    engagement_id = handoff.engagement_id

    log.info("real vuln work start: target=%s engagement=%s",
             target_url, engagement_id)

    # 1. Planning call: which probes to run?
    await _heartbeat(engagement_id, "planning probes")
    selected_ids = await _plan_probes(target_url)
    log.info("planned %d probes: %s", len(selected_ids), selected_ids)

    # 2. Execute each probe
    probes_executed: list[dict[str, Any]] = []
    weaknesses:      list[dict[str, Any]] = []
    for i, probe_id in enumerate(selected_ids, 1):
        probe = next((p for p in PROBE_MENU if p["id"] == probe_id), None)
        if probe is None:
            log.warning("planner asked for unknown probe %r, skipping", probe_id)
            continue

        await _heartbeat(engagement_id,
                         f"probe {i}/{len(selected_ids)}: {probe['name']}")

        record = await _execute_probe(probe, target_url)
        probes_executed.append(record)

        # Aggregate confirmed findings into the weakness list
        analysis = record.get("analysis", {})
        if analysis.get("vulnerable") is True:
            weaknesses.append({
                "cwe":        analysis.get("cwe", ""),
                "location":   probe["endpoint"],
                "confidence": analysis.get("confidence", "low"),
                "evidence":   analysis.get("evidence", ""),
                "probe_id":   probe["id"],
            })

    return {
        "target_url":       target_url,
        "probes_executed":  probes_executed,
        "weaknesses":       weaknesses,
    }


# --------------------------------------------------------------------------- #
# Planning
# --------------------------------------------------------------------------- #

async def _plan_probes(target_url: str) -> list[str]:
    """Ask the model to pick which probes to run from the menu.

    Returns a list of probe ids.  On any failure, falls back to running
    every probe -- we'd rather over-probe than skip.
    """
    menu_lines = "\n".join(
        f"  - id={p['id']}, name={p['name']}, purpose={p['purpose']}"
        for p in PROBE_MENU
    )

    context = (
        f"You are the vulnerability-assessment agent in an autonomous "
        f"pen-testing pipeline.  The target is {target_url}.\n\n"
        f"Available probes:\n{menu_lines}"
    )
    question = (
        "Which probes should we run for this target?  Consider whether "
        "each is likely to yield useful evidence given the target type "
        "(a web application).  It is fine to select all probes if all "
        "look relevant."
    )
    schema = (
        '{ "selected_probe_ids": [ "<probe id>", "<probe id>", ... ] }'
    )

    try:
        result = await reason_then_format(context, question, schema)
        ids = result.get("selected_probe_ids", [])
        if not ids:
            log.warning("planner returned empty; falling back to full menu")
            return [p["id"] for p in PROBE_MENU]
        return ids
    except Exception as exc:
        log.warning("planning call failed (%s); falling back to full menu", exc)
        return [p["id"] for p in PROBE_MENU]


# --------------------------------------------------------------------------- #
# Per-probe execution
# --------------------------------------------------------------------------- #

async def _execute_probe(probe: dict[str, Any],
                         target_url: str) -> dict[str, Any]:
    """Run one probe: send the HTTP request via MCP, analyze the response."""
    url = target_url.rstrip("/") + probe["endpoint"]
    if probe.get("query"):
        url = f"{url}?{urlencode(probe['query'])}"

    mcp_body: dict[str, Any] = {"method": probe["method"], "url": url}
    if probe.get("payload"):
        mcp_body["json_body"] = probe["payload"]

    # Call MCP
    async with _authed_client() as client:
        r = await client.post(f"{MCP_URL}/tools/http_request", json=mcp_body)
        response = r.json()

    if response.get("error"):
        return {
            "probe_id":    probe["id"],
            "probe_name":  probe["name"],
            "endpoint":    probe["endpoint"],
            "test_type":   probe["test_type"],
            "error":       response.get("error"),
            "error_type":  response.get("error_type"),
        }

    # Analyze the response with the model
    analysis = await _analyze_response(probe, response)

    return {
        "probe_id":         probe["id"],
        "probe_name":       probe["name"],
        "endpoint":         probe["endpoint"],
        "test_type":        probe["test_type"],
        "response_status":  response.get("status_code"),
        "response_size":    response.get("body_size"),
        "analysis":         analysis,
    }


async def _analyze_response(probe: dict[str, Any],
                            response: dict[str, Any]) -> dict[str, Any]:
    """Ask the model whether the response indicates a vulnerability."""
    context = (
        f"Probe: {probe['name']}\n"
        f"Purpose: {probe['purpose']}\n"
        f"Method: {probe['method']}\n"
        f"Endpoint: {probe['endpoint']}\n"
        f"Payload: {probe.get('payload') or probe.get('query')}\n\n"
        f"Response received:\n"
        f"  Status code: {response.get('status_code')}\n"
        f"  Body size:   {response.get('body_size')} bytes\n"
        f"  Body (first 800 chars):\n{response.get('body_text', '')[:800]}"
    )

    if probe["test_type"] == "sqli":
        question = (
            "Does this response indicate a SQL injection vulnerability?  "
            "Consider: does the response leak query fragments in an error "
            "message?  Did the response differ from what you'd expect from "
            "a normal request?  Was authentication bypassed?  Rate your "
            "confidence honestly -- do not claim vulnerability without "
            "concrete evidence in the response."
        )
    elif probe["test_type"] == "xss":
        question = (
            "Does this response reflect the XSS payload back unescaped?  "
            "Check whether the payload's HTML tags appear literally in the "
            "response body, not encoded or stripped.  If they appear as "
            "encoded text (like '&lt;script&gt;'), that is safe.  Rate "
            "your confidence honestly."
        )
    else:
        question = "Analyze this response for security-relevant behavior."

    schema = (
        '{\n'
        '  "vulnerable":  true | false,\n'
        '  "confidence":  "low" | "medium" | "high",\n'
        '  "evidence":    "<one-sentence description of what you observed>",\n'
        '  "cwe":         "<CWE identifier or empty string>"\n'
        '}'
    )

    try:
        return await reason_then_format(context, question, schema)
    except Exception as exc:
        log.error("analysis call failed: %s", exc)
        return {
            "vulnerable": False,
            "confidence": "low",
            "evidence":   f"analysis failed: {exc}",
            "cwe":        "",
        }


# --------------------------------------------------------------------------- #
# Heartbeat + HTTP client helpers
# --------------------------------------------------------------------------- #

async def _heartbeat(engagement_id: UUID, message: str) -> None:
    """Post an ``in_progress`` update to the orchestrator.

    Resets ``engagement_state.updated_at`` so the stall scanner sees the
    agent as alive.  Non-fatal on failure -- an occasional missed heartbeat
    is fine; the 300-second stall timeout catches real stalls.
    """
    try:
        async with _authed_client() as client:
            await client.post(
                f"{ORCHESTRATOR_URL}/progress",
                json={
                    "engagement_id": str(engagement_id),
                    "agent":         "vuln",
                    "status":        "in_progress",
                    "message":       message,
                },
                timeout=10.0,
            )
    except Exception as exc:
        log.warning("heartbeat failed (%s): %s", message, exc)


def _authed_client() -> httpx.AsyncClient:
    """httpx client with the agent's bearer token and trust bundle."""
    # NOTE: verify this import path matches YOUR skeleton.  Run
    #   grep -rn "def client_ssl_context" --include="*.py" shared/
    # to find the correct module.  Common locations: shared.tls, shared.auth
    from shared.tls import client_ssl_context
    return httpx.AsyncClient(
        verify=client_ssl_context(),
        timeout=30.0,
        headers=bearer_headers(load_own_token()),
    )
```

**If your grep found `client_ssl_context` in a different module**, change
the marked import line to match. The lazy import (inside `_authed_client`)
means you only edit one line.

**Notes on this code:**

- Every probe's response is captured in `probes_executed` even if the
  analysis says `vulnerable: false`. This is important for the writeup —
  you want the audit trail of what was tested, not just what was found.
- Fallback logic in `_plan_probes` (run all probes on failure) prefers
  over-probing to under-probing. In an academic skeleton, missing a
  vulnerability is worse than doing extra work.

---

## Section E — Wire the dispatch check into `agent/main.py`

Open `agent/main.py`. Find the `_perform_work` function. It'll look
something like this (this is the pattern in the v2 skeleton):

```python
async def _perform_work(handoff: ChainHandoff) -> None:
    engagement_id = handoff.engagement_id
    try:
        await _post_progress(engagement_id, "started", "beginning work")
        await maybe_fail(FAILURE_RATE)
        result = await do_stub_work(AGENT_NAME, handoff.model_dump(mode="json"))
        _write_result(engagement_id, result)
        if NEXT_AGENT is not None:
            await _push_to_next(engagement_id, handoff, result)
        await _post_progress(engagement_id, "done", "work complete",
                             detail={"has_result": True})
    except Exception as exc:
        log.exception("work failed: %s", exc)
        await _post_progress(engagement_id, "failed", str(exc))
```

**Replace** the whole function with this version. Two things change: the
`maybe_fail` and `do_stub_work` lines are now wrapped by an `AGENT_MODE`
check that routes vuln to the real path when enabled.

```python
async def _perform_work(handoff: ChainHandoff) -> None:
    engagement_id = handoff.engagement_id
    try:
        await _post_progress(engagement_id, "started", "beginning work")

        # Phase 5: real-mode dispatch for the vuln agent.
        # AGENT_MODE=real bypasses failure injection and stub work entirely.
        if AGENT_NAME == "vuln" and os.environ.get("AGENT_MODE") == "real":
            from agent.real_vuln import perform_vuln_work_real
            result = await perform_vuln_work_real(handoff)
        else:
            await maybe_fail(FAILURE_RATE)
            result = await do_stub_work(AGENT_NAME, handoff.model_dump(mode="json"))

        _write_result(engagement_id, result)
        if NEXT_AGENT is not None:
            await _push_to_next(engagement_id, handoff, result)
        await _post_progress(engagement_id, "done", "work complete",
                             detail={"has_result": True})
    except Exception as exc:
        log.exception("work failed: %s", exc)
        await _post_progress(engagement_id, "failed", str(exc))
```

Ensure `import os` is at the top of the file — check with:

```bash
grep -n "^import os" agent/main.py
```

If nothing prints, add `import os` near the other stdlib imports at the
top.

Verify the edit landed:

```bash
grep -n "AGENT_MODE\|perform_vuln_work_real" agent/main.py
```

Expected: two matches on adjacent lines inside `_perform_work`.

Rebuild:

```bash
docker compose build agent-vuln
docker compose up -d --force-recreate agent-vuln
```

Confirm no import errors:

```bash
docker compose logs --tail=20 agent-vuln
```

Should show the usual startup lines with no traceback.

Test that stub mode still works (default `AGENT_MODE=stub`):

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli tui
# Fill in the form, use http://juice-shop.test:3000/
# Complete in ~30 seconds with all stubs
```

If that still works, the dispatch check is in place correctly and stub
behaviour is preserved.

---

## Section F — End-to-end test in real mode

Flip to real mode:

```bash
export AGENT_MODE=real
docker compose up -d --force-recreate agent-vuln
docker exec apts-agent-vuln printenv AGENT_MODE   # → real
```

Start an engagement. **Expect ~13 minutes**. Use the TUI in `brief` mode
so the interesting events stand out:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli tui
# Target URL:    http://juice-shop.test:3000/
# Allowed domains: juice-shop.test
# View mode:     brief
```

You should see events roughly like this over the next ~13 minutes:

```
  09:15:12  [orchestrator    ]  engagement_created
  09:15:12  [agent-recon     ]  progress_received  status=started
  09:15:16  [agent-recon     ]  progress_received  status=done
  09:15:16  [agent-vuln      ]  progress_received  status=started
  09:15:16  [agent-vuln      ]  progress_received  status=in_progress   ← planning
  09:17:51  [agent-vuln      ]  progress_received  status=in_progress   ← probe 1
  09:20:29  [agent-vuln      ]  progress_received  status=in_progress   ← probe 2
  09:23:04  [agent-vuln      ]  progress_received  status=in_progress   ← probe 3
  09:25:37  [agent-vuln      ]  progress_received  status=in_progress   ← probe 4
  09:28:12  [agent-vuln      ]  progress_received  status=done
  09:28:12  [agent-mitre     ]  progress_received  status=started       ← stub takes over
  09:28:15  [agent-mitre     ]  progress_received  status=done
  ... (Exploit, Script, Adviser stubs)
  09:28:31  [orchestrator    ]  engagement_complete
```

The vuln agent phase (`agent-vuln started` → `agent-vuln done`) should
take ~13 minutes. Everything after Vuln is stub and finishes in ~15
seconds.

### F.1 Inspect the real findings

The real findings are in `agent_results.payload` (note: this column is
`payload`, not `output`, in the v2 skeleton — verify your schema with
`\d agent_results` if unsure):

```bash
docker compose exec -T database psql -U apts -d apts -c "
SELECT engagement_id, agent, jsonb_pretty(payload)
FROM agent_results
WHERE agent = 'vuln'
ORDER BY written_at DESC LIMIT 1;
"
```

Expected output (this is an **actual result** from a real-mode run, not
a made-up example):

```json
{
  "target_url": "http://juice-shop.test:3000/",
  "weaknesses": [],
  "probes_executed": [
    {
      "probe_id": "login_sqli_tautology",
      "probe_name": "Login SQL injection (tautology)",
      "endpoint": "/rest/user/login",
      "test_type": "sqli",
      "response_status": 401,
      "response_size": 26,
      "analysis": {
        "vulnerable": false,
        "confidence": "low",
        "evidence": "401 Unauthorized with generic error message",
        "cwe": ""
      }
    },
    {
      "probe_id": "login_sqli_union",
      "probe_name": "Login SQL injection (UNION)",
      "endpoint": "/rest/user/login",
      "test_type": "sqli",
      "response_status": 500,
      "response_size": 1449,
      "analysis": {
        "vulnerable": false,
        "confidence": "low",
        "evidence": "500 Internal Server Error without specific SQL error details",
        "cwe": ""
      }
    },
    {
      "probe_id": "search_xss_script",
      "probe_name": "Search reflected XSS",
      "endpoint": "/rest/products/search",
      "test_type": "xss",
      "response_status": 200,
      "response_size": 30,
      "analysis": {
        "vulnerable": false,
        "confidence": "high",
        "evidence": "Response does not contain unescaped HTML tags from the payload",
        "cwe": ""
      }
    },
    {
      "probe_id": "search_sqli_error",
      "probe_name": "Search SQL injection (error-based)",
      "endpoint": "/rest/products/search",
      "test_type": "sqli",
      "response_status": 200,
      "response_size": 30,
      "analysis": {
        "vulnerable": false,
        "confidence": "low",
        "evidence": "No error messages or unusual responses indicating SQL injection vulnerability",
        "cwe": ""
      }
    }
  ]
}
```

**What matters is that the output is real**:
- `probes_executed` has one entry per probe with real HTTP status codes
  from Juice Shop
- Each `analysis` field is the model's actual reasoning about the
  response
- `weaknesses` contains only the entries where `analysis.vulnerable: true`

**About the model's judgment.** In the example above, the model correctly
identified that a 401 with a generic error message doesn't leak query
fragments, and that a JSON-only search endpoint won't reflect HTML.
However, probe 2's 500 response with a 1449-byte body is a *behavioral*
signal that a human tester would investigate further — Qwen 2.5 7B at
Q4_K_M quantization is conservative and requires more explicit evidence
before flagging. This is real and honest data about small-model
capability; frame it that way in the writeup rather than as a bug in
the system.

### F.2 The audit trail

Every step is in the audit log:

```bash
docker compose exec -T database psql -U apts -d apts -c "
SELECT logged_at, component, event_type,
       COALESCE(detail->>'tool', detail->>'agent') AS entity,
       COALESCE(detail->>'url', detail->>'status', '') AS extra
FROM audit_log
WHERE engagement_id = (SELECT id FROM engagements ORDER BY created_at DESC LIMIT 1)
  AND component IN ('mcp-tools', 'orchestrator')
ORDER BY logged_at;
" | head -80
```

You'll see:
- `mcp-tools` `tool_call` events for each MCP `http_request` (4 of them
  for the probes, plus any implicit ones)
- `orchestrator` `progress_received` events showing each `in_progress`
  heartbeat between probes
- The full state machine transitions from `kicked_off` through `done`

**Save this output** — it's core evidence for the writeup showing the
architecture works end-to-end.

### F.3 Verify downstream stubs still complete

The engagement should have reached `complete` status:

```bash
docker compose exec -T database psql -U apts -d apts -c "
SELECT id, status, completed_at - created_at AS elapsed
FROM engagements
ORDER BY created_at DESC LIMIT 1;
"
```

Expected: `status = complete`, `elapsed ≈ 13-14 minutes`.

Confirm vuln itself was a clean one-shot run (retry_count = 0):

```bash
docker compose exec -T database psql -U apts -d apts -c "
SELECT agent, status, retry_count
FROM engagement_state
WHERE engagement_id = (SELECT id FROM engagements ORDER BY created_at DESC LIMIT 1)
ORDER BY agent;
"
```

Expected: `vuln` shows `status=done` and `retry_count=0`. If retry_count
is higher, something failed earlier — check `agent-vuln` logs.

Common failures at this stage:
- Import error for `client_ssl_context` — verify path per Section D
- Model timeout: check `docker compose logs ollama`
- Prompt returned unparseable JSON: `reason_then_format` retries twice
  and then raises; you'd see `analysis failed: could not get valid JSON`
  in the probe's evidence field (finding is still recorded, marked
  vulnerable=false)

### F.4 Flip back to stub mode when done testing

Long engagements chew through your time. When you're done demonstrating:

```bash
unset AGENT_MODE
docker compose up -d --force-recreate agent-vuln
```

Now the vuln agent is back to stub. Engagements finish in ~30 seconds
again, useful for iterating on other work.

---

## Section G — What's next

Phase 5 done. This is the last implementation phase.

**Phase 6** will be short: demo evidence collection for the writeup —
running a canonical engagement, capturing the outputs, formatting them
for inclusion in the project report. That's a session of "run this,
save that output, take a screenshot" rather than any new code.

Say the word and I'll write Phase 6. Or if you'd like to iterate on
Phase 5 first (tune prompts, add more probes, try running against a
different target), do that first and I'll write Phase 6 whenever you're
ready.

---

## Section H — Notes for the writeup

Six points worth capturing.

**End-to-end real integration validated.** The system now integrates
Qwen 2.5 7B (via Ollama), MCP tools for HTTP probing, and the chain-of-
agents orchestration — all working together to produce real findings on
a real target. The vuln agent's stub-vs-real toggle demonstrates the
Q7b parallel-path design: existing stubs coexist with the real
implementation, and behaviour is selected at container startup by a
single environment variable.

**Model-guided probe selection.** The vuln agent doesn't blindly run
every probe. A planning call reviews the target and available probes,
selects which to execute, and only then runs them. On a fast target
this saves time (~155s per skipped probe). On a slow or exotic target
it prevents the agent from wasting effort on inapplicable probes.
The planner falls back to running all probes on any failure — over-
probing is safer than under-probing in a skeleton, and the failure is
logged.

**Heartbeats to the orchestrator.** Real model calls take ~155 seconds
each, which exceeds the default 60-second stall-detection threshold.
Two responses: bump the threshold to 300 seconds (still safe for a
single call), and post `in_progress` progress updates from the vuln
agent between probes. Belt and braces. This is exactly the pattern real
long-running services use to interact with a supervisor — heartbeat
frequently, size the timeout for the worst case anyway.

**Measured engagement runtime.** On the target hardware, a full vuln
engagement (planning call + 4 probes) runs in ~13 minutes. Recon and
downstream stubs add ~30 seconds. Total engagement time: ~13-14 minutes.
This is the demonstrated per-run cost of self-hosted CPU-only inference
at 7B parameters. If future work adopted a GPU (T4 class), the same
work would complete in ~1-2 minutes — but requires ongoing infrastructure
cost.

**Model conservatism is a real observation.** In one representative run
against Juice Shop, the model correctly reasoned about three of four
probes and reached defensible verdicts. Probe 2 (a UNION-based injection
against `/rest/user/login`) triggered a 500 Internal Server Error with
a 1449-byte body — a behavioral signal a human tester would investigate
further, which Qwen 2.5 7B classified as inconclusive due to the lack
of SQL error text in the response. This suggests a capability limit
worth quantifying: does a 7B parameter model reliably escalate on
behavioral signals, or does it require explicit query-fragment leakage?
Future work could measure this by running the same probe suite against
multiple deliberately-vulnerable targets and comparing the model's
detection rate against a ground-truth vulnerability list.

**Every action inspectable in the DB.** The audit trail shows every
MCP tool call, every progress update, every state transition. The
`agent_results` table holds the real findings alongside the intermediate
per-probe evidence. Nothing about the model's reasoning is opaque or
lost — the reasoning-call output is logged with token count and
elapsed time, the format-call output goes through JSON parsing that's
logged on failure, and the final structured findings are queryable
SQL. This is the observability property that has been the design's
strength throughout, and it holds even now that the reasoning behind
findings comes from a language model rather than a hard-coded stub.
