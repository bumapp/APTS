# Vuln Agent — Phase 3: Real MCP Tools for Vuln

Third of six phases. Phase 1 got Ollama running. Phase 2 stood up Juice Shop
and wired the network so `juice-shop.test` resolves from inside agents. This
phase makes the vuln agent's toolkit real — an HTTP client it can point at
Juice Shop, and an HTML-form parser that turns raw pages into structured
data the model can reason about.

## What this phase delivers

By the end of Phase 3 you will have:
- A `mcp_tools/tools/` subpackage with two real tools: `http_request`
  (async HTTP client with safety limits) and `parse_forms` (HTML → list of
  forms with their input fields)
- New endpoints on the `mcp-tools` container: `POST /tools/http_request`
  and `POST /tools/parse_forms`, both behind existing bearer auth
- Every tool call written to the audit log — so the vuln agent's future
  activity is inspectable end-to-end
- Verified: an agent container can call these tools against Juice Shop and
  get real responses back

Nothing about the agent code changes. Vuln still runs its stub. This phase
only builds the tools the vuln agent will *start* calling in Phase 5.

Time budget: **2-3 hours**, mostly typing and testing rather than thinking.

---

## Section A — Design decisions

Before writing code, four choices to be explicit about:

**"Fat" tools rather than thin.** The MCP layer does HTTP *and* HTML
parsing — not just raw HTTP. Rationale: Qwen 2.5 7B has ~32K context, and
a Juice Shop page is ~80KB of raw HTML. Feeding the model raw HTML would
blow the context budget immediately. The parser tool returns a compact
list of forms (name, action, method, input fields) — perhaps 200 tokens
instead of 20,000. The model reasons on the compact representation.

**No policy Guardrails in this phase.** Q5 was "let the agent run freely."
The MCP outbound Guardrails stub stays as-is; every tool call is allowed
regardless of the URL. Basic engineering safety limits (timeout, response
size cap) are inside the tools themselves and are non-negotiable, but
they're not policy checks.

**Two tools, not five.** For SQLi and XSS probing against Juice Shop, the
vuln agent needs (a) the ability to make arbitrary HTTP requests and
(b) the ability to discover forms. Everything else — reflected-content
detection, error-pattern matching — the model can do in reasoning against
the response text we return. If Phase 5 shows we need more tools, we add
them then.

**Audit every call.** Every tool invocation writes an `audit_log` row
with the caller, tool name, URL, and result summary. This gives the
writeup a complete transcript of what the agent probed and when — the
observability story continues to be a strength of the design.

---

## Section B — Add BeautifulSoup4 to requirements

Open the requirements file used to build the shared `apts-skeleton:latest`
image. In the current skeleton this is `requirements.txt` at the top of
the project (used by the shared Dockerfile). Confirm which file it is:

```bash
grep -rl 'fastapi' --include="requirements*.txt" .
```

Should print `./requirements.txt` (and maybe others). Edit it:

```bash
nano requirements.txt
```

**Add** at the end of the file:

```
beautifulsoup4==4.12.3
```

Save. Version pinned for reproducibility — the API surface we use (finding
`<form>` tags, iterating over inputs) has been stable since 4.x, so 4.12.3
is a safe choice.

---

## Section C — Create the tools subpackage

Create the directory and two files:

```bash
mkdir -p mcp_tools/tools
touch mcp_tools/tools/__init__.py
```

The empty `__init__.py` makes `tools/` an importable Python package.

### C.1 The HTTP client tool

Create `mcp_tools/tools/http_client.py`:

```python
"""HTTP client tool for the vuln agent.

Exposed via ``POST /tools/http_request`` on the mcp-tools service.  Called
by agents that need to actually reach external targets during an
engagement.

Design goals:
  * Async: matches the FastAPI event loop used by the MCP HTTP service.
  * Safe defaults: bounded timeout, bounded response size, no follow of
    redirects (redirect-chasing is the agent's decision, not ours).
  * Structured output: returns a dict the calling agent can reason about
    without having to parse anything itself.
"""
from __future__ import annotations

from typing import Any

import httpx

# Engineering safety limits.  These are NOT policy checks -- policy is the
# Guardrails layer's job.  These prevent one bad tool call from breaking
# the process (out-of-memory response, hung connection).
MAX_RESPONSE_BYTES = 128 * 1024   # 128 KB.  Juice Shop pages are ~80 KB.
DEFAULT_TIMEOUT    = 15.0         # seconds
MAX_URL_LENGTH     = 2048         # RFC 7230 recommends 8000; we're stricter


async def http_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    form_data: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Make one HTTP request.  Return a structured response.

    Body is specified by at most one of: ``body`` (raw string),
    ``form_data`` (URL-encoded form), or ``json_body`` (JSON object).
    If none is given, the request has no body.

    On network error (DNS failure, refused connection, timeout), the return
    dict contains ``error`` and ``error_type`` keys instead of the usual
    response fields.  This lets the caller treat network errors as data
    without needing exception handling in the calling code.
    """
    # Bound-check inputs
    if len(url) > MAX_URL_LENGTH:
        return {
            "error": f"URL too long ({len(url)} > {MAX_URL_LENGTH} bytes)",
            "error_type": "URLTooLong",
        }
    method = method.upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        return {
            "error": f"unsupported HTTP method: {method}",
            "error_type": "UnsupportedMethod",
        }

    # Select body form
    kwargs: dict[str, Any] = {}
    body_count = sum(x is not None for x in (body, form_data, json_body))
    if body_count > 1:
        return {
            "error": "specify at most one of body / form_data / json_body",
            "error_type": "AmbiguousBody",
        }
    if json_body is not None:
        kwargs["json"] = json_body
    elif form_data is not None:
        kwargs["data"] = form_data
    elif body is not None:
        kwargs["content"] = body

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=False,           # allow http:// targets like Juice Shop
    ) as client:
        try:
            r = await client.request(method, url, headers=headers, **kwargs)
        except httpx.RequestError as exc:
            return {
                "error": str(exc),
                "error_type": exc.__class__.__name__,
            }

    # Truncate the body to protect the calling agent from oversized responses.
    body_bytes = r.content[:MAX_RESPONSE_BYTES]
    body_truncated = len(r.content) > MAX_RESPONSE_BYTES
    body_text = body_bytes.decode("utf-8", errors="replace")

    return {
        "status_code":     r.status_code,
        "headers":         dict(r.headers),
        "body_text":       body_text,
        "body_size":       len(r.content),
        "body_truncated":  body_truncated,
        "url_final":       str(r.url),
    }
```

### C.2 The HTML form parser tool

Create `mcp_tools/tools/html_parser.py`:

```python
"""HTML form extraction tool for the vuln agent.

Exposed via ``POST /tools/parse_forms`` on the mcp-tools service.

Turns a raw HTML page into a compact list of forms with their fields.  A
form-heavy Juice Shop page (~80 KB HTML) produces maybe 500 bytes of
structured form data -- much easier for a small model to reason about
than the raw markup.
"""
from __future__ import annotations

from typing import Any

from bs4 import BeautifulSoup


def parse_forms(html: str) -> list[dict[str, Any]]:
    """Extract every ``<form>`` from the given HTML.

    For each form, return the action URL, HTTP method, and a list of
    input fields (name, type, current value, whether required).  Fields
    without a ``name`` attribute are skipped -- they can't be submitted.
    """
    soup = BeautifulSoup(html, "html.parser")
    forms: list[dict[str, Any]] = []
    for form in soup.find_all("form"):
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            inputs.append({
                "tag":       inp.name,
                "name":      name,
                "type":      inp.get("type", "text"),
                "value":     inp.get("value"),
                "required":  inp.has_attr("required"),
            })
        forms.append({
            "action":  form.get("action", ""),
            "method":  (form.get("method") or "GET").upper(),
            "inputs":  inputs,
        })
    return forms
```
## Section C.3 must be omitted
### C.3 Verify the files parse

Python-level check before wiring them in:

```bash
python -c "
import sys; sys.path.insert(0, '.')
from mcp_tools.tools.http_client import http_request
from mcp_tools.tools.html_parser import parse_forms
print('imports OK')
print('parse_forms:', parse_forms('<html><form action=\"/x\" method=\"POST\"><input name=\"q\" type=\"text\"/></form></html>'))
"
```

Expected output:

```
imports OK
parse_forms: [{'action': '/x', 'method': 'POST', 'inputs': [{'tag': 'input', 'name': 'q', 'type': 'text', 'value': None, 'required': False}]}]
```

If you get an ImportError on `bs4`, install `beautifulsoup4` locally first:
`pip install --break-system-packages beautifulsoup4`. This is only needed
to run the check on your host; the container will install it during
`docker compose build` in Section E.

---

## Section D — Wire the tools into `mcp_tools/main.py`

Open `mcp_tools/main.py`. This file already has FastAPI setup, auth
wiring, and probably some existing stub endpoints. **Add** the following
in the appropriate places without removing what's there.

### D.1 Add imports

At the top of the file, alongside the existing imports, **add**:

```python
from typing import Any
from pydantic import BaseModel

from mcp_tools.tools.http_client import http_request as _tool_http_request
from mcp_tools.tools.html_parser import parse_forms  as _tool_parse_forms
```

If `Any` or `BaseModel` is already imported, don't re-import. The
underscore prefix on the tool imports (`_tool_http_request`) is a common
convention to signal "this is being renamed for local use" — it avoids
name collisions with the endpoint function names below.

### D.2 Add request-body models

Find where other Pydantic models are defined (probably near the top after
imports). **Add**:

```python
class HttpRequestArgs(BaseModel):
    method: str = "GET"
    url: str
    headers:   dict[str, str] | None = None
    body:      str            | None = None
    form_data: dict[str, str] | None = None
    json_body: dict[str, Any] | None = None
    timeout:   float                  = 15.0


class ParseFormsArgs(BaseModel):
    html: str
```

### D.3 Add the endpoint handlers

Find where existing routes are declared (`@app.get`, `@app.post`, or similar).
**Add** the two new routes, wherever the file's route section lives:

```python
@app.post("/tools/http_request")
async def call_http_request(
    args:   HttpRequestArgs,
    caller: Caller = Depends(require_auth),
) -> dict[str, Any]:
    """HTTP client tool.  Any authenticated agent may call it."""
    audit("mcp-tools", "tool_call", detail={
        "tool":   "http_request",
        "caller": caller.component,
        "method": args.method,
        "url":    args.url,
    })
    result = await _tool_http_request(
        method    = args.method,
        url       = args.url,
        headers   = args.headers,
        body      = args.body,
        form_data = args.form_data,
        json_body = args.json_body,
        timeout   = args.timeout,
    )
    # Audit the outcome shape too, for observability
    audit("mcp-tools", "tool_result", detail={
        "tool":        "http_request",
        "caller":      caller.component,
        "url":         args.url,
        "status_code": result.get("status_code"),
        "error_type":  result.get("error_type"),
        "body_size":   result.get("body_size"),
    })
    return result


@app.post("/tools/parse_forms")
async def call_parse_forms(
    args:   ParseFormsArgs,
    caller: Caller = Depends(require_auth),
) -> dict[str, Any]:
    """HTML form parser.  Compact structured output for a large HTML input."""
    audit("mcp-tools", "tool_call", detail={
        "tool":      "parse_forms",
        "caller":    caller.component,
        "html_size": len(args.html),
    })
    forms = _tool_parse_forms(args.html)
    audit("mcp-tools", "tool_result", detail={
        "tool":       "parse_forms",
        "caller":     caller.component,
        "form_count": len(forms),
    })
    return {"forms": forms}
```

If your file uses a different import name than `Caller` for the auth
return type, or a different name than `require_auth` for the dependency,
match whatever's already in the file — my exact names come from the
skeleton I know, yours may vary.

If the file has no `audit(...)` calls yet, look for how the other services
(e.g., orchestrator) audit and match that pattern. If the file doesn't
import `audit` from `shared.db`, add:

```python
from shared.db import audit
```

near the other `from shared...` imports.

---

## Section E — Rebuild and smoke test

Rebuild the shared image (it's the base image for `mcp-tools`, so the
requirements change and the new files both get baked in):

```bash
docker compose build mcp-tools
docker compose up -d --force-recreate mcp-tools
docker compose ps mcp-tools           # STATUS should be Up
docker compose logs --tail=10 mcp-tools
```

If `mcp-tools` is in `Restarting` state, check the logs. Most likely
cause: import error in `main.py` from an incorrect import path. Fix and
rebuild.

Confirm the new endpoints are registered by asking the OpenAPI docs
(mcp-tools' FastAPI serves auto-generated docs at `/docs` — accessible
from inside the network):

```bash
docker exec -it apts-agent-vuln python -c "
import httpx
from shared.auth import load_own_token, bearer_headers
from shared.tls import client_ssl_context

client = httpx.Client(verify=client_ssl_context(), timeout=10.0)
r = client.get('https://mcp-tools:8443/openapi.json',
               headers=bearer_headers(load_own_token()))
import json
spec = r.json()
routes = sorted(spec.get('paths', {}).keys())
print('Available routes:')
for r in routes:
    print(f'  {r}')
"
```

You should see both `/tools/http_request` and `/tools/parse_forms` in the
list, alongside whatever routes already existed.

If the import for `shared.tls` doesn't exist in your skeleton, use whatever
the other services use to build an httpx client. The exact import name
matters less than the pattern: bearer token from `tokens/agent-vuln.token`
mounted into the container, TLS trust bundle likewise mounted, both
already in the agent-vuln container.

---

## Section F — Real tests against Juice Shop

Now the real validation: an agent container calls the new tools, which
reach out to Juice Shop.

### F.1 http_request tool

```bash
docker exec -it apts-agent-vuln python -c "
import httpx, json
from shared.auth import load_own_token, bearer_headers
from shared.tls import client_ssl_context

client = httpx.Client(verify=client_ssl_context(), timeout=30.0)
r = client.post(
    'https://mcp-tools:8443/tools/http_request',
    json={'method': 'GET', 'url': 'http://juice-shop.test:3000/'},
    headers=bearer_headers(load_own_token()),
)
result = r.json()
print(f'MCP status:    {r.status_code}')
print(f'HTTP status:   {result.get(\"status_code\")}')
print(f'Body size:     {result.get(\"body_size\")}')
print(f'Body truncated:{result.get(\"body_truncated\")}')
print(f'First 200 chars of body:')
print(result.get('body_text', '')[:200])
"
```

Expected:
- MCP status: 200 (mcp-tools accepted the call)
- HTTP status: 200 (Juice Shop returned OK)
- Body size: ~80000+ bytes
- Body truncated: True (we cap at 128KB, Juice Shop's homepage is bigger)
- First 200 chars: the Juice Shop HTML opening

### F.2 parse_forms tool

Use the HTML from the previous call as input to the parser. Combined
test in one shot:

```bash
docker exec -it apts-agent-vuln python -c "
import httpx, json
from shared.auth import load_own_token, bearer_headers
from shared.tls import client_ssl_context

client  = httpx.Client(verify=client_ssl_context(), timeout=30.0)
headers = bearer_headers(load_own_token())

# 1. Fetch the login page
r = client.post(
    'https://mcp-tools:8443/tools/http_request',
    json={'method': 'GET', 'url': 'http://juice-shop.test:3000/#/login'},
    headers=headers,
)
page = r.json()
print(f'Fetched login page: status={page[\"status_code\"]}, size={page[\"body_size\"]}')

# 2. Parse forms out of it
r = client.post(
    'https://mcp-tools:8443/tools/parse_forms',
    json={'html': page['body_text']},
    headers=headers,
)
parsed = r.json()
print(f'Forms found: {len(parsed[\"forms\"])}')
for i, form in enumerate(parsed['forms']):
    print(f'  Form {i}: {form[\"method\"]} {form[\"action\"]}')
    for inp in form['inputs']:
        req = ' (required)' if inp['required'] else ''
        print(f'    - {inp[\"name\"]} type={inp[\"type\"]}{req}')
"
```

Juice Shop is a single-page app so it may not have traditional `<form>`
tags in the initial HTML — most of the login form is built via JavaScript
at runtime. That's fine; the tool works, it just returns an empty
`forms: []` for this specific target. It'll be more useful against
DVWA-style targets in the future.

To see the parser return real form data, hit a page that has server-side
HTML forms. If Juice Shop's homepage `/` has any form (it does have a
newsletter signup at the bottom in some versions), the parser will find
it. Just to confirm the parser works, run this synthetic check:

```bash
docker exec -it apts-agent-vuln python -c "
import httpx
from shared.auth import load_own_token, bearer_headers
from shared.tls import client_ssl_context

client  = httpx.Client(verify=client_ssl_context(), timeout=10.0)
headers = bearer_headers(load_own_token())

sample_html = '''
<html><body>
  <form action=\"/login\" method=\"POST\">
    <input name=\"email\" type=\"email\" required/>
    <input name=\"password\" type=\"password\" required/>
    <input name=\"remember\" type=\"checkbox\"/>
  </form>
  <form action=\"/search\" method=\"GET\">
    <input name=\"q\" type=\"text\"/>
  </form>
</body></html>
'''
r = client.post(
    'https://mcp-tools:8443/tools/parse_forms',
    json={'html': sample_html},
    headers=headers,
)
import json
print(json.dumps(r.json(), indent=2))
"
```

Expected: two forms with their input lists, exactly as declared.

### F.3 Verify the audit trail

Every tool call should have shown up in the audit log:

```bash
docker compose exec -T database psql -U apts -d apts -c "
SELECT logged_at, component, event_type, detail
FROM audit_log
WHERE component = 'mcp-tools'
  AND event_type LIKE 'tool_%'
ORDER BY logged_at DESC LIMIT 10;
"
```

You should see paired `tool_call` and `tool_result` rows for each of the
requests you just made. This is exactly the observability the writeup
notes will highlight — every action the vuln agent takes in Phase 5 will
have this trail.

### F.4 A quick failure test

Verify the safety limits work by asking for a bad URL:

```bash
docker exec -it apts-agent-vuln python -c "
import httpx
from shared.auth import load_own_token, bearer_headers
from shared.tls import client_ssl_context

client = httpx.Client(verify=client_ssl_context(), timeout=30.0)
r = client.post(
    'https://mcp-tools:8443/tools/http_request',
    json={'method': 'GET', 'url': 'http://this-host-does-not-exist.invalid:9999/'},
    headers=bearer_headers(load_own_token()),
)
print(r.json())
"
```

Expected: response with `error` and `error_type` keys, no `status_code`.
This confirms the tool returns network errors as structured data rather
than propagating exceptions up to the agent.

---

## Section G — What's next

Phase 3 done. Say the word and I'll write **Phase 4: Model wrapper for
the agent** — a `shared/model.py` abstraction so the agents can call
Ollama with retry logic, without every agent reimplementing the same
HTTP+timeout+error-handling pattern.

Rough shape of Phase 4:
- Create `shared/model.py` with a `generate(prompt, ...)` helper
- Retry on transient failures (connection dropped, first-load timeout)
- Structured output parsing helpers (D3b: reason-then-format, from our
  earlier design decision)
- No agent code changes yet — Phase 4 delivers a library that Phase 5
  will consume

Time budget for Phase 4: 1-2 hours.

Then Phase 5 is the meat — writing the vuln agent's real reasoning loop
that uses both this phase's tools and Phase 4's model wrapper.

---

## Section H — Notes for the writeup

Three points worth capturing:

**Fat vs thin tools.** The MCP layer chose to include HTML parsing as a
tool, not just raw HTTP. The reason is model-context-budget: a 7B model
with 32K context can't fit a raw Juice Shop page (80 KB) alongside its
system prompt, reasoning trace, and structured output. By parsing HTML
into a compact list of forms at the tool layer, the model gets to reason
about form structure without ever seeing raw HTML. This is a deliberate
architectural inversion of the "smart agent, dumb tools" pattern common
in LLM tutorials — with small local models, it pays to do more work in
the tools and less in the model.

**Engineering safety vs policy Guardrails.** The tools enforce hard
limits (128 KB response, 15-second timeout, 2 KB URL) that are pure
engineering safety — one badly-behaved probe can't crash the vuln
agent or exhaust MCP tools' memory. These are separate from policy
Guardrails, which decide *whether* a call is allowed (target scope,
protocol whitelist, method restrictions). This project keeps the
policy Guardrails as stubs by design (Q5), so the vuln agent can probe
freely — but the engineering safety limits are always on.

**Every tool call audited.** The `audit_log` table now records two rows
per tool invocation: `tool_call` (what was requested) and `tool_result`
(what happened, minus the body). The vuln agent's Phase 5 activity will
be fully reconstructable from the DB — for defence-in-depth review, for
academic reproducibility, or for debugging when a prompt goes wrong.
This is the observability property carrying forward from every earlier
phase; it wasn't planned as a Phase 3 deliverable specifically, but the
tool-audit calls make it richer than before.
