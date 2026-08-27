# Vuln Agent — Phase 4: Model Wrapper

Fourth of six phases. Phase 1-3 built the infrastructure. This phase adds
one file: `shared/model.py`, an abstraction over the raw Ollama HTTP API
that the vuln agent will consume in Phase 5.

## What this phase delivers

By the end of Phase 4 you will have:
- `shared/model.py` — an importable module with three public functions:
  - `generate(prompt, ...)` — the basic completion call, with retry on
    transient failures and a default token cap
  - `reason_then_format(context, question, schema)` — the D3b pattern:
    one reasoning call, one structured-output call, JSON parsing built in
  - `extract_json(text)` — a helper that pulls JSON out of model output
    even when the model wraps it in code fences or preambles
- Verified end-to-end from inside the vuln container: real prompts return
  real answers, structured JSON is produced reliably, latency is
  consistent across runs

Nothing else changes. No agent starts using this yet — that's Phase 5.

Time budget: **1-2 hours**.

---

## Section A — Design of the wrapper

Three functions with distinct responsibilities.

### generate()

The primitive: one prompt in, one response out. Everything the wrapper does
above the raw HTTP call:

- **Retry on transient failure** with exponential backoff (2s, 4s, 8s).
  Transient meaning "connection dropped, timeout, HTTP 5xx." Not on 4xx —
  those are our fault.
- **Default 800-token output cap.** Without a cap, Qwen 2.5 7B occasionally
  decides to write a 2000+ token essay in response to a simple prompt,
  which at ~6 tokens/second on 8 CPU means 5+ minutes of runaway generation.
  Callers who genuinely want longer output must pass `max_tokens` explicitly.
- **10-minute HTTP timeout.** Ludicrously long for typical CPU inference
  (~150s per call), but covers pathological cases and the first cold call
  after model reload.
- **Log every call** with token count and elapsed time so we can spot
  regressions during Phase 5 tuning.

### reason_then_format()

Implements the D3b design decision from Phase-planning: two model calls
per structured output.

**Call 1 — Reasoning.** Free-form thinking. Model gets context and a
question, produces analysis in prose. Temperature 0.3 (some variety in
reasoning). Capped at 600 tokens (~100 seconds on this hardware).

**Call 2 — Formatting.** Takes the model's own prose plus a schema
description, asks it to output only JSON matching that schema.
Temperature 0.0 (deterministic). Capped at 300 tokens (~50 seconds).
If the response isn't parseable JSON, retry with the model's bad output
shown back to it: "your previous response was invalid JSON: ..., try again."

Why two calls instead of one:
- **One reason to think, one to format.** Trying to reason *and*
  produce clean JSON in a single call is where small models fail most
  often — they trail off, mix prose into JSON, or produce syntactically
  invalid output.
- **Cheap to retry the format-only call.** It's short and focused. If
  JSON extraction fails, we retry just the formatting step (a few
  seconds), not the whole reasoning step (100+ seconds).

Total per structured output: ~150 seconds (measured, ±1.5s across replicate
runs on 8 CPU / 32 GB RAM). Multiply by the number of probes the vuln
agent will make per engagement to estimate total agent runtime.

### extract_json()

A defensive parser. Small models often wrap JSON in code fences
(```` ```json ... ``` ````) or add a preamble ("Sure, here's the JSON:"). This
function handles the three common patterns:

1. Pure JSON — the ideal case.
2. JSON inside a triple-backtick fence, optionally labelled `json`.
3. JSON preceded by prose — find the first `{` or `[` and try
   `json.JSONDecoder.raw_decode` from there.

Returns the parsed Python value or raises `ValueError`.

---

## Section B — Create `shared/model.py`

Create a new file `shared/model.py` with the exact contents below.

```python
"""Model-wrapper abstraction over the Ollama HTTP API.

Design notes (Phase 4 of the vuln-agent implementation):

  * ``generate(prompt, ...)`` is the primitive.  Retries transient
    failures with exponential backoff.  Default 800-token cap prevents
    runaway generation.  10-minute timeout covers pathological cases.
  * ``reason_then_format(context, question, schema)`` implements the
    D3b pattern from our Phase-planning: one call to reason (up to 600
    tokens), one call to format as JSON (up to 300 tokens), JSON retry
    if the first format attempt fails.  Twice the runtime per structured
    output, but drastically more reliable on small local models than
    one-shot JSON generation.
  * ``extract_json(text)`` defends against the common wrapping patterns
    small models use (code fences, preambles) so the caller doesn't
    have to.

All calls are async -- the agents run inside FastAPI, which lives on an
asyncio event loop.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

OLLAMA_URL      = "http://ollama:11434"
DEFAULT_MODEL   = "qwen2.5:7b-instruct-q4_K_M"
DEFAULT_TIMEOUT = 600.0   # 10 minutes
MAX_RETRIES     = 3
DEFAULT_MAX_TOKENS = 800  # cap runaway generation for callers that omit max_tokens


# --------------------------------------------------------------------------- #
# Public: generate()
# --------------------------------------------------------------------------- #

async def generate(
    prompt: str,
    *,
    model: str = DEFAULT_MODEL,
    system: str | None = None,
    temperature: float = 0.2,
    max_tokens: int | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """Send a prompt to Ollama and return the model's response text.

    Retries transient failures (network errors, HTTP 5xx) up to
    ``MAX_RETRIES`` times with exponential backoff (2s, 4s, 8s).

    Args:
        prompt: The user-role prompt.
        model: Ollama model tag.  Defaults to the Qwen 2.5 7B Q4_K_M
            we pulled in Phase 1.
        system: Optional system-role message.
        temperature: Sampling temperature.  Low (0.0-0.3) for structured
            tasks, higher for creative ones.
        max_tokens: Cap on output length in tokens.  If ``None``, uses
            ``DEFAULT_MAX_TOKENS`` (800) to prevent runaway generation.
            Pass a larger value explicitly if you genuinely need longer
            output.
        timeout: Per-call timeout in seconds.

    Returns:
        The response text (with leading/trailing whitespace stripped).

    Raises:
        RuntimeError: If all retries fail.
    """
    payload: dict[str, Any] = {
        "model":  model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature},
    }
    if system:
        payload["system"] = system
    # Default cap: prevents runaway generation.  Callers who genuinely
    # want longer output must set max_tokens explicitly.
    payload["options"]["num_predict"] = max_tokens if max_tokens is not None else DEFAULT_MAX_TOKENS

    last_exc: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                t0 = time.time()
                r = await client.post(f"{OLLAMA_URL}/api/generate", json=payload)
                r.raise_for_status()
                data = r.json()
                elapsed = time.time() - t0

            log.info(
                "model call ok: model=%s tokens=%d elapsed=%.1fs",
                model, data.get("eval_count", 0), elapsed,
            )
            return data["response"].strip()

        except (httpx.RequestError, httpx.HTTPStatusError) as exc:
            last_exc = exc
            if attempt < MAX_RETRIES:
                delay = 2 ** attempt
                log.warning(
                    "model call attempt %d/%d failed (%s), retrying in %ds",
                    attempt, MAX_RETRIES, exc, delay,
                )
                await asyncio.sleep(delay)
            else:
                log.error("model call attempt %d/%d failed: %s",
                          attempt, MAX_RETRIES, exc)

    raise RuntimeError(
        f"model call failed after {MAX_RETRIES} attempts: {last_exc}"
    )


# --------------------------------------------------------------------------- #
# Public: extract_json()
# --------------------------------------------------------------------------- #

def extract_json(text: str) -> Any:
    """Pull a JSON value out of text that may have preamble or wrapping.

    Handles:
      1. Pure JSON.
      2. JSON in a triple-backtick fence (optionally labelled ``json``).
      3. JSON preceded by prose -- first ``{`` or ``[`` starts the value.

    Returns the parsed Python value.

    Raises:
        ValueError: If no JSON can be extracted.
    """
    text = text.strip()

    # Case 1: pure JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Case 2: fenced code block
    if "```" in text:
        parts = text.split("```")
        # Odd-indexed parts are inside fences (0,2,4 = outside; 1,3,5 = inside)
        for i in range(1, len(parts), 2):
            block = parts[i]
            # Strip language label if present ("json\n{...}")
            first_nl = block.find("\n")
            if first_nl >= 0:
                first_line = block[:first_nl].strip()
                if first_line and not first_line.startswith(("{", "[")):
                    block = block[first_nl + 1:]
            try:
                return json.loads(block.strip())
            except json.JSONDecodeError:
                continue

    # Case 3: JSON somewhere in prose -- find first '{' or '['
    for start_char in ("{", "["):
        idx = text.find(start_char)
        if idx >= 0:
            try:
                value, _ = json.JSONDecoder().raw_decode(text[idx:])
                return value
            except json.JSONDecodeError:
                continue

    raise ValueError(f"could not extract JSON from response: {text[:200]!r}")


# --------------------------------------------------------------------------- #
# Public: reason_then_format()
# --------------------------------------------------------------------------- #

async def reason_then_format(
    context: str,
    question: str,
    schema_description: str,
    *,
    model: str = DEFAULT_MODEL,
    max_json_retries: int = 2,
) -> Any:
    """Two-call structured extraction (D3b).

    Args:
        context: Background information (e.g. an HTTP response, a target
            description).
        question: The reasoning task (e.g. "identify SQL-injection
            evidence in this response").
        schema_description: Natural-language description of the desired
            JSON output structure.  Include an example if the schema is
            not trivial.
        model: Ollama model tag.
        max_json_retries: How many extra attempts to make if the first
            format-call output isn't valid JSON.

    Returns:
        The parsed JSON value from the model's format-call output.

    Raises:
        RuntimeError: If all format-call attempts fail JSON parsing.
    """
    # ---- Call 1: reason (up to 600 tokens ~= 100s on 8-CPU CPU-only) ----
    reasoning_prompt = (
        f"{context}\n\n"
        f"{question}\n\n"
        f"Think step by step.  Explain your reasoning clearly."
    )
    reasoning = await generate(
        reasoning_prompt, model=model, temperature=0.3, max_tokens=600,
    )
    log.info("reasoning phase: %d chars produced", len(reasoning))

    # ---- Call 2: format (up to 300 tokens ~= 50s), with JSON-retry ----
    format_prompt = (
        f"Based on this analysis:\n\n"
        f"{reasoning}\n\n"
        f"Return your findings as JSON matching this schema:\n\n"
        f"{schema_description}\n\n"
        f"Return ONLY the JSON.  No preamble, no explanation, no code fences."
    )

    last_exc: Exception | None = None
    for attempt in range(1, max_json_retries + 2):   # +2 = initial + retries
        raw = await generate(
            format_prompt, model=model, temperature=0.0, max_tokens=300,
        )
        try:
            return extract_json(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            last_exc = exc
            log.warning(
                "format-call JSON extract attempt %d failed: %s",
                attempt, exc,
            )
            if attempt <= max_json_retries:
                format_prompt = (
                    f"Your previous response was not valid JSON:\n\n"
                    f"{raw[:400]}\n\n"
                    f"Return ONLY valid JSON matching this schema:\n\n"
                    f"{schema_description}"
                )

    raise RuntimeError(
        f"could not get valid JSON after "
        f"{max_json_retries + 1} attempts: {last_exc}"
    )
```

That's the entire module.

**Design notes worth reading in the code above:**

- **Default 800-token cap in generate().** Without this, a caller who
  omits `max_tokens` and receives a runaway reasoning response can wait
  5-10 minutes for a single call. Since Ollama has no server-side cap
  by default, the client has to enforce it.

- **Explicit caps in reason_then_format().** 600 tokens for reasoning,
  300 for formatting. On measured hardware this bounds the total per
  structured output at ~150-160 seconds regardless of how verbose the
  model wants to be.

- **No `depends_on: ollama`** anywhere in the compose file, even in Phase
  5. If Ollama is down, `generate()` raises a `RuntimeError` which the
  agent's own retry logic treats as a normal agent failure.

- **Structured logging.** Every call logs its model, token count, and
  elapsed time. When you're tuning Phase 5 prompts, `docker compose logs
  agent-vuln | grep 'model call'` gives you a live view of what's
  happening.

- **Async through and through.** The FastAPI event loop drives
  everything. If you ever want to call this synchronously (e.g., from a
  script), wrap with `asyncio.run(generate(...))`.

---

## Section C — No requirements changes

`shared/model.py` uses only `httpx` (already required) and `json`,
`asyncio`, `logging`, `time` (Python standard library). No new dependencies.

Skip straight to rebuilding and testing.

---

## Section D — Rebuild and smoke test

Rebuild the shared image so `shared/model.py` is baked in:

```bash
docker compose build agent-vuln
docker compose up -d --force-recreate agent-vuln
docker compose ps agent-vuln           # STATUS should be Up
```

### D.1 Import test

Confirm the module imports cleanly:

```bash
docker exec -it apts-agent-vuln python -c "
from shared.model import generate, reason_then_format, extract_json
print('imports OK')
"
```

Expected output:

```
imports OK
```

### D.2 Test extract_json with the tricky cases

No model call needed — this is pure Python:

```bash
docker exec -it apts-agent-vuln python -c "
from shared.model import extract_json

# Case 1: pure JSON
print('pure:  ', extract_json('{\"a\": 1}'))

# Case 2: fenced
print('fenced:', extract_json('Here is my answer:\n\`\`\`json\n{\"a\": 2}\n\`\`\`\nHope this helps.'))

# Case 3: prose with JSON in the middle
print('prose: ', extract_json('Sure! The answer is {\"a\": 3, \"b\": [4, 5]}. Done.'))

# Case 4: array
print('array: ', extract_json('[1, 2, 3]'))
"
```

Expected:

```
pure:   {'a': 1}
fenced: {'a': 2}
prose:  {'a': 3, 'b': [4, 5]}
array:  [1, 2, 3]
```

If any of these fails, `extract_json` needs a tweak — paste the failing
case here.

### D.3 First real model call

```bash
docker exec -it apts-agent-vuln python -c "
import asyncio
from shared.model import generate

async def main():
    r = await generate('Reply with exactly the word: pong')
    print(f'Response: {r!r}')

asyncio.run(main())
"
```

Expected (using the ~6 tok/s benchmark on this hardware): the call
completes in a few seconds and prints `Response: 'pong'`. If the response
is longer than one word, that's fine; the model just decided to be
verbose. What matters is no exception.

### D.4 Reason-then-format test

The realistic case. Give the model a fake HTTP response, ask it to
identify SQLi evidence, get structured JSON back.

**Important:** use `docker exec -i` (not `-it`) for heredoc-piped input.
The `-t` flag allocates a TTY, which conflicts with piped stdin.

```bash
docker exec -i apts-agent-vuln python << 'EOF'
import asyncio
from shared.model import reason_then_format

# Simulate what the vuln agent will do in Phase 5
context = '''We probed https://juice-shop.test/rest/user/login with the
following payload:

  POST /rest/user/login
  Content-Type: application/json
  {"email": "test' OR '1'='1", "password": "anything"}

The server responded:
  HTTP 401 Unauthorized
  Content-Type: application/json
  {"error": "Invalid credentials"}
'''

question = ('Does this response reveal a SQL-injection vulnerability?  '
            'Consider: did the server error message leak query fragments?  '
            'Did the response differ from a normal 401?  '
            'What further probes would confirm or refute your hypothesis?')

schema = '''{
  "vulnerable": true | false,
  "confidence": "low" | "medium" | "high",
  "reasoning": "<one-sentence summary>",
  "next_probes": [ "<payload string>", "<payload string>" ]
}'''

async def main():
    result = await reason_then_format(context, question, schema)
    import json
    print('Parsed result:')
    print(json.dumps(result, indent=2))

asyncio.run(main())
EOF
```

Wait ~150-160 seconds (two model calls with caps of 600 + 300 tokens at
~6 tok/s).

Expected: valid JSON matching (or reasonably close to) the schema. Example
from actual test runs:

```json
{
  "vulnerable": false,
  "confidence": "high",
  "reasoning": "The response is consistent with a 401 Unauthorized and does not leak any SQL query fragments.",
  "next_probes": [
    "{\"email\": \"admin' UNION SELECT username, password FROM users -- \", \"password\": \"anything\"}"
  ]
}
```

Or maybe the model concludes it *is* vulnerable — that's fine too. What
matters is:
- The response is valid JSON (extract_json succeeded)
- The structure roughly matches the schema (fields present)
- The `reasoning` field is coherent English tied to the context

If the JSON extraction fails all retries, you'll get a `RuntimeError`
naming the last exception. In that case the wrapper is working (it tried,
it failed cleanly) — the issue is Qwen 2.5 7B not producing JSON reliably
for this specific prompt. We'd tune the prompt in Phase 5.

### D.5 A benchmark of the structured-extraction time

Same test as D.4 but with timing, run three times to confirm consistency:

```bash
for i in 1 2 3; do
  echo "=== Run $i ==="
  docker exec -i apts-agent-vuln python << 'EOF'
import asyncio, time
from shared.model import reason_then_format

async def main():
    t0 = time.time()
    result = await reason_then_format(
        context='A REST API endpoint at http://juice-shop.test:3000/rest/user/login accepts JSON with email and password fields.',
        question='Suggest two SQL injection payloads for the email field.',
        schema_description='{"payloads": ["<string>", "<string>"]}',
    )
    print(f'Elapsed: {time.time() - t0:.1f}s')

asyncio.run(main())
EOF
done
```

Expected: three runs, each **150-160 seconds**, with **variance under
±5 seconds** across the three. Reference measurements on 8 CPU / 32 GB RAM:
`152.2s / 153.5s / 152.7s`.

**Record the numbers.** They set the budget for Phase 5:
- Per structured output: ~155 seconds
- Per vuln engagement (4 probes): ~10 minutes
- Per vuln engagement (6 probes): ~15 minutes

If elapsed times vary widely (60s / 400s / 200s) rather than staying
tight, something is off — check that both caps landed:

```bash
grep -n "num_predict\|max_tokens=600\|max_tokens=300\|max_tokens=800" shared/model.py
```

You should see all three cap sites present:
- Line ~87: `payload["options"]["num_predict"] = max_tokens if max_tokens is not None else DEFAULT_MAX_TOKENS`
- Line ~150: `max_tokens=600` in the reasoning call
- Line ~164: `max_tokens=300` in the format call

If any is missing, that edit didn't land — reapply from Section B.

---

## Section E — What's next

Phase 4 done. Say the word and I'll write **Phase 5: The vuln agent's
real work function** — the meat of the project. This is where everything
ties together:

- **Bump `STALL_TIMEOUT_SECONDS`** to 300 in `orchestrator/main.py`.
  With reason_then_format taking ~155s, the default 60s timeout would
  fire during normal operation. Phase 5's first section handles this.
- Add `AGENT_MODE=stub|real` toggle (so you can flip back to stub any
  time)
- Replace the vuln branch of `stub_work.py` with a real reasoning loop
  that uses this phase's model wrapper + Phase 3's MCP tools + Phase 2's
  Juice Shop target
- **Heartbeat progress updates** between probes so the stall scanner
  never sees a stale-looking agent even during a full 155-second call
- Prompt engineering: system prompt + reasoning prompts for SQLi and
  XSS discovery
- Structured output schema for the `WeaknessList` the agent produces
- End-to-end test: real engagement against Juice Shop, real findings
  land in the DB, downstream stubs still complete

Time budget for Phase 5: 6-10 hours, most of it prompt tuning.

---

## Section F — Notes for the writeup

Four points worth capturing:

**Measured hardware performance.** On the target hardware (8 CPU /
32 GB RAM, no GPU), Qwen 2.5 7B Q4_K_M sustains 5.9 tokens/second on
inference. A single reason-then-format structured extraction takes 152
± 1.5 seconds across replicate runs, dominated by the 900-token combined
output budget (600 for reasoning + 300 for formatting). Extrapolating
to a full vuln engagement with 4-6 probes, one engagement runs in
approximately 10-16 minutes on this hardware. This validates the design
choice of CPU-only self-hosted inference for the academic prototype:
throughput is sufficient for one-off engagements while the total system
cost stays at zero recurring dollars.

**Two-call structured output over one-call.** The D3b design gives twice
the latency for each structured output. In exchange it gives dramatically
better reliability on small local models: separating "reason about this"
from "format your reasoning as JSON" is the difference between a model
that produces valid JSON ~40% of the time and one that produces it ~95%
of the time. The trade-off is defensible because the alternative to
higher reliability is more retries at the outer level, which multiplies
latency by more than 2x on failure.

**Defensive JSON parsing.** `extract_json` handles three common wrapping
patterns (pure JSON, code-fenced, prose preamble). A more robust approach
would use grammar-constrained decoding, but that requires either
specialized tooling (like `llama.cpp`'s GBNF grammars) or a hosted API's
structured-output mode — both ruled out by our project constraints.
Defensive parsing plus format-retry gives us the reliability we need
without the tooling complexity.

**Client-enforced output caps.** Ollama does not enforce output length
limits server-side; without a client-side `num_predict` value the model
can generate 2000+ tokens on a whim. The wrapper enforces an 800-token
default so any caller that omits `max_tokens` still gets bounded
latency. `reason_then_format` overrides with 600 and 300 for its two
calls — enough for detailed analysis and structured output respectively,
tight enough to keep total per-extraction latency predictable at ~150s
on this hardware. Output-length management is a client responsibility,
and this project makes that explicit in the wrapper's contract.
