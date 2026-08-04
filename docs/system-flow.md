# How APTS works

New to the project? Start here. Fifteen minutes and you'll know what this
system does, how the pieces fit, and which rules you must not break.

> Prefer a browser? Open [`system-flow.html`](system-flow.html) — same content,
> no dependencies, works offline.

---

## 1. What this thing is

**You give it a website. It tries to break in. It writes you a report.**

A human penetration tester spends 1–4 weeks doing this by hand. APTS is six
small programs — we call them *agents* — that do the same job in a few minutes,
one after another, like a factory line.

```
you ──▶ [1 recon] ──▶ [2 vuln] ──▶ [3 mitre] ──▶ [4 exploit] ──▶ [5 script] ──▶ [6 adviser] ──▶ report
         find the      guess what    label it      try to prove   write repro     write the
         pages         is broken                   it             scripts         report
```

Each agent does one job, hands its result to the next, and saves a copy to the
database. Four of the six use an AI model. Two don't.

---

## 2. The one rule that explains everything else

> **The AI suggests. The code decides.**

Every important decision in this system is made by ordinary Python, not by the
AI. The AI is only allowed to do the fuzzy, judgement-y parts.

**A real example of why.** On an early run, the AI looked at a cross-site
scripting bug and rated it **9.6 out of 10 — critical**. That kind of bug is
normally about a 6. If we'd shipped that, a customer would have dropped
everything to fix a medium-severity issue.

So now the AI is not allowed to give us a number at all. It gives us a
*description* of the bug (`AV:N/AC:L/PR:N/UI:R/...` — a standard format called a
CVSS vector), and our code does the arithmetic. If the AI's description is
obviously exaggerated for that type of bug, the code overrules it and writes
down that it did.

The same idea shows up everywhere:

| The AI is allowed to… | Code always decides… |
|---|---|
| Guess which pages look vulnerable | Whether that page actually exists (we fetch it) |
| Describe how bad a bug is | The severity number |
| Design a test that would prove a bug | Whether the test actually proved it |
| Write remediation advice in English | Every count, status, and score in the report |

**Why so strict?** Because a wrong answer here doesn't just look bad — it goes
into a report that a customer acts on. A made-up vulnerability wastes their
engineers' time. A fake "confirmed" makes them trust a report they shouldn't.

---

## 3. The six agents

| # | Agent | Gets | Produces | Uses AI? |
|---|---|---|---|---|
| 1 | **recon** | the target URL | list of pages, forms, and API routes | **No** |
| 2 | **vuln** | that list | list of suspected bugs, with severity | Yes |
| 3 | **mitre** | the bug list | industry-standard labels for each bug | Yes |
| 4 | **exploit** | the bug list | which bugs are actually real | Yes |
| 5 | **script** | the proven bugs | copy-pasteable scripts to reproduce them | Yes |
| 6 | **adviser** | everything above | the final report | Yes (wording only) |

### Why recon has no AI

Recon's job is "what pages exist on this site?" A crawler answers that
*exactly*. An AI would answer it *approximately* — and a made-up page would then
be tested by agent 2, labelled by agent 3, and printed in the customer's report
as part of their application. So recon just crawls and reports what it saw.

### What "confirmed" means

Only agent 4 is allowed to say a bug is **confirmed**. Everything before it is a
guess. Here's how it works:

1. The AI writes down, *in advance*, what it would need to see to prove the bug.
   For example: *"send `?q=UNIQUEMARKER` and if `UNIQUEMARKER` comes back in the
   page unescaped, that proves reflection."*
2. Our code sends the request and checks for exactly that.
3. Our code also fetches the page **without** the payload. If the marker shows up
   there too, it proves nothing.

That last step exists because of a real bug we hit. The AI said "if the response
contains the word `admin`, that proves it." The server returned a 500 error page
that printed the requested URL — `/rest/admin` — so the word "admin" was right
there. **Four findings got confirmed on nothing at all.** The before-and-after
comparison fixed it.

---

## 4. What happens when you run it

```bash
docker compose up -d

docker exec apts-orchestrator python -m orchestrator.cli start \
  --target=http://juice-shop:3000/ --domain='juice-shop'
```

Then, step by step:

1. **The orchestrator checks your request.** Is this target one we're allowed to
   test? Does the URL you gave actually fall inside the scope you declared? If
   not, it refuses now rather than starting a run that would fail on its first
   request.
2. **Recon crawls the site.** Our practice target (OWASP Juice Shop) is a
   JavaScript app, so its homepage has *no links at all* — everything is drawn by
   JavaScript. So recon also downloads the JavaScript files and pulls the API
   addresses out of them. That takes it from 1 page found to **44 API routes**.
3. **Vuln asks the AI** which of those look risky, then **fetches each one** to
   check it's real. Anything returning 404 gets thrown away — the AI made it up.
4. **Mitre** labels each bug with a standard code (like `T1190`) so the report
   speaks the same language as other security tools.
5. **Exploit** tries to prove each one, using the before-and-after check above.
6. **Script** writes a small Python script for each *proven* bug, so the
   customer's developers can see it for themselves. Nothing gets a script unless
   it was proven.
7. **Adviser** collects everything and writes the report to `./reports/`.

You'll get two files:

```
reports/report-<engagement-id>.md     ← read this one
reports/report-<engagement-id>.json   ← for other tools to parse
```

### A real result

From an actual run against Juice Shop:

- 15 suspected bugs found
- **2 proven** (`/rest/user/whoami` and `/api/SecurityQuestions` both hand out
  data without asking who you are)
- 8 tested but not proven
- 5 never tested

The report says all of that plainly. It does **not** say "13 issues found" and
leave you to assume they're real.

---

## 5. Where the code lives

Every service is organised the same way. Read it top to bottom:

```
controllers/    the web endpoints — receives a request, returns a response
providers/      the recipe — calls services in the right order
services/       the actual work — one job each
repositories/   database only — every SQL query lives here
utils/          little helpers with no dependencies
```

**Each layer only ever calls the one below it.** A controller never runs SQL. A
service never knows there's a web request. If you find yourself importing
"upwards", something has gone wrong.

Where the important bits are:

| I want to… | Look at |
|---|---|
| Change what an agent does | `agent/services/workers/<name>_worker.py` |
| Add a new tool for agents | `mcp_tools/services/tools/` |
| Change who can use which tool | `mcp_tools/services/policy_service.py` |
| Change the safety rules | `mcp_tools/services/guardrails_service.py` |
| Change how the report looks | `agent/services/report_renderer.py` |
| Change severity maths | `shared/cvss.py` |

---

## 6. The safety rules

Agents **never** talk to the target directly. Every single request goes through
one container (`mcp-tools`) that checks it first. Four checks, in this order:

```
1. Are you a real agent?              → no: refused
2. Is this tool on your allowed list? → no: refused
3. What scope was this job approved for?   (looked up in the database)
4. Is this request inside that scope, and not destructive?  → no: blocked
```

Some specifics that matter:

- **Recon literally cannot run shell commands.** Not "shouldn't" — the allowed
  list doesn't include it, so the request is refused before anything reads the
  arguments.
- **Scope comes from the database, never from the agent.** An agent can't ask
  for a bigger playground than it was given.
- **If we can't tell whether something is in scope, we block it.** "I'm not
  sure" and "no" have the same result.
- **The crawler re-checks every link it finds.** The safety check only ever saw
  the first URL. A link to `evil.com` on an approved page is just a normal
  `<a href>` — an unchecked crawler would happily follow it.
- **Nothing destructive is ever sent.** No `DROP TABLE`, no `DELETE`, no `rm`.
  We prove a bug by making the app *react*, never by breaking anything.

### The network

The practice target sits on its own Docker network marked `internal: true`,
which means Docker gives it no route out. It can't reach the internet, and
nothing on your machine can reach it. Only `mcp-tools` sits on both networks —
which is exactly why the safety checks live there and nowhere else.

You can verify this yourself:

```bash
# works
docker exec apts-mcp-tools  python -c "import httpx;print(httpx.get('http://juice-shop:3000/').status_code)"
# fails with ConnectError — agents can't reach the target directly
docker exec apts-agent-recon python -c "import httpx;httpx.get('http://juice-shop:3000/',timeout=5)"
```

---

## 7. Running the tests

189 tests, no network or database needed:

```bash
docker build -t apts-skeleton:latest .
docker run --rm --user root \
  -v "$PWD/tests:/app/tests:ro" -v "$PWD/pytest.ini:/app/pytest.ini:ro" \
  apts-skeleton:latest sh -c "pip install -q pytest pytest-asyncio && python -m pytest -q"
```

Tests that call the real AI model are skipped by default so nobody spends money
by accident. Turn them on with `APTS_LIVE_LLM_TESTS=1`.

Want to watch the safety checks work without running the whole system?

```bash
python scripts/trace_flow.py
```

---

## 8. What isn't finished

Be honest about this in any demo:

- **The AI picks weak proof signals.** Our checking is solid, but the AI often
  chooses something lazy like "did it return 200?" — which proves the page
  exists, not that it's broken. Most bugs stay unproven as a result.
- **Standard labels aren't verified.** We check that `T1190` is the right
  *shape*, not that it's the right *label*. A real code applied to the wrong bug
  still gets through.
- **No PDF.** Markdown and JSON only.
- **No Simulation Engine.** The spec describes a feature that generates practice
  websites on demand — six templates, adjustable difficulty. It doesn't exist
  yet; we borrow OWASP Juice Shop instead. That's roughly 40% of the spec.

---

## Jargon

| Term | Meaning |
|---|---|
| **Agent** | One of the six programs in the pipeline |
| **Engagement** | One run against one target |
| **Scope** | The domains and paths we're allowed to touch |
| **Artifact** | The typed result one agent hands to the next |
| **MCP** | The container holding every tool agents can use |
| **Guardrails** | The safety checks that block unsafe requests |
| **CVSS** | Industry-standard 0–10 severity score |
| **ATT&CK** | Industry-standard catalogue of attacker techniques |
| **Juice Shop** | A deliberately broken practice website |
