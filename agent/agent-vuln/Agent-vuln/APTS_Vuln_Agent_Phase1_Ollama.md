# Vuln Agent — Phase 1: Ollama Running with Qwen 2.5 7B

First of six phases toward a real, model-backed Vuln Assessment agent.

Phase 1 gets a working Ollama server in your compose stack with the Qwen 2.5 7B
Instruct model pulled and callable from inside the APTS network. Nothing about
the agent code changes yet — this phase just proves the model layer works.

## What this phase delivers

By the end of Phase 1 you will have:
- An `apts-ollama` container running on the same Docker network as the rest
  of the APTS stack
- The Qwen 2.5 7B Instruct model (Q4_K_M quantization, ~4.5 GB) pulled and
  cached
- Verified inference response from a direct `ollama run` call
- Verified inference response from an HTTP call originating inside another
  container (proves the network wiring the agent will use in Phase 5)
- A benchmark of how long inference actually takes on your hardware

Nothing about the existing skeleton's behaviour changes. Every existing
container keeps running exactly as it did. Ollama is a new service that
nothing else depends on yet.

Time budget: **20-40 minutes**, of which most is waiting for the model pull.

---

## Section 1 — Discover the APTS network name

Docker Compose needs Ollama on the same network as every other APTS service,
otherwise DNS resolution for `ollama` will fail from inside agent containers.
Find the network name your stack is actually using:

```bash
cd ~/apts-skeleton-2      # or wherever your project is
docker inspect apts-orchestrator --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}'
```

This prints the name of the network the orchestrator is on. Common values:
- `apts-skeleton-2_apts-net` — if your compose file declares a named network
  called `apts-net`
- `apts-skeleton-2_default` — if your compose file uses the auto-created
  default network

**Write that exact name down.** You'll paste it into the Ollama service
definition in the next step. In the examples below I'll write it as
`<YOUR-NETWORK-NAME>` — replace with your actual value everywhere it appears.

Cross-check by listing all Docker networks:

```bash
docker network ls
```

You should see `<YOUR-NETWORK-NAME>` in the list. If not, double-check the
inspect command output — it must exactly match a real network.

---

## Section 2 — Add the Ollama service to `docker-compose.yml`

Open `docker-compose.yml`. Find any existing service definition (for example
`database:` or `orchestrator:`) so you know the indentation and style used
by the rest of the file. Note how those services reference the network — you
need to match that syntax.

**Add** the following service definition. Place it after any existing service
— location within the file doesn't matter, but a natural spot is at the end of
the `services:` block, right before the top-level `volumes:` or `networks:`
block if one exists:

```yaml
  ollama:
    image: ollama/ollama:latest
    container_name: apts-ollama
    restart: unless-stopped
    volumes:
      - ollama_data:/root/.ollama
    environment:
      # Keep the model loaded in memory between requests for the whole
      # session. Default is 5 minutes idle unload, which would force a
      # 15-30 second reload every time we haven't hit it recently.
      OLLAMA_KEEP_ALIVE: "24h"
    networks:
      - <YOUR-NETWORK-NAME-WITHOUT-PROJECT-PREFIX>
```

**About the network name in the YAML:** Compose auto-prefixes network names
with your project name at runtime. If the inspect from Section 1 returned
`apts-skeleton-2_apts-net`, the YAML entry is just `apts-net` (Compose adds
the prefix when it creates the container). If it returned
`apts-skeleton-2_default`, the YAML entry is `default`.

The quickest way to get this right: look at how another service in your
compose file lists its networks, and copy that exact value.

Then at the bottom of the file, in the `volumes:` block, **add** the new
named volume. If your file doesn't have a top-level `volumes:` block yet,
create one:

```yaml
volumes:
  ollama_data:
  # ... any existing volumes stay listed here ...
```

Save the file.

**Key design points:**
- **Explicit `networks:` block.** APTS uses a named network, so every service
  must declare membership. A service that omits the block silently lands on
  Compose's default network with no error — and its DNS lookups for peer
  services will fail (which is exactly the trap this section exists to avoid).
- **No `ports:` mapping to the host.** Ollama listens on port 11434 inside
  its container. Other containers reach it via `http://ollama:11434` on
  the internal Docker network. Not exposing it to the host follows the same
  "loopback-only or internal-only" discipline as the rest of the APTS
  services.
- **Named volume `ollama_data`.** Models are cached in `/root/.ollama`.
  Without a volume, every container recreation would re-download the 4.5 GB
  model. The named volume persists across `docker compose down` (but not
  `docker compose down -v`).
- **`OLLAMA_KEEP_ALIVE: "24h"`.** Default is 5 minutes. During Phase 5
  you'll iterate on prompts and it's frustrating to eat the 15-30 second
  reload each time you take a coffee break. 24 hours keeps it warm for
  the whole day.
- **No `depends_on:`.** No existing service needs Ollama yet — Phase 5 will
  add the dependency only for the vuln agent.

---

## Section 3 — Bring up Ollama

```bash
docker compose up -d ollama
```

You'll see Docker pull the `ollama/ollama:latest` image (a few hundred MB)
and start the container. Confirm:

```bash
docker compose ps ollama
```

Expected: `STATUS Up X seconds`.

Confirm Ollama landed on the correct network:

```bash
docker inspect apts-ollama --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}'
```

Must show the same network name as the orchestrator (Section 1). If it shows
something else — usually `bridge` — the YAML fix didn't take. Check that the
`networks:` block is present with correct indentation and the right name,
then:

```bash
docker compose up -d --force-recreate ollama
```

Check the logs to confirm Ollama started clean:

```bash
docker compose logs --tail=20 ollama
```

You should see lines like:

```
Ollama is now serving on 0.0.0.0:11434
```

If instead the container is in `Restarting` state, check the logs for the
actual error and fix before proceeding.

---

## Section 4 — Pull the Qwen 2.5 7B model

This is the long step. The model is ~4.5 GB and the pull is bandwidth-bound
— expect 5-30 minutes depending on your connection.

```bash
docker exec -it apts-ollama ollama pull qwen2.5:7b-instruct-q4_K_M
```

You'll see progress lines like:

```
pulling manifest
pulling ff1d1fc78170... 100% ▕████████▏ 4.4 GB
pulling ...
verifying sha256 digest
writing manifest
success
```

Once it prints `success`, verify the model is registered:

```bash
docker exec -it apts-ollama ollama list
```

Expected output:

```
NAME                              ID              SIZE      MODIFIED
qwen2.5:7b-instruct-q4_K_M        <hash>          4.7 GB    N seconds ago
```

**Why this specific tag:** `qwen2.5:7b` defaults to Q4_K_M quantization on
Ollama, but pinning the explicit tag `qwen2.5:7b-instruct-q4_K_M` protects
you from Ollama silently changing the default in a future release. Reproducible
builds matter for an academic project — you want the model in your writeup
to be the same one anyone else can pull.

---

## Section 5 — Direct inference test

Simplest possible smoke test — run the model interactively:

```bash
docker exec -it apts-ollama ollama run qwen2.5:7b-instruct-q4_K_M "Reply with exactly the word: pong"
```

The **first** call after model load will take 30-60 seconds — Ollama is
loading the ~5 GB of weights into memory. Subsequent calls are much faster
(the model stays warm because of `OLLAMA_KEEP_ALIVE: "24h"`).

Expected output:

```
pong
```

or something very close (models occasionally add whitespace or punctuation).
If you get pong-ish output, the model works.

**Common issues at this step:**

*If the response takes more than 5 minutes:* your host is more constrained
than expected. Check `docker stats apts-ollama` in another terminal to see
memory pressure. If memory is fine but CPU is pegged, this is just how slow
Q4_K_M on 8 CPU is — expect similar times per inference throughout Phase 5.

*If you get an out-of-memory error:* the container hit the 32 GB limit. Check
what else is running on the host (`docker stats`). You may need to reduce
concurrent workloads.

*If it prints unrelated text (not "pong"):* the model works, it just didn't
follow the instruction perfectly. That's fine for this smoke test — Phase 5
will use much more structured prompts.

---

## Section 6 — HTTP inference test from inside the APTS network

The direct test proves Ollama works. This test proves the agents will be
able to reach it via HTTP on the internal network — which is how they'll
actually call it in Phase 5.

The APTS containers are built from `python:3.11-slim-bookworm` which has no
curl or wget — so we use `httpx` (already installed for every Python service):

```bash
docker exec -it apts-orchestrator python -c "
import httpx
r = httpx.post('http://ollama:11434/api/generate',
    json={'model':'qwen2.5:7b-instruct-q4_K_M',
          'prompt':'Reply with exactly the word: pong',
          'stream': False},
    timeout=180.0)
print(r.json())
"
```

Wait 5-60 seconds. Expected JSON response:

```json
{
  "model": "qwen2.5:7b-instruct-q4_K_M",
  "created_at": "2026-08-...",
  "response": "pong",
  "done": true,
  "context": [...],
  "total_duration": 4123456789,
  "load_duration": 12345,
  "prompt_eval_count": 15,
  "prompt_eval_duration": 234567,
  "eval_count": 4,
  "eval_duration": 987654
}
```

The `response` field is the model's actual output. The `total_duration` is
in nanoseconds — divide by 1,000,000,000 to get seconds.

**If this succeeds**, you've proven:
- Ollama is reachable at hostname `ollama` from other containers on the
  APTS network. This is DNS provided automatically by Docker Compose from
  the service name.
- The HTTP API is functioning at port 11434.
- The model responds within reasonable time.

**If you see `httpx.ConnectError: [Errno -3] Temporary failure in name
resolution`:** the orchestrator can't find `ollama` via DNS. This is a
network-membership issue — Ollama is on a different Docker network. Go
back to Section 3 and verify Ollama is on the same network as the
orchestrator. If needed, fix Section 2's YAML and rerun
`docker compose up -d --force-recreate ollama`.

**Note on `timeout=180.0`:** httpx's default timeout is 5 seconds, far too
short for a cold model call. The explicit 180-second timeout handles the
first-call model-loading time. If a call ever hits this timeout, the
inference is still running in Ollama — retry the same call, it should
succeed quickly the second time because the model is now warm.

---

## Section 7 — Realistic benchmark

Now measure what actual inference (not "reply with one word") looks like
on your hardware. This tells you what to expect during Phase 5 development
and lets you plan engagement runtimes realistically.

Run a benchmark prompt that resembles what the vuln agent will send:

```bash
docker exec -it apts-orchestrator python -c "
import httpx, time
prompt = ('You are analysing a web application. Given the URL '
          'https://example.com/login and a form with fields username '
          'and password, list two SQL injection payloads that could '
          'probe for weaknesses. Answer as a short numbered list.')
t0 = time.time()
r = httpx.post('http://ollama:11434/api/generate',
    json={'model':'qwen2.5:7b-instruct-q4_K_M',
          'prompt': prompt, 'stream': False},
    timeout=600.0)
elapsed = time.time() - t0
data = r.json()
print(f'Elapsed (wall clock): {elapsed:.1f}s')
print(f'Ollama total_duration: {data[\"total_duration\"] / 1e9:.1f}s')
print(f'Ollama eval_count:     {data[\"eval_count\"]} tokens')
print(f'Response:')
print(data['response'])
"
```

Expected on 8 CPU / 32 GB RAM:
- **Elapsed:** 45-180 seconds — a typical inference call takes 45 seconds
  to 3 minutes on CPU-only depending on how much output the model generates.
- **eval_count:** the number of output tokens produced. Divide by
  `eval_duration/1e9` to get tokens per second — expect roughly 3-8 tok/s
  on this hardware.

**Record the Elapsed number.** You'll use it to estimate Phase 5 engagement
runtimes: one vuln engagement will make roughly 4-8 model calls (planning +
one per probe + format extraction). If each call is 90 seconds, a vuln
engagement will take 6-12 minutes. That informs how you tune the
stall-detection timeout in Phase 5.

---

## Section 8 — Checkpoint

Verify everything is in a good state before moving on:

```bash
# All services up
docker compose ps

# Ollama in particular
docker compose ps ollama

# Model pulled and cached
docker exec apts-ollama ollama list

# Ollama volume exists and has data in it
docker volume ls | grep ollama_data
```

Then check the volume size (should be ~5 GB):

```bash
docker system df -v | grep ollama_data
```

All existing engagements should still work exactly as before:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli tui
# fill in the form as usual, submit
# should complete in ~30 seconds with all stubs (no ollama involvement yet)
```

That last test is the important one — it confirms Phase 1 truly changed
nothing about the existing skeleton. Ollama is present but idle; no agent
calls it yet.

---

## Section 9 — What's next

Phase 1 done. Say the word and I'll write **Phase 2: Juice Shop target +
network wiring** — adding a real vulnerable target the vuln agent will be
able to reach.

Rough estimate of what Phase 2 covers:
- Add `juice-shop` service to docker-compose (uses the official
  `bkimminich/juice-shop` image), on the same network you identified in
  Section 1
- Wire DNS so `juice-shop.test` resolves to the container from inside
  agent containers
- Verify HTTP requests from an agent container reach Juice Shop
- Nothing about the agent code changes — same "add plumbing, verify, no
  behaviour change" discipline as this phase

Time budget for Phase 2: 20-30 minutes.

## Notes for the writeup

Three points worth capturing while they're fresh:

**The choice of Ollama over llama.cpp direct.** Ollama gives us process
isolation (the model runs in its own container, insulated from the agent
containers) and an HTTP API that's identical whether we're on CPU or GPU.
When the modelling phase eventually gets a GPU, changing hardware means
changing an image tag and a runtime flag — no agent code touches. The trade
is one extra container in the stack (~200 MB overhead) which is negligible
next to the 5 GB model.

**The choice of Qwen 2.5 7B Q4_K_M.** Qwen 2.5 was released with explicit
attention to structured-output reliability, which matters for the D3b
reason-then-format design chosen for the vuln agent. Q4_K_M is the sweet
spot on 8 CPU / 32 GB RAM: bigger quantizations (Q5, Q6, Q8) improve
quality marginally but slow inference significantly; smaller quantizations
(Q3, Q2) run faster but introduce hallucinations that would break the
JSON-parsing path. Q4_K_M is what the Ollama library and the llama.cpp
community both recommend as the CPU-serving default at this parameter count.

**Explicit network membership.** The APTS stack uses a named Docker network
rather than Compose's implicit default, so services can be added or removed
without accidental isolation. Every service definition includes an explicit
`networks:` block; a service that omits it silently lands on a different
network with no error, and its DNS lookups for peer services fail. Making
the network membership explicit at the service level prevents this class of
misconfiguration and forced Ollama's config to be discovered rather than
guessed.
