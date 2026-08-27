# Vuln Agent — Phase 2: Juice Shop Target + Network Wiring

Second of six phases. Phase 1 got Ollama running and callable. This phase
adds the target the vuln agent will actually probe once Phase 5 goes live:
an OWASP Juice Shop instance, wired into the APTS network so the hostname
`juice-shop.test` resolves to it from any agent container.

## What this phase delivers

By the end of Phase 2 you will have:
- An `apts-juice-shop` container running on the same network as the APTS stack
- The hostname `juice-shop.test` resolving to that container from any agent
  container (via a Docker Compose network alias — no external DNS needed)
- Verified HTTP requests from an agent container reach Juice Shop and return
  real responses
- A documented target URL to use in the TUI: `http://juice-shop.test:3000/`

Nothing about the existing skeleton's behaviour changes. Agents still run
stubs; Ollama is still idle. Juice Shop is a new service that no other
service depends on.

Time budget: **20-30 minutes**, most of it just waiting for the image pull.

---

## Section 1 — Add Juice Shop to `docker-compose.yml`

Open `docker-compose.yml`. **Add** the following service definition alongside
the others (same indentation as `ollama:` from Phase 1). Substitute
`<YOUR-NETWORK-NAME>` with the same value you used for Ollama:

```yaml
  juice-shop:
    image: bkimminich/juice-shop:latest
    container_name: apts-juice-shop
    restart: unless-stopped
    networks:
      <YOUR-NETWORK-NAME>:
        aliases:
          - juice-shop.test
```

Note the different YAML shape compared to Ollama's `networks:` block. Ollama
used the simple form:

```yaml
    networks:
      - <YOUR-NETWORK-NAME>
```

Juice Shop uses the extended form:

```yaml
    networks:
      <YOUR-NETWORK-NAME>:
        aliases:
          - juice-shop.test
```

Both forms are legal Compose syntax. The extended form is required whenever
you need per-service network configuration — in this case, the `aliases`
list. Aliases give the container extra DNS names on that network in addition
to its default service name.

Save the file.

**Key design points:**
- **`bkimminich/juice-shop:latest`.** The official image maintained by the
  Juice Shop project. Deliberately vulnerable Node.js web app used in
  security education worldwide.
- **Network alias `juice-shop.test`.** Docker's DNS resolver in the APTS
  network will now return the container's IP for both `juice-shop` (the
  service name) and `juice-shop.test` (the alias). The `.test` TLD is
  reserved by RFC 6761 for testing — safe to use, will never conflict
  with a real domain.
- **No `ports:` mapping to the host.** Juice Shop listens on port 3000
  inside its container. Only the APTS network needs to reach it. If you
  want to browse Juice Shop from your own laptop for exploratory testing,
  temporarily add `ports: ["3000:3000"]` — but for the vuln agent's
  purposes it stays internal.
- **No `healthcheck:`.** Juice Shop takes ~30 seconds to boot after the
  container starts. A healthcheck would be tidy but requires either bash
  or curl in the image; neither is guaranteed. Compose will show `Up` as
  soon as the Node process is running; we'll verify readiness with the
  HTTP test in Section 4.
- **No `depends_on:`.** No existing service needs Juice Shop yet. Phase 5
  will make the vuln agent's real-mode behaviour depend on it being
  reachable, but by that point it should be up anyway.

---

## Section 2 — Bring it up

```bash
cd ~/apts-skeleton-2
docker compose up -d juice-shop
```

The image pull is ~800 MB — a few minutes on a normal connection. When it
finishes, verify:

```bash
docker compose ps juice-shop
```

Expected: `STATUS Up X seconds`.

Confirm it landed on the right network:

```bash
docker inspect apts-juice-shop --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}'
```

Must show the same network name as `apts-orchestrator` (from Phase 1's
Section 1). If it shows `bridge` instead, the `networks:` block in the YAML
is wrong — go back to Section 1 and fix it, then:

```bash
docker compose up -d --force-recreate juice-shop
```

Check the logs to see Juice Shop announced its listening port:

```bash
docker compose logs --tail=30 juice-shop
```

You should see startup output ending with a line like:

```
info: Server listening on port 3000
```

**Give it ~30 seconds after startup before testing.** Juice Shop initializes
its in-memory database and seeds test data on first boot; hitting it before
that finishes gives HTTP 500 responses. If the log stream ends without the
"Server listening" line yet, wait a bit longer.

---

## Section 3 — Verify DNS resolution

Prove that both hostnames (`juice-shop` and the alias `juice-shop.test`)
resolve from another APTS container:

```bash
docker exec -it apts-orchestrator python -c "
import socket
print('juice-shop:      ', socket.gethostbyname('juice-shop'))
print('juice-shop.test: ', socket.gethostbyname('juice-shop.test'))
"
```

Expected output:

```
juice-shop:       172.20.0.9
juice-shop.test:  172.20.0.9
```

**Both must return the same IP address.** If only `juice-shop` resolves but
`juice-shop.test` errors with "Name or service not known," the alias didn't
take. Recheck the YAML indentation in Section 1 — `aliases:` must be nested
under `<network-name>:` under `networks:`, not at the top level of the
service.

If neither resolves, Juice Shop is on the wrong network. Go back to
Section 2's network check and force-recreate.

---

## Section 4 — Verify HTTP works end-to-end

DNS working doesn't guarantee HTTP does — the container might not have
finished starting, might be listening only on 127.0.0.1, etc. Confirm
with a real request:

```bash
docker exec -it apts-orchestrator python -c "
import httpx
r = httpx.get('http://juice-shop.test:3000/', timeout=15.0)
print(f'Status:       {r.status_code}')
print(f'Content-Type: {r.headers.get(\"content-type\")}')
print(f'Body length:  {len(r.content)}')
print(f'--- first 300 chars ---')
print(r.text[:300])
"
```

Expected output:

```
Status:       200
Content-Type: text/html; charset=UTF-8
Body length:  84371
--- first 300 chars ---
<!--
  ~ Copyright (c) 2014-... Bjoern Kimminich & the OWASP Juice Shop contributors.
  ~ SPDX-License-Identifier: MIT
  -->
<!DOCTYPE html><html lang="en" ...
```

Status 200, HTML content type, real Juice Shop copyright header in the
body — that's the target ready for probing.

**If you get status 500 with an error page:** Juice Shop is still
initializing. Wait 20-30 seconds and retry.

**If you get "Connection refused":** the container is up but not listening.
Check `docker compose logs juice-shop` for a startup error.

**If you get `httpx.ConnectError: [Errno -3] Temporary failure in name
resolution`:** you skipped Section 3 or the alias isn't working. Go back
and fix that first.

While you're here, hit a couple of endpoints to see what Juice Shop exposes.
These are the kinds of things the vuln agent will discover and probe:

```bash
docker exec -it apts-orchestrator python -c "
import httpx
# The REST API root
r = httpx.get('http://juice-shop.test:3000/rest/products/search?q=', timeout=10.0)
print(f'/rest/products/search  status={r.status_code}  size={len(r.content)}')
# The login endpoint (POST)
r = httpx.post('http://juice-shop.test:3000/rest/user/login',
               json={'email': 'x', 'password': 'y'}, timeout=10.0)
print(f'/rest/user/login      status={r.status_code}  body={r.text[:100]}')
"
```

Both should return real Juice Shop responses. The login endpoint should
return HTTP 401 with a JSON error — that's fine, we sent bogus credentials
intentionally.

---

## Section 5 — Quick regression check

Make sure Phase 2 didn't accidentally break the existing skeleton. Run one
normal engagement — everything is still stubs at this point, so it should
complete in ~30 seconds exactly as before:

```bash
docker exec -it apts-orchestrator python -m orchestrator.cli tui
```

When the TUI asks for the target URL, use the new one:

```
Target URL: http://juice-shop.test:3000/
Allowed domains: juice-shop.test
```

Confirm and let it run. Should complete cleanly with all six agents
reporting `done` — because they're stubs and don't actually make HTTP
requests. The target URL is just data being passed through.

Verify in the DB:

```bash
docker compose exec -T database psql -U apts -d apts -c \
    "SELECT status FROM engagements ORDER BY created_at DESC LIMIT 1;"
# should show: complete
```

If this passes, Phase 2 is done — infrastructure is fully in place for the
Phase 3 MCP tools to actually probe the target.

---

## Section 6 — What's next

Phase 2 done. Say the word and I'll write **Phase 3: Real MCP tools for
Vuln** — replacing the stub `mcp_tools` container with real HTTP client
operations the vuln agent will call to probe Juice Shop.

Rough shape of Phase 3:
- Design the MCP tool interface for the vuln agent (GET, POST, form submission,
  response parsing)
- Implement each tool with reasonable safety limits (max response size,
  timeout, rate limiting)
- Wire it into the existing `mcp-tools` container without breaking any
  other agent's stub calls
- Verify from a Python shell inside the vuln container that the tools work
  end-to-end against Juice Shop
- Still no changes to the vuln agent's own code — that's Phase 5

Time budget for Phase 3: 2-3 hours (this is a real implementation phase,
not just plumbing).

---

## Section 7 — Notes for the writeup

Three points worth capturing now:

**The choice of network alias over an external DNS service.** APTS could
have run a dedicated DNS container (e.g., `coredns` or `dnsmasq`) to give
targets custom hostnames. Instead we used Docker Compose's built-in per-
service `aliases`, which piggybacks on the internal DNS Docker already
provides for service names. One less container to run, no zone files to
maintain, and the alias binding is declared in the same file as the
service itself — so anyone reading `docker-compose.yml` sees the full
picture in one place.

**The choice of the .test TLD.** RFC 6761 reserves `.test`, `.example`,
`.invalid`, and `.localhost` for testing and documentation. Using one of
these guarantees the hostname will never conflict with a real domain
name, even if the container escapes its network. Alternatives like
`.local` (mDNS) or a made-up TLD (`.myapp`) either have specific
semantics that clash or could be squatted upstream at any time.

**HTTP-only for now, HTTPS as future work.** Juice Shop's default image
serves plain HTTP on port 3000. Real production penetration testing tools
usually work over HTTPS. Two paths to add TLS if needed later: run a
reverse proxy (nginx or caddy) sidecar that terminates TLS and forwards
to Juice Shop, or configure Juice Shop directly with a cert (their docs
support this). For the academic skeleton, the vuln agent's HTTP-vs-HTTPS
behaviour is a plumbing detail — the reasoning and probe-selection logic
in Phase 5 is identical either way.
