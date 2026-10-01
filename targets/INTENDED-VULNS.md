# Intended vulnerabilities — target lab

Three deliberately vulnerable "AI" apps on **different stacks**, used to benchmark
the recon/exploit tooling. Every issue below is **intentional**. Each is a textbook
class (PortSwigger Web Security Academy / HackTricks names given) so results are
checkable against a known ground truth. **Disposable lab only — never deploy.**

One site is up at a time via `./select.sh <site>`; browse it at `http://localhost:8000`.
Recon/mcp-native reaches each by its internal hostname (below).

---

## 1. NeuralNotes — Flask / SQLite  (internal `http://neuralnotes:5000`)

| # | Class (PortSwigger / HackTricks) | Where | Trigger / proof |
|---|---|---|---|
| 1 | **SQL injection — authentication bypass** (PortSwigger: SQL injection) | `POST /login` (`email`,`password`) | `email=' OR 1=1-- -` logs in as the first user (admin). Query is string-formatted. |
| 2 | **SQL injection — in-band/UNION** (PortSwigger: SQL injection, UNION) | `GET /search?q=` | `q=%' UNION SELECT email,password FROM users-- -` dumps creds. sqlmap-detectable. |
| 3 | **Reflected XSS** (PortSwigger: Cross-site scripting, reflected) | `GET /search?q=` | `q=<script>alert(1)</script>` executes — `q` echoed unescaped. |
| 4 | **IDOR / broken access control** (PortSwigger: Access control, IDOR) | `GET /api/note/<id>` | `/api/note/1` and `/api/note/4` return **private** notes (secrets) with no auth. |
| 5 | **SSRF** (PortSwigger: SSRF) | `GET /summarize?url=` | `url=http://localhost:5000/api/note/1` (or an internal/metadata host) — server fetches it. |

## 2. ChatForge — Node / Express  (internal `http://chatforge:3100`)

| # | Class | Where | Trigger / proof |
|---|---|---|---|
| 1 | **Stored XSS** (PortSwigger: XSS, stored) | `POST /chat` → rendered at `GET /chat` | Send `<img src=x onerror=alert(1)>`; it executes for every viewer of `/chat`. |
| 2 | **IDOR / broken access control** | `GET /api/conversations/:id` | `/api/conversations/1` returns the **admin** conversation (holds a secret) with no auth. |
| 3 | **SSRF** (PortSwigger: SSRF) | `POST /api/summarize` `{ "url": ... }` | Server-side `fetch(url)` of any URL — internal hosts / metadata reachable. |

## 3. PromptVault — PHP / SQLite  (internal `http://promptvault:8080`)

| # | Class | Where | Trigger / proof |
|---|---|---|---|
| 1 | **SQL injection** (PortSwigger: SQL injection) | `GET /?page=search&q=` | `q=%' UNION SELECT name,body FROM prompts-- -` leaks the admin-only prompt. |
| 2 | **Path traversal / LFI** (PortSwigger: Path traversal; HackTricks: LFI) | `GET /?page=download&file=` | `file=/etc/passwd` is read and returned verbatim. |
| 3 | **OS command injection** (PortSwigger: OS command injection) | `GET /?page=ping&host=` | `host=127.0.0.1;id` (or `` `id` ``) executes shell commands. |

---

### Coverage vs our tooling
- **sqlmap** → NeuralNotes #1/#2, PromptVault #1.
- **xss_prove** → NeuralNotes #3 (reflected), ChatForge #1 (stored).
- **http_request** (model judgment) → all the IDOR/SSRF/LFI/cmdi cases.
- **New tools to add** → `arjun`/`ffuf` to discover params like `url`, `file`, `host`,
  `q` and hidden routes; `katana` to crawl/enumerate endpoints before exploitation.

### Note on realism
These are minimal single-file apps — the *vulnerabilities* are faithful to the named
classes, but the apps are intentionally tiny. The point is a controllable,
documented ground truth across three stacks, not production-shaped applications.
