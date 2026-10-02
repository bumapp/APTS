# Recon migration guide

What this branch adds: an **agentic, phased recon stage** (replaces the old single-crawl
recon) plus the MCP tools it drives, and the **findings → vuln/exploit** wiring so recon's
graded findings are proven downstream. This doc is for an assistant/engineer merging it
into another codebase.

## The recon pipeline (what it does)

```
Phase 0  (code)   katana headless-deep sweep  -> breadth URI/API map
Phase 0.5 (code)  peek: render each route     -> per-page inputs + on-load XHRs (meaning map)
Phase 1  (agent)  crawl_v2 + ffuf + arjun      -> capture REAL requests + unlinked/hidden surface
Phase 2  (code)   merge + one grade call       -> grouped, graded findings  (AssetMap)
```
- Phase 0 is **fail-loud**: if katana errors/returns 0 it raises `WorkFailed` (no blind run).
- The agent loop decides *which* routes/tools; code owns the raw surface and the dedup/grouping.
- Findings are **page-grouped** (`findings_tree`: rogue-first, then per page) and each carries
  its raw captured `request` as evidence.

## Files to migrate

**Recon stage (agent side):**
- `agent/services/workers/recon_worker.py` — the stage: phases 0/0.5/2, merge, grade,
  grouping (`_split_endpoints`, `_phase1_task`, `_peek_findings`, `_group_findings`,
  `_attach_requests`, `_findings_tree`), prompts (`RECON_LOOP_SYSTEM`, `RECON_GRADE_SYSTEM`).
  Opt-in per-phase audit dumps via env `APTS_RECON_DEBUG_DIR`.
- `agent/services/workers/recon_graph.py` — the Phase-1 LangGraph loop (agent↔tools, de-dup
  guard, shallow-crawl coaching). Tools exposed to the model: `crawl_v2`, `ffuf`, `arjun`.

**MCP tools (mcp_native/ — the server the loop calls):**
- `mcp_native/tools/katana_tool.py` — katana wrapper. Flags: `js_crawl, jsluice, headless,
  xhr, known_files`. Headless uses katana's own go-rod Chrome (**NOT** `-system-chrome-path`);
  salvages partial results on timeout; needs `HOME=/tmp`.
- `mcp_native/tools/ffuf_tool.py` — ffuf; AI picks a SecLists wordlist by purpose; `HOME=/tmp`.
- `mcp_native/tools/arjun_tool.py` — hidden-parameter discovery; `HOME=/tmp`.
- `mcp_native/tools/playwright_live.py` — **NEW**: `peek` (Phase 0.5 batch render, concurrent)
  + raw Playwright primitives `pw_goto/snapshot/fill/click/press/requests` (a browser the agent
  can drive step-by-step; optional).
- `mcp_native/crawler/crawler_v2.py` — generic browser crawler (fill-by-type + Enter-submit on
  the **password field**; no heuristics). This is what captures the real login/form POSTs.
- `mcp_native/tools/crawl_v2_tool.py` — MCP wrapper for crawler_v2.
- `mcp_native/tools/__init__.py` — registers the above (add to `ALL`).
- `mcp_native/Dockerfile` — installs katana/ffuf/arjun + a sparse SecLists checkout; CMD
  background-warms katana's Chrome on boot. **Gotcha:** a fresh container must have that Chrome
  cached or the first headless katana returns 0 — see "Gotchas".

**Shared contract:**
- `shared/models.py` `AssetMap` — additive fields: `mode, summary, findings,
  findings_tree, request_tree`. `findings` each = `{finding, where, category, grade, reason,
  page, request}`. Downstream still reads `endpoints`/`observed_requests` directly.

**Findings → downstream (vuln):**
- `agent/services/workers/vuln_worker.py` — folds recon findings into the register
  (`_finding_to_weakness`, high/medium, request attached as `origin_request`); deterministic
  `_group_for_vuln` (dedup requests by `(method, path, param-set)` + group by page).
  Loads recon's AssetMap from the results store.
- `agent/main.py` — pass the results store to `VulnWorker(llm, results)` (needed for the above;
  `ctx.upstream` is empty in orchestrator-driven mode).

## Integration note (the one real merge cost)

This recon drives the model with **raw httpx (`agentic.chat`) + a hand-rolled LangGraph
`StateGraph`**. If the target codebase standardizes on `langchain_openai.ChatOpenAI` +
`langgraph.prebuilt.create_react_agent` + Langfuse, port the Phase-1 loop to that: expose the
same three tools as LangChain tools, keep the code-owned Phases 0/0.5/2 around it, and pass
`config={"callbacks": langfuse_callbacks(), ...}`. The stage logic and tools are engine-agnostic;
only the model-call layer changes.

## Gotchas
- **katana headless Chrome**: katana downloads its own Chrome at first headless use. Pre-bake it
  into the image or warm it on boot against a *real* page (the example.com warm does NOT download).
  Symptom if missing: Phase 0 raises "katana returned 0 endpoints".
- **`HOME=/tmp`** is required for katana/ffuf/arjun (they write `~/.config`; the service user has none).
- **Transport noise**: socket.io/websocket dismissal is **prompt-driven** in recon (not code).
- **Known gaps**: multi-step/captcha forms (register/contact) don't auto-submit; recon runs
  unauthenticated (no behind-login pass). katana depth-2 headless may not finish in its timeout
  (salvages partial) — tune `depth`/`timeout_sec` in `recon_worker` Phase 0.
