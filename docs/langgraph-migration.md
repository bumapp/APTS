# LangGraph / LangChain + Langfuse migration — DONE

The hand-rolled `httpx` agentic loop is gone. **Every** agentic stage
(recon/vuln/mitre/exploit/script/adviser) now runs on LangGraph /
LangChain with Langfuse observability, and the legacy code has been removed.
Branch: `feature/aws-next` (off `AWS`).

## Where things are now

| Piece | File |
|---|---|
| Chat-model factory (all OpenAI-compatible backends) + Langfuse wiring | `shared/llm.py` |
| Prompt registry (Langfuse-backed, in-repo default fallback) | `shared/prompts.py` |
| Boot-time validated config (pydantic) | `shared/settings.py` |
| MCP-v2 → LangChain tool wrapper + `create_react_agent` glue + compaction | `agent/services/workers/agentic.py` |
| Vuln loop (hypothesis generation) | `agent/services/workers/vuln_worker.py` |
| MITRE loop (ATT&CK mapping) | `agent/services/workers/mitre_worker.py` |
| Exploit loop (proof, credential injection, deterministic signal) | `agent/services/workers/exploit_worker.py` |
| Script loop (sandbox PoC) | `agent/services/workers/script_worker.py` |
| Recon triage (crawl is a tool; the model only ranks) | `agent/services/workers/recon_worker.py` |
| Adviser reasoning (grouped, proven-only, ranked report) | `agent/services/workers/adviser_worker.py` |
| Composition root (no flag, no provider switch) | `agent/main.py` |
| Deps | `requirements.txt` (langchain / langgraph / langchain-openai / langfuse) |
| Tests (28, offline, real graphs) | `tests/test_langgraph_migration.py` |

## What this consolidation removed/renamed (vs the strangler state)

The migration had been strangler/flag-gated (`APTS_AGENT_FRAMEWORK`, parallel
`*_lc.py` modules). That scaffolding is gone:

- **The flag is gone.** `APTS_AGENT_FRAMEWORK` / `LANGGRAPH_WORKERS` no longer
  exist; LangGraph is the only engine. `agent/main.build_worker` just picks the
  worker.
- **The `_lc` suffix is gone.** `agentic_lc.py` folded into `agentic.py`;
  `vuln_worker_lc.py` / `exploit_worker_lc.py` became the real
  `vuln_worker.py` / `exploit_worker.py` (domain helpers that used to be imported
  from the legacy modules now live in the one worker file).
- **The hand-rolled httpx loop is gone** (`agentic.chat`, `_canonicalise_tool_args`,
  `mcp_tools_to_openai`, the dict-message `compact`).
- **Four dead LLM modules deleted, one renamed.** The injected `LlmClient` family
  (`shared/llm.py` old, `llm_aws.py`, `llm_local.py`, `llm_hf.py`) and
  `base.ask_for` were already dead — every loop drove the model through
  `agentic.chat`, not the injected client, and `ask_for`/`complete_json` had no
  callers. Deleted. The LangChain factory (`llm_langchain.py`) was renamed to the
  single `shared/llm.py`. The `APTS_LLM_PROVIDER` switch and the dead
  `APTS_LLM_*` / `APTS_HF_*` compose env went with them.
- **Config reads folded into settings.** `agentic.MCP_URL` / `CONTEXT_BUDGET_CHARS`
  and `vuln.PROMPT_BUDGET_CHARS` now come from `shared/settings.py` (validated at
  boot) instead of raw `os.environ`.

## Design decisions (in code)

- **One chat model for every backend.** All runtime backends (AWS Bedrock's
  OpenAI surface, local llama.cpp, DeepSeek) speak `/v1/chat/completions`, so a
  single `ChatOpenAI` configured from the same env vars covers them
  (`shared/llm.build_chat_model`). A keyless endpoint is treated as local llama
  (`enable_thinking=false` via `extra_body`); a keyed endpoint gets `store=false`.
- **No `langchain-mcp-adapters`.** It targets the MCP **v1** SDK; this repo pins
  MCP **v2** (`from mcp import Client`). We wrap the v2 client's tools as
  `StructuredTool`s ourselves (`agentic.as_langchain_tools`), preserving the
  domain guards as `transform` / `on_call` / `observe` hooks.
- **Langfuse fails open.** No keys / package missing ⇒ empty callback list, the
  loop still runs (`shared/llm.langfuse_callbacks`). Secrets are masked before
  export; `store=false` opts out of provider-side retention; one run = one trace
  (`trace_run`); `flush()` on stage end.
- **Security invariant preserved (exploit).** The deterministic proof signal is an
  `on_call` hook that sets `det_basis` from the raw sqlmap/xss_prove payload the
  moment it fires — independent of the model's verdict. A PROVEN claim with no
  signal is recorded `model_judgment`, never upgraded. Covered by
  `test_exploit_lc_proven_without_signal_is_model_judgment`.

## Open items

1. ✅ **Live model auth — RESOLVED (2026-10-01).** The earlier HTTP 401s from
   `bedrock-mantle.eu-north-1.api.aws` were a **stale/invalid key**, not an auth-
   method problem. The endpoint accepts a plain `Authorization: Bearer <ABSK… key>`
   (an AWS Bedrock API key), which is exactly what `ChatOpenAI` sends — **no SigV4,
   no code change.** A valid key in `tokens/aws_llm.key` (the `llm_api_key` compose
   secret, read by `shared.llm._api_key`) authenticates; verified end-to-end through
   `build_chat_model(...).ainvoke(...)` → HTTP 200 with `store=false`. (The gateway
   *also* validates SigV4 if signed with service `bedrock-mantle` / region
   `eu-north-1`, but bearer is simpler and is what the stack uses.) Keep the key out
   of git — `tokens/` and `*.key` are gitignored.
2. **Publish the prompts to Langfuse.** The registry already prefers Langfuse by
   label and falls back to the in-repo default; publishing `recon.rank`,
   `vuln.system`, `mitre.system`, `exploit.system`, `script.system`,
   `adviser.system` makes the defaults pure fallbacks and the versions
   trace-linked.
3. **Creds from a runtime secret store**, not env/mounted file (Langfuse keys, the
   model bearer).
4. **Per-tool knobs → settings.** The per-worker step/token counts
   (`APTS_VULN_MAX_STEPS`, etc.) still read `os.environ` directly; fold them into
   `shared/settings.py` the same way `mcp_url`/`context_chars`/`prompt_chars` now are.
5. **Harder trace masking** — the current mask is key/pattern redaction; the
   monorepo's "emit lengths, never values" is the P2 upgrade if a hard guarantee
   is needed.

## How to run the tests

```bash
python -m venv .venv-lc && . .venv-lc/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/test_langgraph_migration.py -q   # 28 passing
```
