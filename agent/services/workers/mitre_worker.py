"""MITRE ATT&CK mapping — an agentic loop over the native MCP server.

Takes the Vulnerability Register from the previous stage and tags every weakness
with ATT&CK Tactics and Techniques (PRD §5.4). Like the vuln and exploit stages,
this is a genuine agentic loop rather than one batched call: for each weakness
the model drives the ATT&CK reference tools on ``mcp-native`` (``mcp_native.
mitre_loop``) — search for candidate techniques, validate an id, decide — and
the worker keeps only the ids the ``attack_technique`` tool confirmed.

Two layers of checking, and it is worth being precise about what each buys:

* **The tool is the trust boundary.** ``mitre_loop.run_weakness`` calls
  ``attack_technique`` for every id the model proposes and discards any the
  catalogue does not know, substituting the authoritative name and tactic. A
  hallucinated id does not survive the loop — this is the ``attack_validate``
  capability the old single-call version only wished for.
* :class:`AttackMap` is the final schema gate on the assembled result: it
  enforces §5.4's "every finding gets at least one technique". The catalogue is
  a curated web-app subset, not the whole matrix, so coverage — not correctness
  of the ids that do map — is the remaining gap.

**Stop condition.** The worker runs the loop over the weaknesses that are still
untagged, up to ``APTS_MITRE_MAX_PASSES`` times, and stops as soon as a check
finds nothing left to map. A pass that tags nothing new is not retried — that
routes into the orchestrator's ordinary retry path instead of burning passes.

The model is constrained to the weakness IDs it was given: downstream stages
join on those IDs, so a mapping for an ID that was never in the register is
dropped rather than passed on.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx
from pydantic import ValidationError

from shared.llm import LlmClient
from shared.models import AttackMap

from agent.services.mcp_service import McpService
from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("agent.workers.mitre")

MCP_URL = os.environ.get("APTS_MCP_URL", "http://mcp-native:9000/mcp")
LLM_TIMEOUT = float(os.environ.get("APTS_LOOP_LLM_TIMEOUT", "150"))
# How many times the worker re-runs the loop for the weaknesses still untagged
# before giving up. One or two passes normally clears a register; the cap bounds
# cost and latency.
MAX_PASSES = int(os.environ.get("APTS_MITRE_MAX_PASSES", "3"))


class MitreWorker:
    """Runs the agentic ATT&CK-mapping loop and renders its tags as an AttackMap."""

    def __init__(self, llm: LlmClient, mcp: McpService | None = None) -> None:
        # The loop opens its own MCP client and LLM connection (it talks to
        # mcp-native directly, like the vuln/exploit loops); these are kept only
        # for constructor parity with the composition root.
        self._llm = llm
        self._mcp = mcp

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        from mcp import Client
        from mcp_native import mitre_loop as M

        weaknesses = ctx.upstream.get("weaknesses") or []
        if not weaknesses:
            # Nothing upstream found anything. An empty map is the correct
            # artifact, and running the loop to confirm that would be waste.
            log.info("no weaknesses upstream; emitting empty ATT&CK map")
            return AttackMap().model_dump(mode="json")

        by_id = {w.get("id") or w.get("weakness_id"): w for w in weaknesses}
        by_id.pop(None, None)
        known_ids = set(by_id)

        mapped: dict[str, list[dict[str, Any]]] = {}
        # Loop invariant: `remaining` is exactly the weaknesses with no confirmed
        # tag yet. It shrinks each pass; the loop ends when a check finds it empty.
        remaining = set(known_ids)

        try:
            async with Client(MCP_URL) as client, \
                    httpx.AsyncClient(timeout=LLM_TIMEOUT) as llm:
                tools = [t for t in (await client.list_tools()).tools
                         if t.name in M.AGENT_TOOLS]
                if not tools:
                    raise WorkFailed(
                        "mcp-native exposes none of the ATT&CK tools "
                        f"{sorted(M.AGENT_TOOLS)} — is attack_tool registered?")
                openai_tools = M.mcp_tools_to_openai(tools)
                catalog = (await client.call_tool(
                    "attack_catalog", {})).structured_content
                menu = M.render_menu((catalog or {}).get("techniques", []))

                for attempt in range(1, MAX_PASSES + 1):
                    progressed = False
                    for wid in sorted(remaining):
                        tags, _raw, _trail = await M.run_weakness(
                            client, llm, openai_tools, menu, by_id[wid])
                        if tags:
                            mapped[wid] = tags
                            remaining.discard(wid)
                            progressed = True

                    if not remaining:
                        log.info("all %d weaknesses tagged after %d pass(es)",
                                 len(known_ids), attempt)
                        break
                    if not progressed:
                        raise WorkFailed(
                            f"mapping loop confirmed no ATT&CK technique on pass "
                            f"{attempt} for: {', '.join(sorted(remaining))}")
                    log.info("pass %d: %d tagged, %d still to map", attempt,
                             len(known_ids) - len(remaining), len(remaining))
                else:
                    raise WorkFailed(
                        f"weaknesses left untagged after {MAX_PASSES} passes, "
                        f"which §5.4 forbids: {', '.join(sorted(remaining))}")
        except WorkFailed:
            raise
        except Exception as exc:  # noqa: BLE001 — retryable stage failure
            raise WorkFailed(
                f"mitre loop failed: {type(exc).__name__}: {exc}") from exc

        try:
            artifact = AttackMap(mappings=mapped)
        except ValidationError as exc:
            raise WorkFailed(
                f"ATT&CK map failed schema validation: "
                f"{json.dumps(exc.errors()[:3], default=str)[:300]}") from exc

        log.info("tagged %d weaknesses with ATT&CK techniques", len(artifact.mappings))
        return artifact.model_dump(mode="json")
