"""MITRE ATT&CK mapping — the first stage backed by a real model.

Takes the Vulnerability Register from the previous stage and tags every
weakness with ATT&CK Tactics and Techniques (PRD §5.4).

This stage was chosen to go first deliberately. Its output is a closed set of
identifiers rather than free prose, so it is the cheapest place to prove the
model plumbing: a wrong answer is *detectable* here in a way that a wrong
remediation paragraph from the Adviser would not be.

Two layers of checking, and it is worth being precise about what each buys:

* :class:`AttackMap` rejects malformed IDs and untagged weaknesses. That is a
  **syntax** check. It catches ``T99`` and enforces §5.4's "every finding gets
  at least one technique", but it will happily accept ``T1763`` if no such
  technique exists.
* Confirming an ID is real needs the ``attack_validate`` MCP tool against the
  ATT&CK STIX bundle. That tool does not exist yet, so **hallucinated-but-well-
  formed technique IDs can still get through** — §9's model-hallucination risk
  is mitigated here, not closed. The gap is narrow and named rather than
  hidden.

The model is also constrained to the weakness IDs it was given: a mapping for a
weakness that was never in the register is dropped rather than passed on, since
downstream stages join on those IDs.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import ValidationError

from shared.llm import LlmClient, LlmError
from shared.models import AttackMap

from agent.services.workers.base import WorkContext, WorkFailed

log = logging.getLogger("agent.workers.mitre")

SYSTEM_PROMPT = """\
You map web application weaknesses to the MITRE ATT&CK for Enterprise framework.

For every weakness you are given, return one or more ATT&CK techniques.

Reply with ONLY a JSON object of this exact shape:
{"mappings": {"<weakness_id>": [{"technique_id": "T####",
                                 "technique_name": "<official name>",
                                 "tactic": "<ATT&CK tactic>"}]}}

Rules:
- technique_id must match ^T[0-9]{4}([.][0-9]{3})?$ (e.g. T1190, T1059.007).
- Use only techniques that genuinely exist in ATT&CK for Enterprise v15+.
- Every weakness ID you were given must appear as a key with at least one tag.
- Do not invent weakness IDs. Use exactly the IDs supplied.
- Prefer the most specific sub-technique that accurately fits.
"""


def _describe(weaknesses: list[dict[str, Any]]) -> str:
    """Render the register as compact prompt text.

    Only the fields that inform a technique choice are sent — an ID, what the
    weakness is, and where. Evidence blobs and request/response captures are
    deliberately withheld: they would multiply token cost, and they are the part
    of an engagement most likely to contain material that should not leave the
    deployment.
    """
    lines = []
    for weakness in weaknesses:
        wid = weakness.get("id") or weakness.get("weakness_id")
        if not wid:
            continue
        kind = weakness.get("kind") or weakness.get("title") or "unspecified weakness"
        where = weakness.get("page") or weakness.get("asset") or "unknown location"
        lines.append(f"{wid}: {kind} at {where}")
    return "\n".join(lines)


class MitreWorker:
    """LLM-backed ATT&CK mapping."""

    def __init__(self, llm: LlmClient) -> None:
        self._llm = llm

    async def __call__(self, ctx: WorkContext) -> dict[str, Any]:
        weaknesses = ctx.upstream.get("weaknesses") or []
        if not weaknesses:
            # Nothing upstream found anything. An empty map is the correct
            # artifact, and calling the model to confirm that would be waste.
            log.info("no weaknesses upstream; emitting empty ATT&CK map")
            return AttackMap().model_dump(mode="json")

        known_ids = {w.get("id") or w.get("weakness_id") for w in weaknesses}
        known_ids.discard(None)

        try:
            raw = await self._llm.complete_json(SYSTEM_PROMPT, _describe(weaknesses))
        except LlmError as exc:
            raise WorkFailed(f"ATT&CK mapping call failed: {exc}") from exc

        mappings = raw.get("mappings")
        if not isinstance(mappings, dict):
            raise WorkFailed(
                f"model returned no 'mappings' object (got keys: {sorted(raw)})")

        invented = sorted(set(mappings) - known_ids)
        if invented:
            log.warning("dropping mappings for unknown weakness ids: %s", invented)
            mappings = {k: v for k, v in mappings.items() if k in known_ids}

        missing = sorted(known_ids - set(mappings))
        if missing:
            raise WorkFailed(
                f"model left weaknesses untagged, which §5.4 forbids: "
                f"{', '.join(missing)}")

        try:
            artifact = AttackMap(mappings=mappings)
        except ValidationError as exc:
            raise WorkFailed(
                f"ATT&CK map failed schema validation: "
                f"{json.dumps(exc.errors()[:3], default=str)[:300]}") from exc

        log.info("tagged %d weaknesses with ATT&CK techniques", len(artifact.mappings))
        return artifact.model_dump(mode="json")
