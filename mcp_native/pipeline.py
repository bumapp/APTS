"""Connect the two agentic loops into one run: Vulnerability -> Exploitation.

The vulnerability loop (``mcp_native.vuln_loop``) proposes hypotheses from the
recon batch and the HackTricks knowledge base; the exploitation loop
(``mcp_native.exploit_loop``) then tries to PROVE or DISPROVE each with its own
tools (sqlmap, http_request, get_recorded_request). They already speak the same
format — the vuln loop emits the exact ``## Suspected vulnerabilities`` block the
exploit loop parses — so this module just hands the first's output to the second
in-process, no file round-trip.

Run (mcp-native + llama services up):
    python -m mcp_native.pipeline

Each loop reads its own environment (APTS_VULN_* for the proposer, APTS_LOOP_*
for the prover), so scope/limits/timeouts are tuned independently. Set
APTS_PIPELINE_SKIP_EXPLOIT=1 to stop after proposing (same as running vuln_loop
alone). To prove hypotheses from an earlier run instead of generating fresh ones,
run the exploit loop directly on that run's markdown file.
"""
from __future__ import annotations

import asyncio
import os

from mcp_native import exploit_loop, vuln_loop


async def main() -> None:
    print("=" * 70)
    print("STAGE 1/2 — Vulnerability agent: propose hypotheses")
    print("=" * 70)
    report = await vuln_loop.main()

    if os.environ.get("APTS_PIPELINE_SKIP_EXPLOIT", "") in ("1", "true"):
        print("\nAPTS_PIPELINE_SKIP_EXPLOIT set — stopping after proposal.")
        return

    if "## Suspected vulnerabilities" not in report:
        print("\nNo hypotheses to exploit; stopping.")
        return

    print("\n" + "=" * 70)
    print("STAGE 2/2 — Exploitation agent: prove / disprove each hypothesis")
    print("=" * 70)
    # Hand the proposer's output straight to the prover — same format, no file.
    await exploit_loop.main(report)


if __name__ == "__main__":
    asyncio.run(main())
