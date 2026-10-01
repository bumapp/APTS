"""katana — crawl/endpoint enumeration via ProjectDiscovery's katana, as an MCP tool.

A fast crawler that parses JavaScript and follows endpoints; complements the
browser crawler for deep link/endpoint discovery. Bounded by depth + wall-clock.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

_KATANA = "/usr/local/bin/katana"


async def katana(
    url: str,
    depth: int = 2,
    js_crawl: bool = True,
    timeout_sec: int = 120,
    extra_flags: list[str] | None = None,
) -> dict[str, Any]:
    """Crawl a target with katana and return the endpoints it discovers.

    Args:
        url: Seed URL.
        depth: Crawl depth (default 2).
        js_crawl: Also parse JS for endpoints (katana -jc). Default true.
        timeout_sec: Hard wall-clock limit (default 120s).
        extra_flags: Any extra raw katana flags.
    """
    argv = [_KATANA, "-u", url, "-d", str(int(depth)), "-silent", "-nc"]
    if js_crawl:
        argv.append("-jc")
    if extra_flags:
        argv += [str(f) for f in extra_flags]
    # katana writes a config under $HOME/.config/katana; the service user has no
    # writable home, so point HOME at /tmp (verified: fixes the startup FTL).
    env = {**os.environ, "HOME": "/tmp"}
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=env)
    except FileNotFoundError as exc:
        return {"error": f"katana not found: {exc}"}
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {"error": f"katana timed out after {timeout_sec}s", "timed_out": True,
                "command": " ".join(argv)}
    text = out.decode(errors="replace")
    endpoints = sorted({ln.strip() for ln in text.splitlines()
                        if ln.strip().startswith("http")})
    return {
        "command": " ".join(argv),
        "exit_code": proc.returncode,
        "endpoints": endpoints,
        "count": len(endpoints),
        "guidance": (f"katana found {len(endpoints)} endpoint(s). Crawl any that look "
                     f"security-relevant, or fuzz for parameters/IDs on them."),
        "output_truncated": len(text) > 8000,
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Crawl a target with katana (ProjectDiscovery) — fast endpoint/URL "
        "enumeration that also parses JavaScript. Args: url, depth, js_crawl, "
        "extra_flags. Returns the list of discovered endpoints. Use it to enumerate "
        "the link/JS-reachable surface; pair with ffuf (unlinked paths/IDs) and "
        "arjun (hidden parameters)."
    ))(katana)
    return ["katana"]
