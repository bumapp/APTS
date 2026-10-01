"""arjun — hidden HTTP parameter discovery, as an MCP tool.

Finds query/body parameters an endpoint accepts but doesn't advertise — exactly
the injection points (e.g. ``q``, ``url``, ``id``) the vuln/exploit stages need.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

_ARJUN = "arjun"


async def arjun(
    url: str,
    method: str = "GET",
    timeout_sec: int = 180,
    extra_flags: list[str] | None = None,
) -> dict[str, Any]:
    """Discover hidden parameters an endpoint accepts.

    Args:
        url: The endpoint to probe, e.g. "http://h/search".
        method: GET, POST, or JSON (arjun -m). Default GET.
        timeout_sec: Hard wall-clock limit (default 180s).
        extra_flags: Any extra raw arjun flags.
    """
    out = "/tmp/arjun_out.json"
    try:
        os.remove(out)
    except OSError:
        pass
    # -q quiets the per-chunk progress spam; -oJ writes structured results.
    argv = [_ARJUN, "-u", url, "-m", method.upper(), "-q", "-oJ", out]
    if extra_flags:
        argv += [str(f) for f in extra_flags]
    env = {**os.environ, "HOME": "/tmp"}
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=env)
    except FileNotFoundError as exc:
        return {"error": f"arjun not found: {exc}"}
    try:
        tail, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {"error": f"arjun timed out after {timeout_sec}s", "timed_out": True,
                "command": " ".join(argv)}
    text = tail.decode(errors="replace")
    params: list[str] = []
    # Prefer the JSON output; fall back to parsing the "Parameters found" line.
    try:
        with open(out) as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, dict) and isinstance(v.get("params"), list):
                    params += [str(p) for p in v["params"]]
                elif isinstance(v, list):
                    params += [str(p) for p in v]
    except (OSError, ValueError):
        pass
    if not params:
        for ln in text.splitlines():
            if "Parameters found" in ln:
                params += [p.strip() for p in ln.split(":", 1)[-1].split(",") if p.strip()]
    params = sorted(set(params))
    return {
        "command": " ".join(argv),
        "exit_code": proc.returncode,
        "parameters": params,
        "count": len(params),
        "guidance": (f"arjun found {len(params)} parameter(s): {', '.join(params) or 'none'}. "
                     f"These are inputs the endpoint accepts — hand them to the vuln/exploit "
                     f"stage as injection candidates."),
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Discover HIDDEN HTTP parameters an endpoint accepts but doesn't advertise "
        "(e.g. q, url, id, file) using arjun. Args: url, method (GET/POST/JSON). "
        "Returns the parameter names found — the concrete injection points the vuln/"
        "exploit stages test. Pair with crawl/katana (endpoints) and ffuf (unlinked paths)."
    ))(arjun)
    return ["arjun"]
