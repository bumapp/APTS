"""ffuf — content/parameter fuzzing, as an MCP tool.

Finds the surface a crawler can't: UNLINKED paths and enumerable IDs (e.g. an
IDOR endpoint /api/note/FUZZ). The URL must contain the `FUZZ` keyword.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Any

_FFUF = "/usr/local/bin/ffuf"
# Named wordlists the agent chooses from — SecLists (curated subset baked into the
# image) plus two tiny built-ins. Pick by PURPOSE; or pass an absolute path.
_SL = "/opt/seclists/Discovery/Web-Content"
_WORDLISTS = {
    "common":     f"{_SL}/common.txt",                    # dir/file discovery (fast, ~4.7k)
    "big":        f"{_SL}/big.txt",                       # larger dir/file discovery (~20k)
    "raft-dirs":  f"{_SL}/raft-large-directories.txt",    # thorough directory discovery
    "raft-files": f"{_SL}/raft-large-files.txt",          # thorough file discovery
    "api":        f"{_SL}/api/api-endpoints.txt",         # API route names
    "params":     f"{_SL}/burp-parameter-names.txt",      # parameter names (FUZZ as a param)
    "lfi":        "/opt/seclists/Fuzzing/LFI/LFI-Jhaddix.txt",  # path traversal / LFI payloads
    "ids":        "/app/mcp_native/wordlists/ids.txt",    # numeric IDs (IDOR enumeration)
    "quick":      "/app/mcp_native/wordlists/common.txt", # tiny built-in list (fast lab checks)
}


async def ffuf(
    url: str,
    wordlist: str = "common",
    match_codes: str = "200,204,301,302,307,401,403,405",
    filter_size: str | None = None,
    method: str = "GET",
    data: str | None = None,
    recursion: bool = False,
    recursion_depth: int = 1,
    timeout_sec: int = 120,
    extra_flags: list[str] | None = None,
) -> dict[str, Any]:
    """Fuzz a target with ffuf. The URL (or data/header) must contain ``FUZZ``.

    Args:
        url: Target with a FUZZ keyword, e.g. "http://h/FUZZ" or "http://h/api/note/FUZZ".
        wordlist: which list to use — choose by PURPOSE:
            "common"/"big"/"raft-dirs"/"raft-files" = directory/file discovery;
            "api" = API route names; "params" = parameter-name fuzzing (FUZZ in a param);
            "lfi" = path-traversal/LFI payloads; "ids" = numeric IDs for IDOR enumeration;
            "quick" = tiny built-in list. Or pass an absolute path to a custom wordlist.
            (Lists are from SecLists, baked into the image.)
        match_codes: HTTP codes to treat as hits (ffuf -mc).
        filter_size: Optional response size to filter out (ffuf -fs), to drop a
            uniform "not found" page that still returns 200.
        method: HTTP method (default GET).
        data: Optional request body (for POST fuzzing; include FUZZ in it).
        timeout_sec: Hard wall-clock limit (default 120s).
        extra_flags: Any extra raw ffuf flags.
    """
    if "FUZZ" not in url and not (data and "FUZZ" in data):
        return {"error": "url (or data) must contain the FUZZ keyword"}
    wl = _WORDLISTS.get(wordlist, wordlist)
    if not os.path.exists(wl):
        return {"error": f"wordlist not found: {wl!r} (use 'paths', 'ids', or a valid path)"}
    out = "/tmp/ffuf_out.json"
    argv = [_FFUF, "-u", url, "-w", wl, "-mc", match_codes, "-ac", "-s",
            "-of", "json", "-o", out]
    if method and method.upper() != "GET":
        argv += ["-X", method.upper()]
    if data:
        argv += ["-d", data]
    if filter_size:
        argv += ["-fs", str(filter_size)]
    if recursion:  # walk discovered directories deeper (FUZZ must be at the path end)
        argv += ["-recursion", "-recursion-depth", str(int(recursion_depth))]
    if extra_flags:
        argv += [str(f) for f in extra_flags]
    env = {**os.environ, "HOME": "/tmp"}  # ffuf reads ~/.config/ffuf; service user has no home
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=env)
    except FileNotFoundError as exc:
        return {"error": f"ffuf not found: {exc}"}
    try:
        tail, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {"error": f"ffuf timed out after {timeout_sec}s", "timed_out": True,
                "command": " ".join(argv)}
    hits: list[dict] = []
    try:
        with open(out) as fh:
            data_json = json.load(fh)
        for r in data_json.get("results", []):
            hits.append({"input": (r.get("input") or {}).get("FUZZ"),
                         "url": r.get("url"), "status": r.get("status"),
                         "length": r.get("length"), "words": r.get("words")})
    except (OSError, ValueError):
        pass
    return {
        "command": " ".join(argv),
        "exit_code": proc.returncode,
        "wordlist": wl,
        "hits": hits,
        "count": len(hits),
        "guidance": (f"ffuf found {len(hits)} hit(s). Each is a reachable path/ID — "
                     f"treat unlinked ones (e.g. enumerable IDs) as access-control/"
                     f"IDOR candidates for the exploit stage."),
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Fuzz a target with ffuf to find UNLINKED paths and enumerable IDs that a "
        "crawler cannot see (e.g. an IDOR endpoint /api/note/FUZZ). The url (or data) "
        "MUST contain the FUZZ keyword. wordlist: 'paths' (default), 'ids' (numeric, "
        "for IDOR enumeration), or a custom path. Returns matching hits "
        "(input/url/status/length). Pair with katana/crawl (linked surface) and arjun "
        "(hidden params)."
    ))(ffuf)
    return ["ffuf"]
