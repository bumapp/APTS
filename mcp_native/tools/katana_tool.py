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
    jsluice: bool = False,
    headless: bool = False,
    xhr: bool = False,
    known_files: bool = False,
    timeout_sec: int = 150,
    extra_flags: list[str] | None = None,
) -> dict[str, Any]:
    """Crawl a target with katana and return the endpoints it discovers.

    The default (``-jc``) is katana's STATIC crawler + JS endpoint parsing — fast,
    but it does not execute the app, so a JavaScript SPA's client routes and the
    XHR/fetch calls it fires at runtime stay invisible. Turn on ``headless`` for
    those targets. The deep-discovery modes:

    Args:
        url: Seed URL.
        depth: Crawl depth (default 2; raise to 3 for a thorough sweep).
        js_crawl: Parse JS files for endpoints (katana -jc). Default true.
        jsluice: AST-based JS endpoint extraction (-jsl) — pulls endpoints out of
            minified bundles that the regex -jc parser misses. Cheap, static.
        headless: Render the page in a real headless browser (-headless,
            EXPERIMENTAL) — executes the app so client-rendered routes appear.
            Use for JS SPAs (React/Angular/Vue). Slower; needs more depth time.
        xhr: Extract the XHR/fetch calls the app makes at runtime (-xhr), each with
            its method — captures the /rest, /api calls a static crawl never sees.
            Requires (and auto-enables) ``headless``.
        known_files: Fetch robots.txt + sitemap.xml (-kf all). Cheap; always safe.
        timeout_sec: Hard wall-clock limit (default 150s; raise for headless+depth).
        extra_flags: Any extra raw katana flags.
    """
    argv = [_KATANA, "-u", url, "-d", str(int(depth)), "-silent", "-nc"]
    if js_crawl:
        argv.append("-jc")
    if jsluice:
        argv.append("-jsl")
    if known_files:
        argv += ["-kf", "all"]
    if xhr:
        headless = True  # xhr extraction is only available under the headless engine
    if headless:
        # Headless renders JS like a browser (what a SPA needs). As root inside a
        # container, Chrome crashes on launch without --no-sandbox — katana reports
        # it as "context deadline exceeded <- could not get dom" and silently falls
        # back to junk, so -nos is MANDATORY here, not optional. (-ho passes extra
        # Chrome flags.) katana uses its own downloaded Chrome, cached under $HOME.
        # katana's headless engine uses its OWN go-rod Chrome (pointing it at another
        # Chromium via -system-chrome-path does not work — it yields nothing). The image
        # pre-downloads that Chrome at build time (see Dockerfile) so this needs no
        # runtime download; -nos is required for root-in-container.
        argv += ["-headless", "-nos", "-ho", "disable-dev-shm-usage"]
        if xhr:
            argv.append("-xhr")
    if extra_flags:
        argv += [str(f) for f in extra_flags]
    # Write results to a file as they are found (-o). A deep headless sweep can run
    # long; if we hit the wall-clock limit we still SALVAGE whatever katana wrote so
    # far rather than discarding it — a partial deep map beats an error.
    import tempfile
    out_file = tempfile.mktemp(prefix="katana_", suffix=".txt")
    argv += ["-o", out_file]
    # katana writes a config under $HOME/.config/katana; the service user has no
    # writable home, so point HOME at /tmp (verified: fixes the startup FTL).
    env = {**os.environ, "HOME": "/tmp"}
    timed_out = False
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            env=env)
    except FileNotFoundError as exc:
        return {"error": f"katana not found: {exc}"}
    try:
        await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        await proc.wait()
    endpoints: list[str] = []
    try:
        with open(out_file) as fh:
            endpoints = sorted({ln.strip() for ln in fh if ln.strip().startswith("http")})
    except OSError:
        pass
    finally:
        try:
            os.remove(out_file)
        except OSError:
            pass
    # Only a timeout with NOTHING salvaged is an error; a partial map is usable.
    if timed_out and not endpoints:
        return {"error": f"katana timed out after {timeout_sec}s with no results",
                "timed_out": True, "command": " ".join(argv)}
    return {
        "command": " ".join(argv),
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        "endpoints": endpoints,
        "count": len(endpoints),
        "guidance": (f"katana found {len(endpoints)} endpoint(s)"
                     f"{' (partial — timed out)' if timed_out else ''}. Crawl any that look "
                     f"security-relevant, or fuzz for parameters/IDs on them."),
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Crawl a target with katana (ProjectDiscovery) for endpoint/URL enumeration. "
        "Args: url, depth, js_crawl (parse JS, default on), jsluice (deeper AST-based "
        "JS endpoint extraction), headless (render in a real browser — REQUIRED for a "
        "JavaScript SPA like React/Angular/Vue, or a static crawl misses its client "
        "routes), xhr (capture the runtime /rest, /api calls the app fires; implies "
        "headless), known_files (robots.txt + sitemap.xml). For a JS app use "
        "headless=true, xhr=true, jsluice=true; for a plain server-rendered site the "
        "default is fine. Returns the discovered endpoints. Pair with ffuf (unlinked "
        "paths/IDs) and arjun (hidden parameters)."
    ))(katana)
    return ["katana"]
