"""sqlmap — drive sqlmap against a target to prove/disprove SQL injection.

Wraps the sqlmap CLI (the user's checkout, mounted into the container at
APTS_SQLMAP_PATH). The model chooses the target and the interesting knobs —
which parameter, how hard to try, which techniques, what to enumerate — and gets
back sqlmap's verdict plus the tail of its output.

Two things are enforced no matter what the model asks:

* ``--batch`` is always added. Without it sqlmap stops to ask interactive
  questions and the tool would hang forever.
* A wall-clock timeout kills a run that overruns, so one probe cannot stall the
  whole exploit loop. sqlmap is also told to write its session/output under
  ``/tmp`` so a read-only code mount does not break it.

Everything is passed as an argv list to exec (never a shell), so a value the
model supplies cannot break out into shell command injection. ``extra_flags`` is
an escape hatch for any sqlmap option not surfaced as a typed argument — "all
the flags the AI can use" without enumerating the hundreds sqlmap has.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from typing import Any

SQLMAP_PATH = os.environ.get("APTS_SQLMAP_PATH", "/opt/sqlmap/sqlmap.py")
OUTPUT_DIR = os.environ.get("APTS_SQLMAP_OUTPUT_DIR", "/tmp/sqlmap-out")
_OUTPUT_TAIL = 6000

# What sqlmap prints when it has (not) found something — used for a quick verdict
# on top of the raw output the model also gets to read.
_INJECTABLE = re.compile(
    r"is vulnerable|appears to be injectable|the following injection point|"
    r"identified the following injection", re.IGNORECASE)
_NOT_INJECTABLE = re.compile(
    r"all tested parameters do not appear to be injectable|"
    r"might not be injectable", re.IGNORECASE)


def _extract_hints(output: str, injectable: bool) -> tuple[list[str], str]:
    """Turn sqlmap's own advice into actionable hints for the next call.

    sqlmap is verbose about *why* it stopped and what to try next; a model
    rarely reads 6 KB of log carefully, so we mine the well-known signals and
    hand back a short list plus a one-line 'do this next' guidance. Generic to
    sqlmap, not to any one target — every signal below is a stock sqlmap message.
    """
    o = output.lower()
    hints: list[str] = []

    if injectable:
        return (["CONFIRMED injectable. Stop testing this parameter and report "
                 "VERDICT: PROVEN. To gather proof detail you may re-run with the "
                 "'enumerate' argument (e.g. 'current-db', 'banner')."],
                "Injection confirmed — conclude PROVEN.")

    if "ignore-code" in o or "not authorized" in o or "forbidden" in o:
        hints.append("The target answered with an auth/deny code (e.g. 401/403) "
                     "and sqlmap refused to continue. Re-run with "
                     "extra_flags=[\"--ignore-code=401\"] (use the code you saw).")
    if "increase values for '--level'" in o or "--risk" in o:
        hints.append("sqlmap asked for more thoroughness. Re-run with a higher "
                     "level (e.g. level=3) and risk (e.g. risk=2).")
    if ("without flag 't'" in o or "hasn't recovered" in o
            or "connection refused" in o or "continuous problem with connection" in o):
        hints.append("Time-based payloads destabilised the target. Re-run with "
                     "technique=\"BE\" (boolean+error only, no time-based).")
    if "protection mechanism" in o or "tamper" in o or "waf" in o:
        hints.append("A WAF/protection may be filtering payloads. Try "
                     "extra_flags=[\"--random-agent\"] or a --tamper script.")

    m = re.search(r"500 \(internal server error\) - (\d+) times", o)
    if m and int(m.group(1)) > 0:
        hints.append(f"{m.group(1)}x HTTP 500 seen — the parameter probably "
                     f"reaches the SQL parser (promising). Adjust flags per the "
                     f"hints above and retry; do NOT conclude DISPROVEN yet.")

    if not hints:
        hints.append("No injection and no specific sqlmap hint. Consider a higher "
                     "level/risk, a different technique, or another parameter; "
                     "otherwise conclude DISPROVEN.")

    guidance = ("sqlmap did NOT confirm injection. Read the hints, change your "
                "arguments accordingly (flags/level/risk/technique), and call "
                "sqlmap again — do not repeat the same arguments, and do not give "
                "up while a hint suggests something untried.")
    return hints, guidance

# enumerate keyword -> sqlmap flag(s). A small curated set; anything else goes
# through extra_flags.
_ENUMERATE = {
    "banner": ["--banner"],
    "current-user": ["--current-user"],
    "current-db": ["--current-db"],
    "is-dba": ["--is-dba"],
    "users": ["--users"],
    "passwords": ["--passwords"],
    "dbs": ["--dbs"],
    "tables": ["--tables"],
    "columns": ["--columns"],
    "dump": ["--dump"],
}


async def sqlmap(
    url: str,
    method: str = "GET",
    data: str | dict | None = None,
    cookie: str | None = None,
    headers: dict[str, str] | None = None,
    param: str | None = None,
    level: int = 1,
    risk: int = 1,
    technique: str | None = None,
    dbms: str | None = None,
    enumerate: str | None = None,
    extra_flags: list[str] | None = None,
    timeout_sec: int = 180,
) -> dict[str, Any]:
    """Run sqlmap against one target and report whether it is SQL-injectable.

    Args:
        url: Target URL. For GET, put params in the query string; for POST, pass
            them in ``data``.
        method: HTTP method (GET or POST typically).
        data: POST body / parameters, e.g. '{"email":"x","password":"y"}' or
            'email=x&password=y'. sqlmap tests the params found here.
        cookie: Cookie header value, if the endpoint needs a session.
        headers: Extra request headers as a string->string map.
        param: Restrict testing to this parameter name (sqlmap -p). Strongly
            recommended when you already suspect one param.
        level: 1-5, how thorough (more places tested). Default 1.
        risk: 1-3, how risky the payloads may be. Default 1.
        technique: Restrict techniques, a subset of letters "BEUSTQ"
            (Boolean, Error, Union, Stacked, Time, inline Query). Optional.
        dbms: Hint the backend, e.g. "sqlite", "mysql", "postgresql". Optional.
        enumerate: One of banner, current-user, current-db, is-dba, users,
            passwords, dbs, tables, columns, dump — only useful AFTER a param is
            confirmed injectable. Optional.
        extra_flags: Any other raw sqlmap flags, as a list, e.g.
            ["--dbms-cred", "--no-cast"]. The escape hatch for full control.
        timeout_sec: Hard wall-clock limit for this run (default 180s).
    """
    argv = [
        "python3", SQLMAP_PATH,
        "-u", url,
        "--batch",                 # never interactive
        "--disable-coloring",      # clean, parseable output
        "--output-dir", OUTPUT_DIR,
        "--level", str(int(level)),
        "--risk", str(int(risk)),
    ]
    if method and method.upper() != "GET":
        argv += ["--method", method.upper()]
    if data:
        # A JSON body is often delivered as a dict (the MCP transport parses a
        # JSON-string argument), so normalise back to the raw string sqlmap wants.
        argv += ["--data", json.dumps(data) if isinstance(data, dict) else str(data)]
    if cookie:
        argv += ["--cookie", cookie]
    for key, value in (headers or {}).items():
        argv += ["-H", f"{key}: {value}"]
    if param:
        argv += ["-p", param]
    if technique:
        argv += ["--technique", technique.upper()]
    if dbms:
        argv += ["--dbms", dbms]
    if enumerate:
        argv += _ENUMERATE.get(enumerate.strip().lower(), [])
    if extra_flags:
        argv += [str(f) for f in extra_flags]

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError as exc:
        return {"error": f"sqlmap not found at {SQLMAP_PATH!r}: {exc}"}

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return {"error": f"sqlmap timed out after {timeout_sec}s",
                "command": " ".join(argv), "timed_out": True}

    out = stdout.decode(errors="replace")
    injectable = bool(_INJECTABLE.search(out)) and not _NOT_INJECTABLE.search(out)
    hints, guidance = _extract_hints(out, injectable)

    return {
        "command": " ".join(argv),
        "exit_code": proc.returncode,
        "injectable": injectable,
        # A mini-prompt + parsed hints so the model adapts its NEXT call instead
        # of accepting the first "not injectable" as final.
        "guidance": guidance,
        "hints": hints,
        # The model reads the tail: sqlmap prints its verdict, the injection
        # points, the payloads, and the DBMS near the end.
        "output_tail": out[-_OUTPUT_TAIL:],
        "output_truncated": len(out) > _OUTPUT_TAIL,
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Run sqlmap to PROVE or DISPROVE SQL injection on a specific request. "
        "You pick the URL, method, POST data, the parameter to test (-p), and how "
        "hard to try (level/risk/technique). Returns sqlmap's verdict "
        "('injectable': true/false) plus the tail of its output showing the "
        "injection point, payloads, and backend DBMS. Start with just the "
        "suspected parameter at level 1; only raise level/risk or enumerate "
        "(dbs/tables/dump) after a parameter is confirmed injectable."
    ))(sqlmap)
    return ["sqlmap"]
