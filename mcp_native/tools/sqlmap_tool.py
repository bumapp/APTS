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

    # Every hint below names a real argument of THIS tool (param, level, risk,
    # technique, enumerate, extra_flags) — not a raw sqlmap CLI flag — so the model
    # can act on it directly with its next call.
    if injectable:
        return (["CONFIRMED injectable — report VERDICT: PROVEN. For extra proof "
                 "detail you may call again with the `enumerate` argument set to "
                 "e.g. \"banner\" or \"current-db\"."],
                "Injection confirmed — conclude PROVEN.")

    # First thing to reconsider on a miss: was the right input tested?
    hints.append("Not injectable clears only the parameter(s) you tested — not the "
                 "endpoint. To test the others, either OMIT the `param` argument "
                 "(sqlmap then tests every parameter it finds) or set `param` to one "
                 "you have not tried yet. Also raise the `level` and `risk` arguments.")

    if "ignore-code" in o or "not authorized" in o or "forbidden" in o:
        hints.append("The target replied with an auth/deny code (e.g. 401/403) and "
                     "sqlmap stopped. Call again with "
                     "extra_flags=[\"--ignore-code=401\"] (use the code you saw).")
    if "increase values for '--level'" in o or "--risk" in o:
        hints.append("sqlmap wants more thoroughness — raise the `level` argument "
                     "(e.g. 3) and the `risk` argument (e.g. 2).")
    if ("without flag 't'" in o or "hasn't recovered" in o
            or "connection refused" in o or "continuous problem with connection" in o):
        hints.append("Time-based payloads destabilised the target. Set the "
                     "`technique` argument to \"BE\" (boolean + error only).")
    if "protection mechanism" in o or "tamper" in o or "waf" in o:
        hints.append("A WAF/filter may be blocking payloads. Try "
                     "extra_flags=[\"--random-agent\"], or a tamper script via "
                     "extra_flags=[\"--tamper=<name>\"].")

    m = re.search(r"500 \(internal server error\) - (\d+) times", o)
    if m and int(m.group(1)) > 0:
        hints.append(f"{m.group(1)}x HTTP 500 seen — the parameter likely reaches "
                     f"the SQL parser (promising). Adjust the arguments above and "
                     f"retry; do NOT conclude DISPROVEN yet.")

    guidance = ("sqlmap did NOT confirm injection. Change your ARGUMENTS per the "
                "hints (param / level / risk / technique / extra_flags) and call "
                "sqlmap again — never repeat the same arguments, and do not give up "
                "while a hint suggests something untried.")
    return hints, guidance

def _parse_proof(out: str) -> dict[str, Any]:
    """Pull the concrete proof out of a confirmed sqlmap run.

    On a hit sqlmap prints the injection point(s) with, per technique, the
    Type/Title and the exact winning Payload, plus the back-end DBMS and a short
    fingerprint. That is the real evidence — far more than 'injectable: true' —
    so we parse it into structured fields the loop can store."""
    points: list[dict] = []
    for m in re.finditer(
            r"Type:\s*(?P<type>[^\n]+)\n\s*Title:\s*(?P<title>[^\n]+)\n\s*"
            r"Payload:\s*(?P<payload>[^\n]+)", out):
        points.append({"type": m.group("type").strip(),
                       "title": m.group("title").strip(),
                       "payload": m.group("payload").strip()[:400]})
    pm = re.search(r"Parameter:\s*([^\n(]+)\(([^)]+)\)", out)
    dm = re.search(r"back-end DBMS:\s*([^\n]+)", out)
    fingerprint: dict[str, str] = {}
    for label, key in (("web server operating system", "os"),
                       ("web application technology", "tech")):
        fm = re.search(re.escape(label) + r":\s*([^\n]+)", out)
        if fm:
            fingerprint[key] = fm.group(1).strip()[:200]
    return {
        "parameter": pm.group(1).strip() if pm else None,
        "place": pm.group(2).strip() if pm else None,
        "dbms": dm.group(1).strip() if dm else None,
        "injection_points": points,
        "fingerprint": fingerprint,
    }


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
        data: POST body / parameters, as a form string 'a=1&b=2' or a JSON
            body '{"a":"1","b":"2"}'. sqlmap tests the params found here.
        cookie: Cookie header value, if the endpoint needs a session.
        headers: Extra request headers as a string->string map.
        param: Restrict testing to this one parameter name. OMIT it to let sqlmap
            test every parameter it finds (do this if you are unsure which is
            vulnerable); set it only when you already suspect one.
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
    # Clamp thoroughness. level/risk are the dominant request multipliers — level 5
    # (tests headers/cookies/referer + more boundaries) and risk 3 (heavy OR-based
    # payloads) can turn one call into tens of thousands of requests, which crashes
    # the fragile target and wastes the step budget on dead endpoints. Real bugs on
    # this surface prove at level 1-2 (login SQLi: level 2; search UNION: level 1),
    # so cap at level 3 / risk 2 — the agent can still escalate within that band.
    level = max(1, min(int(level), 3))
    risk = max(1, min(int(risk), 2))
    argv = [
        "python3", SQLMAP_PATH,
        "-u", url,
        "--batch",                 # never interactive
        "--disable-coloring",      # clean, parseable output
        "--output-dir", OUTPUT_DIR,
        "--level", str(level),
        "--risk", str(risk),
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
    proof = _parse_proof(out) if injectable else {}
    if injectable and proof.get("injection_points"):
        guidance = (f"Injection confirmed on parameter {proof.get('parameter')!r} "
                    f"({len(proof['injection_points'])} technique(s), DBMS "
                    f"{proof.get('dbms') or 'unknown'}) — conclude PROVEN and cite the "
                    f"payload(s). For more proof you may re-run enumerate='banner' or "
                    f"'current-db'.")

    return {
        "command": " ".join(argv),
        "exit_code": proc.returncode,
        "injectable": injectable,
        # Structured proof first, so it survives evidence truncation downstream:
        # the confirmed parameter, the winning payload(s)/technique(s), DBMS, and
        # sqlmap's fingerprint of the stack.
        "parameter": proof.get("parameter"),
        "dbms": proof.get("dbms"),
        "injection_points": proof.get("injection_points", []),
        "fingerprint": proof.get("fingerprint", {}),
        # A mini-prompt + parsed hints so the model adapts its NEXT call instead
        # of accepting the first "not injectable" as final.
        "guidance": guidance,
        "hints": hints,
        # The model can still read the tail for anything not parsed above.
        "output_tail": out[-_OUTPUT_TAIL:],
        "output_truncated": len(out) > _OUTPUT_TAIL,
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "Run sqlmap to PROVE or DISPROVE SQL injection on a specific request. "
        "Arguments: url, method, data (POST body), param (one parameter to test, or "
        "omit to test all), level/risk/technique (how hard to try), extra_flags (any "
        "other sqlmap flag), enumerate (after a hit). Returns 'injectable' plus STRUCTURED "
        "PROOF on a hit: the confirmed parameter, the winning payload(s) and "
        "technique(s) (injection_points), the back-end DBMS, and a stack "
        "fingerprint — cite these as evidence. This is the correct tool for SQLi. "
        "Start at level 1 (omit param to test all inputs, or set it if you suspect "
        "one); raise level/risk, switch technique, or enumerate (banner/dbs/dump) "
        "only after a hit or when a returned hint tells you to."
    ))(sqlmap)
    return ["sqlmap"]
