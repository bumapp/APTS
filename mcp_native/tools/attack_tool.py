"""attack — a callable MITRE ATT&CK for Enterprise technique reference.

Three tools over a bundled technique catalogue
(``corpus/attack/techniques.json`` — a curated subset covering what a
web-application weakness plausibly maps to, not the whole matrix):

    * attack_catalog   — the menu: id + name + tactics for every technique,
      so the model picks from a real list instead of reciting an id from memory.
    * attack_search    — keyword search over names, keywords and descriptions;
      returns candidate techniques ranked by match.
    * attack_technique — look up ONE id. Validates it against the catalogue and
      returns the official name, tactics, description and url. On a miss it
      returns the nearest real ids (and, for a bad sub-technique, the parent and
      its real children) so the model corrects itself instead of inventing one.

This is the ``attack_validate`` capability the MITRE mapping stage's docstring
anticipated: with it, the mapping loop can only emit ids a tool confirmed.

The corpus directory is ``APTS_ATTACK_DIR`` (default ``/opt/attack`` in the
mcp-native container; falls back to the in-repo copy for host runs).
"""
from __future__ import annotations

import json
import os
import re
from difflib import get_close_matches
from functools import lru_cache
from pathlib import Path
from typing import Any

# In the container the corpus is mounted read-only at /opt/attack; on a host run
# (no mount) fall back to the copy that ships in the repo next to this file.
_REPO_COPY = Path(__file__).resolve().parents[1] / "corpus" / "attack"
CORPUS_DIR = Path(os.environ.get("APTS_ATTACK_DIR", str(_REPO_COPY)))

_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_SEARCH_LIMIT = int(os.environ.get("APTS_ATTACK_SEARCH_LIMIT", "8"))


@lru_cache(maxsize=1)
def _catalog() -> dict[str, Any]:
    """Load and cache techniques.json (also keyed by id for O(1) lookup)."""
    with open(CORPUS_DIR / "techniques.json", encoding="utf-8") as fh:
        data = json.load(fh)
    techniques = data.get("techniques", [])
    return {"raw": data, "by_id": {t["id"]: t for t in techniques},
            "techniques": techniques}


def _public(t: dict[str, Any]) -> dict[str, Any]:
    """The fields a caller gets back for one technique (keywords stay internal)."""
    return {"technique_id": t["id"], "name": t["name"],
            "tactics": t.get("tactics", []), "url": t.get("url", ""),
            "description": t.get("description", "")}


def attack_catalog() -> dict[str, Any]:
    """List every ATT&CK technique available to map to, as id + name + tactics.

    This is the technique menu. Scan it to see what exists, then confirm a
    specific id with ``attack_technique`` or find candidates with
    ``attack_search``. Ids not listed here cannot be validated.
    """
    try:
        cat = _catalog()
    except (OSError, ValueError) as exc:
        return {"error": f"could not load ATT&CK corpus: {exc}",
                "corpus_dir": str(CORPUS_DIR)}
    techniques = [{"technique_id": t["id"], "name": t["name"],
                   "tactics": t.get("tactics", [])}
                  for t in cat["techniques"]]
    return {
        "count": len(techniques),
        "version": cat["raw"].get("version", ""),
        "techniques": techniques,
        "guidance": (
            "Pick the technique(s) that describe how this weakness would be "
            "used in an intrusion. Confirm each id with attack_technique before "
            "you rely on it. This subset is curated for web-app findings; if "
            "nothing fits well, choose the closest listed technique."),
    }


def attack_search(query: str) -> dict[str, Any]:
    """Find ATT&CK techniques matching a free-text query.

    Args:
        query: What the weakness is or does, e.g. "sql injection",
            "steal session cookie via xss", "no rate limiting on login".

    Returns up to a handful of candidate techniques ranked by how well they
    match, each with its official name, tactics and description. Confirm the one
    you choose with ``attack_technique``.
    """
    try:
        cat = _catalog()
    except (OSError, ValueError) as exc:
        return {"error": f"could not load ATT&CK corpus: {exc}",
                "corpus_dir": str(CORPUS_DIR)}

    q = (query or "").strip().lower()
    if not q:
        return {"query": query, "count": 0, "matches": [],
                "guidance": "Pass a short description of the weakness to search."}
    terms = [w for w in re.split(r"[^a-z0-9]+", q) if len(w) > 2]

    scored: list[tuple[int, dict[str, Any]]] = []
    for t in cat["techniques"]:
        hay = " ".join([
            t["name"].lower(), " ".join(t.get("tactics", [])).lower(),
            " ".join(t.get("keywords", [])).lower(),
            t.get("description", "").lower(),
        ])
        score = 0
        for kw in t.get("keywords", []):
            if kw in q or q in kw:
                score += 5
        score += sum(3 for term in terms if term in t["name"].lower())
        score += sum(1 for term in terms if term in hay)
        if score:
            scored.append((score, t))

    scored.sort(key=lambda s: s[0], reverse=True)
    matches = [_public(t) for _, t in scored[:_SEARCH_LIMIT]]
    result = {"query": query, "count": len(matches), "matches": matches}
    if not matches:
        result["guidance"] = (
            "No technique matched. Try broader words (the vulnerability class, "
            "or the attacker's goal), or scan attack_catalog and pick the "
            "closest fit.")
    else:
        result["guidance"] = (
            "These are candidates, not confirmed choices. Pass the id you want "
            "to attack_technique to validate it and get the authoritative name "
            "and tactic.")
    return result


def attack_technique(technique_id: str) -> dict[str, Any]:
    """Validate one ATT&CK technique id and return its official details.

    Args:
        technique_id: An ATT&CK Enterprise id, e.g. "T1190" or "T1059.007".

    On success returns ``found: true`` with the official name, tactics,
    description and url — use those exact values, do not paraphrase the name.
    On an unknown id returns ``found: false`` with the nearest real ids so you
    can correct the choice rather than invent one.
    """
    try:
        cat = _catalog()
    except (OSError, ValueError) as exc:
        return {"error": f"could not load ATT&CK corpus: {exc}",
                "corpus_dir": str(CORPUS_DIR)}

    tid = (technique_id or "").strip().upper()
    if not _ID_RE.match(tid):
        return {"technique_id": technique_id, "found": False,
                "reason": "not a well-formed ATT&CK id",
                "guidance": ("An id looks like T1190 or T1059.007 "
                             "(T + 4 digits, optional .NNN sub-technique). "
                             "Use attack_search to find the right one.")}

    hit = cat["by_id"].get(tid)
    if hit is not None:
        return {"found": True, **_public(hit),
                "guidance": ("Confirmed. Use this technique_id, name and the "
                             "single most relevant tactic verbatim in your "
                             "mapping.")}

    # Miss. For a bad sub-technique, surface the parent and its real children;
    # otherwise the closest ids by string similarity.
    base = tid.split(".", 1)[0]
    family = sorted(i for i in cat["by_id"] if i == base or i.startswith(base + "."))
    near = family or get_close_matches(tid, list(cat["by_id"]), n=6, cutoff=0.3)
    return {
        "technique_id": tid, "found": False,
        "did_you_mean": [{"technique_id": i, "name": cat["by_id"][i]["name"]}
                         for i in near],
        "guidance": ("That id is not in the catalogue. Do NOT use it. Pick one "
                     "from did_you_mean, or run attack_search again with a "
                     "description of the weakness."),
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "List every MITRE ATT&CK (Enterprise) technique available to map a "
        "weakness to — id, name and tactics. The technique menu; scan it, then "
        "confirm a choice with attack_technique."
    ))(attack_catalog)
    mcp.tool(description=(
        "Search MITRE ATT&CK techniques by free text (the vulnerability class or "
        "the attacker's goal). Returns ranked candidate techniques with their "
        "official names, tactics and descriptions. Validate your pick with "
        "attack_technique."
    ))(attack_search)
    mcp.tool(description=(
        "Validate one ATT&CK technique id (e.g. T1190, T1059.007) and return its "
        "official name, tactics, description and url. On an unknown id it returns "
        "the nearest real ids instead of failing."
    ))(attack_technique)
    return ["attack_catalog", "attack_search", "attack_technique"]
