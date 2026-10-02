"""hacktricks — a callable HackTricks web-pentest knowledge base.

Two tools over a local corpus (an ``index.json`` catalogue, an ``overview.md``
methodology page, and one markdown article per technique under ``articles/``):

    * hacktricks_overview  — the technique menu: every article's slug + title,
      so the model chooses from a real, valid list instead of guessing names.
    * hacktricks_article   — fetch one technique's markdown (worked examples,
      payloads) by its slug, to inform a concrete hypothesis.

The corpus directory is ``APTS_HACKTRICKS_DIR`` (default ``/opt/hacktricks`` in
the mcp-native container; falls back to the in-repo copy for host runs).
"""
from __future__ import annotations

import json
import os
from difflib import get_close_matches
from functools import lru_cache
from pathlib import Path
from typing import Any

# In the container the corpus is mounted read-only at /opt/hacktricks; on a host
# run (no mount) fall back to the copy that ships in the repo next to this file.
_REPO_COPY = Path(__file__).resolve().parents[1] / "corpus" / "hacktricks"
CORPUS_DIR = Path(os.environ.get("APTS_HACKTRICKS_DIR", str(_REPO_COPY)))

_ARTICLE_CHAR_CAP = int(os.environ.get("APTS_HACKTRICKS_ARTICLE_CHARS", "7000"))


@lru_cache(maxsize=1)
def _index() -> dict[str, Any]:
    """Load and cache index.json (slug -> article metadata)."""
    with open(CORPUS_DIR / "index.json", encoding="utf-8") as fh:
        data = json.load(fh)
    by_slug = {a["slug"]: a for a in data.get("articles", [])}
    return {"raw": data, "by_slug": by_slug}


def hacktricks_overview() -> dict[str, Any]:
    """List every HackTricks web-pentest technique available to fetch.

    Returns the technique menu — each entry is a ``slug`` (the exact key to pass
    to ``hacktricks_article``) and a human ``title``. Scan this to decide which
    techniques are worth testing against a given request, then pull the ones you
    want with ``hacktricks_article(slug)``.
    """
    try:
        idx = _index()
    except (OSError, ValueError) as exc:
        return {"error": f"could not load HackTricks corpus: {exc}",
                "corpus_dir": str(CORPUS_DIR)}
    techniques = [{"slug": a["slug"], "title": a.get("title", a["slug"]),
                   "chars": a.get("chars", 0)}
                  for a in idx["raw"].get("articles", [])]
    return {
        "count": len(techniques),
        "techniques": techniques,
        "guidance": (
            "Pick the techniques that plausibly apply to the request under test. "
            "For each, call hacktricks_article(slug) to read worked examples and "
            "payloads before writing a hypothesis. The slug must be one listed "
            "here verbatim."),
    }


def hacktricks_article(slug: str) -> dict[str, Any]:
    """Fetch one HackTricks technique article (examples, payloads) by slug.

    Args:
        slug: The technique slug, exactly as listed by hacktricks_overview,
            e.g. "sql-injection", "xss-cross-site-scripting", "command-injection".
    """
    try:
        idx = _index()
    except (OSError, ValueError) as exc:
        return {"error": f"could not load HackTricks corpus: {exc}",
                "corpus_dir": str(CORPUS_DIR)}

    key = (slug or "").strip().lower()
    meta = idx["by_slug"].get(key)
    if meta is None:
        # Miss: hand back the nearest real slugs so the model corrects itself
        # instead of inventing a technique name.
        near = get_close_matches(key, list(idx["by_slug"]), n=8, cutoff=0.3)
        return {
            "slug": key, "found": False,
            "did_you_mean": near,
            "guidance": (
                "No article by that slug. Do NOT invent one. Pick the closest "
                "match from did_you_mean (or from hacktricks_overview) and call "
                "hacktricks_article again. If nothing fits, write your hypothesis "
                "from first principles without an example."),
        }

    path = CORPUS_DIR / meta["file"]
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"slug": key, "found": False,
                "error": f"article file unreadable: {exc}"}

    truncated = len(text) > _ARTICLE_CHAR_CAP
    return {
        "slug": key,
        "found": True,
        "title": meta.get("title", key),
        "content": text[:_ARTICLE_CHAR_CAP],
        "truncated": truncated,
        "total_chars": len(text),
        "guidance": ("Use these examples to shape a concrete, testable hypothesis "
                     "for the specific parameter/endpoint under test."
                     + (" Article truncated — the head usually carries the core "
                        "technique and payloads." if truncated else "")),
    }


def register(mcp) -> list[str]:
    mcp.tool(description=(
        "List every HackTricks web-pentest technique available, as slug + title. "
        "This is the technique menu: scan it to decide what is worth testing "
        "against a request, then fetch specific ones with hacktricks_article."
    ))(hacktricks_overview)
    mcp.tool(description=(
        "Fetch one HackTricks technique article by its slug (from "
        "hacktricks_overview) — worked examples and payloads for that class of "
        "bug. On an unknown slug it returns the nearest real slugs instead."
    ))(hacktricks_article)
    return ["hacktricks_overview", "hacktricks_article"]
