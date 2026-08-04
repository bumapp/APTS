"""Extract API paths from JavaScript bundles.

A single-page app serves an HTML shell with no links and no forms — the entire
attack surface is constructed at runtime by JavaScript. A static crawler sees
one page and reports it, which is technically accurate and practically useless.

But the API paths that app calls are *string literals in the bundle*. Pulling
them out is standard practice when mapping an SPA by hand, and it is
deterministic — a regex over shipped source, not a guess. That matters: an
endpoint invented here would be tested by the next stage and reported to the
client as a real part of their application.

This finds candidate paths, not confirmed endpoints. Something in the bundle
looked like an API route; whether it responds is for a later probe to say.
"""
from __future__ import annotations

import re

# Quoted string literals that look like absolute API paths. Anchored on a
# leading slash and a known API-ish prefix rather than matching every quoted
# slash-string, which on a minified bundle returns mostly CSS selectors and
# i18n keys.
_API_PATH = re.compile(
    r"""['"`](/(?:rest|api|v\d+|graphql|admin|auth|oauth|users?|account|"""
    r"""session|login|logout|register|search|upload|download|file|report)"""
    r"""[a-zA-Z0-9._~\-/]*)['"`]""",
    re.IGNORECASE,
)

# Template placeholders (`/api/users/${id}`, `/api/users/:id`) normalise to a
# single form so one route does not appear as a dozen distinct endpoints.
_PLACEHOLDER = re.compile(r"\$\{[^}]*\}|:[a-zA-Z_][a-zA-Z0-9_]*")

# Paths that are almost never API routes, however they are spelled.
_NOISE_SUFFIXES = (".js", ".css", ".map", ".png", ".jpg", ".svg", ".woff",
                   ".woff2", ".ico", ".html", ".json.gz")


def extract_api_paths(source: str, limit: int = 200) -> list[str]:
    """Return candidate API paths found in ``source``, deduplicated and sorted.

    ``limit`` bounds the result: a large bundle can yield hundreds of matches,
    and an unbounded list would flow straight into an agent's context window.
    """
    found: set[str] = set()
    for match in _API_PATH.finditer(source or ""):
        path = _PLACEHOLDER.sub("{param}", match.group(1))
        path = path.rstrip("/") or "/"
        if path.lower().endswith(_NOISE_SUFFIXES):
            continue
        if len(path) > 200:
            continue
        found.add(path)
        if len(found) >= limit:
            break
    return sorted(found)
