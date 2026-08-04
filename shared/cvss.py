"""CVSS v3.1 base score calculation.

Deliberately implemented rather than pulled from a package. Not to avoid the
dependency — though that is a bonus — but because of *where* this sits: a
severity number is the single most consequential figure in the final report,
and it must be arithmetic on a vector string, never something a language model
produced.

That distinction is the whole point. A model is good at judging that a login
form taking unescaped input is network-reachable, needs no privileges, and
compromises confidentiality — that is the vector. It is not reliable at
converting those judgements into 8.8, and a plausible-looking wrong number
propagates into the remediation priority matrix and out to the client. So the
model proposes ``CVSS:3.1/AV:N/AC:L/...`` and this module computes the score.

Formula per the FIRST CVSS v3.1 specification, section 7.1. The Environmental
and Temporal metric groups are not implemented — v1.0 reports base scores only
(PRD §5.3).
"""
from __future__ import annotations

import math
import re

__all__ = ["CvssError", "base_score", "severity_label", "parse_vector"]


class CvssError(ValueError):
    """Raised when a vector string is malformed or incomplete."""


# Metric value → numeric weight, per specification table.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
# Privileges Required is the one metric whose weight depends on Scope.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_VALID = {
    "AV": set(_AV), "AC": set(_AC), "PR": {"N", "L", "H"}, "UI": set(_UI),
    "S": {"U", "C"}, "C": set(_CIA), "I": set(_CIA), "A": set(_CIA),
}

_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/(.+)$", re.IGNORECASE)


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.x vector string into its base metrics.

    Raises :class:`CvssError` on anything that is not a complete, valid base
    vector. Rejecting loudly matters more than being permissive here — a vector
    silently coerced to a default produces a confident, wrong severity.
    """
    if not isinstance(vector, str):
        raise CvssError(f"vector must be a string, got {type(vector).__name__}")

    match = _VECTOR_RE.match(vector.strip())
    if not match:
        raise CvssError(
            f"not a CVSS v3.x vector (expected a 'CVSS:3.1/...' prefix): {vector!r}")

    metrics: dict[str, str] = {}
    for part in match.group(1).split("/"):
        if not part:
            continue
        key, _, value = part.partition(":")
        key, value = key.upper(), value.upper()
        if not value:
            raise CvssError(f"malformed metric {part!r} in {vector!r}")
        # Temporal/Environmental metrics are accepted but ignored; only the
        # base group contributes to a base score.
        if key in _VALID:
            if value not in _VALID[key]:
                raise CvssError(
                    f"invalid value {value!r} for metric {key} "
                    f"(expected one of {sorted(_VALID[key])})")
            metrics[key] = value

    missing = [m for m in _REQUIRED if m not in metrics]
    if missing:
        raise CvssError(
            f"vector is missing required base metrics: {', '.join(missing)}")
    return metrics


def _roundup(value: float) -> float:
    """Round up to one decimal place, per the v3.1 Appendix A definition.

    Not ``math.ceil(value * 10) / 10``: that mis-rounds values whose float
    representation sits a hair below an exact tenth, which the specification
    calls out explicitly.
    """
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Return the CVSS v3.1 base score, 0.0–10.0, for ``vector``."""
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    iss = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]

    combined = impact + exploitability
    if scope_changed:
        combined *= 1.08
    return _roundup(min(combined, 10.0))


def severity_label(score: float) -> str:
    """Qualitative rating for a score, per the v3.1 severity rating scale."""
    if score == 0:
        return "informational"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
