"""Plausibility ceilings for CVSS vectors, by weakness class.

Added in response to a real observation: on a live run the model scored a
reflected XSS at **9.6 critical**, using ``S:C/C:H/I:H/A:H``. The arithmetic was
correct — ``shared.cvss`` computed exactly what that vector says — but the
vector was wrong. Reflected XSS is around 6.1. Code that only validates the
*format* of a vector cannot catch this, because the vector was well-formed.

So this is the second half of "the model judges, code scores": the model still
picks the vector, but a vector claiming a severity its weakness class cannot
plausibly reach is clamped to the canonical vector for that class, and the
substitution is recorded on the finding rather than done quietly.

The ceilings are deliberately generous. They exist to catch a reflected XSS
rated 9.6, not to second-guess whether a specific SQL injection is 9.1 or 9.8.
A weakness class that is not recognised is left entirely alone — an unknown
class is not evidence of inflation, and silently clamping novel findings would
be worse than the problem being solved.
"""
from __future__ import annotations

from dataclasses import dataclass

from shared.cvss import base_score


@dataclass(frozen=True)
class ClassCeiling:
    """The most severe plausible base vector for a class of weakness."""
    label: str
    canonical_vector: str
    keywords: tuple[str, ...]

    @property
    def max_score(self) -> float:
        return base_score(self.canonical_vector)


# Ordered: the first keyword match wins, so put specific classes before generic
# ones ("stored xss" before "xss", "second-order sqli" before "injection").
CEILINGS: tuple[ClassCeiling, ...] = (
    ClassCeiling(
        "stored XSS", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N",
        ("stored xss", "persistent xss", "stored cross-site")),
    ClassCeiling(
        "reflected/DOM XSS", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        ("reflected xss", "dom xss", "cross-site scripting", "xss")),
    ClassCeiling(
        "SQL injection", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ("sql injection", "sqli", "nosql injection")),
    ClassCeiling(
        "remote code execution", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        ("remote code execution", "rce", "deserialization", "command injection")),
    ClassCeiling(
        "unrestricted file upload", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        ("file upload", "webshell", "unrestricted upload")),
    ClassCeiling(
        "SSRF", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
        ("ssrf", "server-side request forgery")),
    ClassCeiling(
        "IDOR / broken access control", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        ("idor", "insecure direct object", "broken access control",
         "privilege escalation", "mass assignment")),
    ClassCeiling(
        "CSRF", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        ("csrf", "cross-site request forgery")),
    ClassCeiling(
        "path traversal / LFI", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ("path traversal", "directory traversal", "local file inclusion", "lfi")),
    ClassCeiling(
        "information disclosure", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        ("information disclosure", "information exposure", "sensitive data",
         "directory listing", "exposed", "debug endpoint", "configuration")),
    ClassCeiling(
        "user enumeration", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        ("user enumeration", "username enumeration", "account enumeration")),
    ClassCeiling(
        "weak authentication", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        ("brute force", "no rate limit", "no lockout", "default credential",
         "weak password", "session fixation", "jwt")),
)


def find_ceiling(*text: str) -> ClassCeiling | None:
    """Match a weakness description against a known class, or return ``None``."""
    haystack = " ".join(t for t in text if t).lower()
    for ceiling in CEILINGS:
        if any(keyword in haystack for keyword in ceiling.keywords):
            return ceiling
    return None


def clamp(vector: str, score: float, *description: str) -> tuple[str, float, str]:
    """Clamp an implausible vector to its class canonical.

    Returns ``(vector, score, note)``. ``note`` is empty when nothing changed;
    otherwise it explains the substitution so the finding carries its own audit
    trail rather than quietly showing a different number than the model chose.
    """
    ceiling = find_ceiling(*description)
    if ceiling is None or score <= ceiling.max_score:
        return vector, score, ""

    return (
        ceiling.canonical_vector,
        ceiling.max_score,
        f"model proposed {vector} ({score}), implausible for "
        f"{ceiling.label}; clamped to the class canonical",
    )
