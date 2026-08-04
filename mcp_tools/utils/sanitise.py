"""Content sanitisation applied to data coming back from a target.

Target responses are attacker-controlled by definition — that is the whole
point of the engagement — so anything a tool returns and an agent will later
read has to be treated as hostile input, not data.

Skeleton status: a regex list.  PRD §6.2 calls for a prompt-injection
*classifier* here; these patterns catch only the most obvious phrasings and
will not survive a motivated adversary.  Replacing this with the real
classifier is a modelling-phase task.
"""
from __future__ import annotations

import re

_INJECTION_PATTERNS = [
    re.compile(r"ignore (?:all )?(?:previous|prior) instructions", re.IGNORECASE),
    re.compile(r"you are now.*mode", re.IGNORECASE),
    re.compile(r"<\s*system\s*>.*?<\s*/\s*system\s*>", re.IGNORECASE | re.DOTALL),
]


def strip_injection(text: str) -> str:
    """Return ``text`` with known prompt-injection markers removed."""
    for pattern in _INJECTION_PATTERNS:
        text = pattern.sub("", text)
    return text
