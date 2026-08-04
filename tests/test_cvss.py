"""CVSS v3.1 base score tests.

The reference vectors below are published CVSS v3.1 examples with known scores.
They are the point of this file: a scoring bug is invisible in review and
changes every severity in the client's report.
"""
from __future__ import annotations

import pytest

from shared.cvss import CvssError, base_score, parse_vector, severity_label

# (vector, expected base score) — from the FIRST v3.1 examples and CVE records.
REFERENCE = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # unauth RCE
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),   # unauth info disclosure
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),   # authed SQLi
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),   # no impact
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),   # physical, minimal
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # scope change, max
]


@pytest.mark.parametrize("vector,expected", REFERENCE)
def test_reference_vectors(vector, expected):
    assert base_score(vector) == expected


def test_v30_prefix_also_accepted():
    assert base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_temporal_metrics_ignored_not_rejected():
    """Extra metric groups may appear; only the base group scores."""
    assert base_score(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C") == 9.8


def test_scope_change_raises_privileges_weight():
    """Same metrics but S:C scores higher — the one Scope-dependent weight."""
    unchanged = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L")
    changed = base_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L")
    assert changed > unchanged


# --------------------------------------------------------------------------- #
# Rejecting bad input, rather than defaulting it
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("vector", [
    "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",                    # no prefix
    "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",                    # wrong version
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",               # missing A
    "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",           # invalid AV
    "CVSS:3.1/",                                              # empty
    "",
])
def test_malformed_vectors_rejected(vector):
    with pytest.raises(CvssError):
        base_score(vector)


def test_non_string_rejected():
    with pytest.raises(CvssError):
        base_score(8.8)          # type: ignore[arg-type]


def test_parse_returns_base_metrics():
    metrics = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert metrics["AV"] == "N" and metrics["S"] == "C" and metrics["A"] == "N"


# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("score,label", [
    (0.0, "informational"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
    (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
])
def test_severity_bands(score, label):
    assert severity_label(score) == label
