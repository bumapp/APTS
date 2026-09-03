"""Tests for the native-MCP ATT&CK reference tool.

The mapping loop trusts exactly one thing about a technique id: that
``attack_technique`` confirmed it. These tests pin that tool's contract —
it validates real ids, refuses invented ones, and hands back usable
corrections rather than a bare failure.
"""
from __future__ import annotations

from mcp_native.tools import attack_tool


def test_catalog_lists_every_technique():
    cat = attack_tool.attack_catalog()
    assert cat["count"] >= 40
    ids = {t["technique_id"] for t in cat["techniques"]}
    assert "T1190" in ids and "T1059.007" in ids
    # every entry carries at least one tactic — the loop needs one to emit
    assert all(t["tactics"] for t in cat["techniques"])


def test_technique_validates_a_real_id():
    res = attack_tool.attack_technique("T1190")
    assert res["found"] is True
    assert res["name"] == "Exploit Public-Facing Application"
    assert res["tactics"] == ["Initial Access"]


def test_technique_is_case_and_space_insensitive():
    assert attack_tool.attack_technique("  t1059.007 ")["found"] is True


def test_unknown_id_is_refused_with_suggestions():
    res = attack_tool.attack_technique("T9999")
    assert res["found"] is False
    assert res["did_you_mean"]  # nearest real ids, not an empty failure
    assert all(d["technique_id"].startswith("T") for d in res["did_you_mean"])


def test_bad_subtechnique_points_at_the_family():
    res = attack_tool.attack_technique("T1059.999")
    assert res["found"] is False
    suggested = {d["technique_id"] for d in res["did_you_mean"]}
    assert "T1059" in suggested and "T1059.007" in suggested


def test_malformed_id_is_rejected_before_lookup():
    res = attack_tool.attack_technique("not-an-id")
    assert res["found"] is False
    assert "well-formed" in res["reason"]


def test_search_finds_the_expected_technique():
    matches = attack_tool.attack_search("sql injection in login")["matches"]
    assert matches and matches[0]["technique_id"] == "T1190"


def test_search_ranks_session_theft_for_xss_cookie_theft():
    ids = [m["technique_id"]
           for m in attack_tool.attack_search("steal session cookie via xss")["matches"]]
    assert "T1539" in ids[:3]


def test_search_empty_query_is_handled():
    res = attack_tool.attack_search("   ")
    assert res["count"] == 0 and res["matches"] == []
