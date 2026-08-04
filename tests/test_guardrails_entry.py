"""Entry-checkpoint tests.

The theme here is coherence rather than authorisation: a spec that passes
intake must describe an engagement the agents can actually run. Every
"rejected" case below is one that used to be accepted and would then have died
at the MCP checkpoint on Recon's first request.

The final class pins entry and MCP to the same answer. Those two checkpoints
having different opinions about a pattern is the specific bug this shares a
matcher to prevent, so it is worth asserting directly rather than trusting the
shared import to stay shared.
"""
from __future__ import annotations

import pytest

from mcp_tools.services.guardrails_service import (
    GuardrailsBlocked,
    GuardrailsService,
)
from orchestrator import guardrails_entry
from orchestrator.guardrails_entry import (
    GuardrailsEntryBlocked,
    _check_scope_well_formed,
    _check_target_allowed,
)
from shared.models import EngagementSpec, Scope

GUARDRAILS = GuardrailsService()


def spec(target: str, **scope_kwargs) -> EngagementSpec:
    return EngagementSpec(target_url=target, scope=Scope(**scope_kwargs))


# --------------------------------------------------------------------------- #
# Specs that must be accepted
# --------------------------------------------------------------------------- #

def test_readme_smoke_test_spec_is_accepted():
    """The exact invocation in README step 7 must still start an engagement."""
    _check_scope_well_formed(
        spec("https://juice-shop.test/", domains=["*.juice-shop.test"]))


def test_exact_domain_accepted():
    _check_scope_well_formed(spec("https://example.com/", domains=["example.com"]))


def test_target_under_allow_paths_accepted():
    _check_scope_well_formed(
        spec("https://example.com/app/login",
             domains=["example.com"], allow_paths=["/app/"]))


# --------------------------------------------------------------------------- #
# Specs that would start but never work
# --------------------------------------------------------------------------- #

def test_domainless_scope_rejected():
    """allow_paths alone leaves the MCP checkpoint with no permitted hosts."""
    with pytest.raises(GuardrailsEntryBlocked, match="at least one domain"):
        _check_scope_well_formed(spec("https://example.com/", allow_paths=["/app/"]))


def test_empty_scope_rejected():
    with pytest.raises(GuardrailsEntryBlocked, match="at least one domain"):
        _check_scope_well_formed(spec("https://example.com/"))


def test_target_outside_its_own_scope_rejected():
    with pytest.raises(GuardrailsEntryBlocked, match="not covered by its own scope"):
        _check_scope_well_formed(
            spec("https://app.example.com/", domains=["*.example.org"]))


def test_subdomain_target_without_wildcard_rejected():
    """A classic operator slip: exact apex scope, subdomain target."""
    with pytest.raises(GuardrailsEntryBlocked, match="not covered by its own scope"):
        _check_scope_well_formed(
            spec("https://app.example.com/", domains=["example.com"]))


def test_target_path_excluded_by_own_deny_paths_rejected():
    with pytest.raises(GuardrailsEntryBlocked, match="deny_paths"):
        _check_scope_well_formed(
            spec("https://example.com/admin/",
                 domains=["example.com"], deny_paths=["/admin/"]))


def test_target_path_outside_own_allow_paths_rejected():
    with pytest.raises(GuardrailsEntryBlocked, match="allow_paths"):
        _check_scope_well_formed(
            spec("https://example.com/", domains=["example.com"], allow_paths=["/app/"]))


def test_unparseable_target_rejected():
    with pytest.raises(GuardrailsEntryBlocked, match="hostname"):
        _check_scope_well_formed(spec("not-a-url", domains=["example.com"]))


# --------------------------------------------------------------------------- #
# The deployment allowlist (config/target_allowlist), which no spec can widen
# --------------------------------------------------------------------------- #

@pytest.fixture
def allowlist(monkeypatch):
    """Set the module-level allowlist, normally read from the config file."""
    def _set(entries: list[str]) -> None:
        monkeypatch.setattr(guardrails_entry, "ALLOWLIST", entries)
    return _set


def test_empty_allowlist_accepts_anything(allowlist):
    """Skeleton convenience; the README warns against running this way."""
    allowlist([])
    _check_target_allowed("https://anything.test/")


def test_allowlist_wildcard_covers_apex_and_subdomains(allowlist):
    allowlist(["*.juice-shop.test"])
    _check_target_allowed("https://juice-shop.test/")
    _check_target_allowed("https://api.juice-shop.test/")


def test_allowlist_blocks_unlisted_host(allowlist):
    allowlist(["*.juice-shop.test"])
    with pytest.raises(GuardrailsEntryBlocked, match="allowlist"):
        _check_target_allowed("https://evil.test/")


def test_allowlist_resists_suffix_confusion(allowlist):
    allowlist(["*.juice-shop.test"])
    with pytest.raises(GuardrailsEntryBlocked):
        _check_target_allowed("https://notjuice-shop.test/")
    with pytest.raises(GuardrailsEntryBlocked):
        _check_target_allowed("https://juice-shop.test.evil.test/")


# --------------------------------------------------------------------------- #
# The two checkpoints must agree
# --------------------------------------------------------------------------- #

AGREEMENT_CASES = [
    ("https://juice-shop.test/",        ["*.juice-shop.test"], True),
    ("https://api.juice-shop.test/v1",  ["*.juice-shop.test"], True),
    ("https://example.com/",            ["example.com"],       True),
    ("https://app.example.com/",        ["example.com"],       False),
    ("https://notexample.com/",         ["*.example.com"],     False),
    ("https://example.com.evil.test/",  ["*.example.com"],     False),
    ("https://EXAMPLE.com/",            ["example.com"],       True),
]


@pytest.mark.parametrize("target,domains,expected_in_scope", AGREEMENT_CASES)
def test_entry_and_mcp_reach_the_same_verdict(target, domains, expected_in_scope):
    def entry_accepts() -> bool:
        try:
            _check_scope_well_formed(spec(target, domains=domains))
            return True
        except GuardrailsEntryBlocked:
            return False

    def mcp_accepts() -> bool:
        try:
            GUARDRAILS.check("http", {"url": target}, Scope(domains=domains))
            return True
        except GuardrailsBlocked:
            return False

    assert entry_accepts() is expected_in_scope
    assert mcp_accepts() is expected_in_scope
