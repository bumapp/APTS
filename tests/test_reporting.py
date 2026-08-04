"""Script Builder and Adviser tests.

The Adviser is the last chance to misrepresent the engagement, so most of these
assert what the report refuses to do: claim an unproven finding is proven,
average away a critical, ship a script for something nobody reproduced, or omit
the limitations. A report that reads cleanly over a shallow test is the most
damaging thing this pipeline could produce.
"""
from __future__ import annotations

import json
from uuid import uuid4

import httpx
import pytest

from shared.llm import LlmClient
from shared.models import Scope

from agent.services.report_renderer import render_markdown
from agent.services.workers.adviser_worker import AdviserWorker
from agent.services.workers.base import WorkContext
from agent.services.workers.script_worker import ScriptWorker, safety_check

REGISTER = {"weaknesses": [
    {"id": "W-001", "title": "SQL injection in login", "asset": "/rest/user/login",
     "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "owasp_category": "A03:2021", "evidence": []},
    {"id": "W-002", "title": "Info disclosure", "asset": "/rest/admin/config",
     "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "owasp_category": "A01:2021", "evidence": []},
    {"id": "W-003", "title": "User enumeration", "asset": "/rest/user/whoami",
     "cvss_score": 5.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "owasp_category": "A07:2021", "evidence": []},
], "candidates_dropped": 1}

EXPLOITATION = {"attempts": [
    {"weakness_id": "W-002", "confirmed": True, "payload": "GET /rest/admin/config",
     "detection": "status:200", "reason": "",
     "evidence": {"request": "GET /rest/admin/config", "response": "HTTP 200 {...}",
                  "note": "", "captured_at": "2026-08-04T00:00:00"}},
    {"weakness_id": "W-001", "confirmed": False, "payload": "GET /rest/user/login",
     "detection": "contains:SQL", "reason": "signal did not appear", "evidence": None},
], "skipped": ["W-003"]}

ATTACK_MAP = {"mappings": {
    "W-001": [{"technique_id": "T1190", "technique_name": "Exploit Public-Facing App",
               "tactic": "Initial Access"}],
    "W-002": [{"technique_id": "T1005", "technique_name": "Data from Local System",
               "tactic": "Collection"}],
}}


class FakeResults:
    def __init__(self, **artifacts):
        self.artifacts = {"recon": {"pages_crawled": 1, "api_paths": ["/x"],
                                    "truncated": True},
                          "vuln": REGISTER, "mitre": ATTACK_MAP,
                          "exploit": EXPLOITATION, "script": {"scripts": []}}
        self.artifacts.update(artifacts)

    def load(self, engagement_id, agent):
        return self.artifacts.get(agent)


class FakeReports:
    def __init__(self):
        self.saved = []

    def save(self, report):
        self.saved.append(report)
        return ["/var/apts/reports/report-x.json", "/var/apts/reports/report-x.md"]


def ctx(upstream=None) -> WorkContext:
    return WorkContext(engagement_id=uuid4(), target_url="http://target.test",
                       scope=Scope(domains=["target.test"]), upstream=upstream or {})


def llm_returning(payload) -> LlmClient:
    def handler(request):
        return httpx.Response(200, json={
            "choices": [{"message": {"content": json.dumps(payload)}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    return LlmClient("adviser", client=httpx.AsyncClient(
        transport=httpx.MockTransport(handler)), api_key="k")


ADVICE = {"recommendations": {
    "W-001": {"fix": "Use parameterised queries in the login handler.",
              "effort": "medium"},
    "W-002": {"fix": "Require authentication on the config endpoint.",
              "effort": "low"}},
    "narrative": "One confirmed exposure; two unproven hypotheses."}


# --------------------------------------------------------------------------- #
# Script safety
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("source", [
    "import requests\nrequests.post(url, data='1; DROP TABLE users')",
    "import os\nos.system('curl x')",
    "while True:\n    requests.get(url)",
    "eval(payload)",
    "subprocess.run(cmd, shell=True)",
])
def test_unsafe_scripts_rejected(source):
    passed, notes = safety_check(source)
    assert passed is False and "rejected" in notes


def test_benign_repro_script_passes():
    source = ("import sys, requests\n"
              "r = requests.get(sys.argv[1] + '/rest/admin/config')\n"
              "print('reproduced' if r.status_code == 200 else 'not reproduced')")
    passed, _ = safety_check(source)
    assert passed is True


async def test_no_scripts_when_nothing_confirmed():
    """A repro script for an unproven finding is a guess presented as a demo."""
    def explode(request):
        raise AssertionError("the model must not be called with no confirmations")

    llm = LlmClient("script", client=httpx.AsyncClient(
        transport=httpx.MockTransport(explode)), api_key="k")
    async with llm:
        result = await ScriptWorker(llm, FakeResults(
            exploit={"attempts": [], "skipped": []}))(ctx())

    assert result["scripts"] == []


async def test_unsafe_generated_script_is_rejected_not_shipped():
    async with (llm := llm_returning({"scripts": [
        {"weakness_id": "W-002", "language": "python",
         "source": "import os\nos.system('rm -rf /')"}]})):
        result = await ScriptWorker(llm, FakeResults())(ctx())

    assert result["scripts"] == [] and result["rejected"] == 1


async def test_safe_script_ships_with_technique_tags():
    async with (llm := llm_returning({"scripts": [
        {"weakness_id": "W-002", "language": "python",
         "source": "import sys, requests\nprint(requests.get(sys.argv[1]).status_code)",
         "description": "reproduces the exposure",
         "remediation_pointer": "require auth"}]})):
        result = await ScriptWorker(llm, FakeResults())(ctx())

    script = result["scripts"][0]
    assert script["safety_checked"] is True
    assert script["technique_ids"] == ["T1005"]


# --------------------------------------------------------------------------- #
# The report tells the truth
# --------------------------------------------------------------------------- #

async def test_status_distinguishes_confirmed_unproven_and_untested():
    reports = FakeReports()
    async with (llm := llm_returning(ADVICE)):
        result = await AdviserWorker(llm, FakeResults(), reports)(ctx())

    by_id = {f["id"]: f for f in result["findings"]}
    assert by_id["W-002"]["confirmed"] is True
    assert by_id["W-002"]["status"] == "confirmed exploitable"
    assert by_id["W-001"]["confirmed"] is False
    assert "not proven" in by_id["W-001"]["status"]
    assert by_id["W-003"]["status"] == "not tested"


async def test_risk_score_is_worst_confirmed_not_an_average():
    """One critical among lows must not average into 'medium'."""
    async with (llm := llm_returning(ADVICE)):
        result = await AdviserWorker(llm, FakeResults(), FakeReports())(ctx())

    # W-002 (7.5) is the only confirmed finding; W-001 scores higher but is unproven.
    assert result["executive_summary"]["risk_score"] == 7.5
    assert result["executive_summary"]["confirmed_count"] == 1
    assert result["executive_summary"]["total_findings"] == 3


async def test_confirmed_findings_sort_first():
    async with (llm := llm_returning(ADVICE)):
        result = await AdviserWorker(llm, FakeResults(), FakeReports())(ctx())

    assert result["findings"][0]["id"] == "W-002"


async def test_caveats_report_what_actually_limited_the_run():
    async with (llm := llm_returning(ADVICE)):
        result = await AdviserWorker(llm, FakeResults(), FakeReports())(ctx())

    caveats = " ".join(result["caveats"])
    assert "no human review" in caveats
    assert "crawl hit a configured limit" in caveats     # recon truncated
    assert "were not proven exploitable" in caveats       # W-001, W-003
    assert "never tested" in caveats                      # W-003 skipped
    assert "discarded" in caveats                         # candidates_dropped=1


async def test_report_survives_an_llm_outage():
    """The findings are the deliverable; missing prose must not lose them."""
    def broken(request):
        return httpx.Response(503, json={"error": "down"})

    llm = LlmClient("adviser", client=httpx.AsyncClient(
        transport=httpx.MockTransport(broken)), api_key="k")
    async with llm:
        result = await AdviserWorker(llm, FakeResults(), FakeReports())(ctx())

    assert len(result["findings"]) == 3
    assert "unavailable" in result["executive_summary"]["narrative"]


async def test_report_is_written_to_disk():
    reports = FakeReports()
    async with (llm := llm_returning(ADVICE)):
        result = await AdviserWorker(llm, FakeResults(), reports)(ctx())

    assert len(reports.saved) == 1
    assert result["report_files"][1].endswith(".md")


async def test_attack_coverage_maps_techniques_to_findings():
    async with (llm := llm_returning(ADVICE)):
        result = await AdviserWorker(llm, FakeResults(), FakeReports())(ctx())

    assert result["attack_coverage"] == {"T1005": ["W-002"], "T1190": ["W-001"]}


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

async def test_markdown_marks_confirmed_and_carries_caveats():
    reports = FakeReports()
    async with (llm := llm_returning(ADVICE)):
        await AdviserWorker(llm, FakeResults(), reports)(ctx())

    markdown = render_markdown(reports.saved[0])
    assert "**CONFIRMED**" in markdown
    assert "not tested" in markdown
    assert "## Caveats and limitations" in markdown
    assert "no human review" in markdown


async def test_markdown_warns_when_exploitation_never_ran():
    reports = FakeReports()
    async with (llm := llm_returning(ADVICE)):
        await AdviserWorker(llm, FakeResults(
            exploit={"attempts": [], "skipped": []}), reports)(ctx())

    markdown = render_markdown(reports.saved[0])
    assert "Weaknesses found but not confirmed" in markdown
