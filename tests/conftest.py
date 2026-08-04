"""Shared test setup.

``agent/config.py`` raises at import time when ``AGENT_NAME`` is unset — correct
for a container, which must never start without knowing which stage it is, but
it turns any test that reaches ``agent.main`` or ``agent.controllers`` into a
confusing collection error. Setting a default here keeps that guard strict in
production without making it a tripwire for the suite.

Set before any test module is imported, and only when absent, so a run with an
explicit ``AGENT_NAME=vuln`` still exercises that stage.
"""
from __future__ import annotations

import os

os.environ.setdefault("AGENT_NAME", "mitre")
