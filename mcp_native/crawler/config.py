"""Crawler tunables (ported from the retired ``mcp_tools`` facade).

Same environment-variable names and defaults the crawler always used, so a
deployment that set ``APTS_CRAWL_*`` keeps working unchanged. The cache is off
by default; when enabled it writes under a directory this container can write to.
"""
from __future__ import annotations

import os

TARGET_TIMEOUT_SECONDS = float(os.environ.get("APTS_TARGET_TIMEOUT", "10"))
# Coverage-first defaults: crawl the whole app surface. The ceiling is high and the
# time budget is generous so recon finds EVERY reachable endpoint; route mining +
# menu expansion already surface far more pages than plain link-following.
CRAWL_MAX_PAGES = int(os.environ.get("APTS_CRAWL_MAX_PAGES", "150"))
CRAWL_MAX_DEPTH = int(os.environ.get("APTS_CRAWL_MAX_DEPTH", "4"))
CRAWL_MAX_SECONDS = float(os.environ.get("APTS_CRAWL_MAX_SECONDS", "600"))
# Per-page settle after "load" before reading requests/links AND before the crawler
# fills+submits forms. 700ms proved too aggressive: the Angular login form was not
# interactive yet, so _fill_and_submit never fired POST /rest/user/login, the login
# endpoint never reached recon, and the login-SQLi finding was silently lost. Form
# coverage (a critical finding class) beats shaving ~0.5s/page, so keep 1200ms.
CRAWL_SETTLE_MS = int(os.environ.get("APTS_CRAWL_SETTLE_MS", "1200"))
CRAWL_BODY_LIMIT = int(os.environ.get("APTS_CRAWL_BODY_LIMIT", "500000"))

# Development crawl cache — off unless APTS_CRAWL_CACHE=1.
CRAWL_CACHE_ENABLED = os.environ.get("APTS_CRAWL_CACHE", "0") == "1"
CRAWL_CACHE_DIR = os.environ.get("APTS_CRAWL_CACHE_DIR", "/tmp/apts-crawl-cache")
