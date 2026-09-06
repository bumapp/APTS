"""Crawler tunables (ported from the retired ``mcp_tools`` facade).

Same environment-variable names and defaults the crawler always used, so a
deployment that set ``APTS_CRAWL_*`` keeps working unchanged. The cache is off
by default; when enabled it writes under a directory this container can write to.
"""
from __future__ import annotations

import os

TARGET_TIMEOUT_SECONDS = float(os.environ.get("APTS_TARGET_TIMEOUT", "10"))
CRAWL_MAX_PAGES = int(os.environ.get("APTS_CRAWL_MAX_PAGES", "60"))
CRAWL_MAX_DEPTH = int(os.environ.get("APTS_CRAWL_MAX_DEPTH", "3"))
# Raised alongside route mining/menu expansion: those surface far more pages, and
# the per-page speed-ups (load+settle instead of networkidle, discovery passes run
# once) make a larger budget usable rather than just slower.
CRAWL_MAX_SECONDS = float(os.environ.get("APTS_CRAWL_MAX_SECONDS", "240"))
CRAWL_BODY_LIMIT = int(os.environ.get("APTS_CRAWL_BODY_LIMIT", "500000"))

# Development crawl cache — off unless APTS_CRAWL_CACHE=1.
CRAWL_CACHE_ENABLED = os.environ.get("APTS_CRAWL_CACHE", "0") == "1"
CRAWL_CACHE_DIR = os.environ.get("APTS_CRAWL_CACHE_DIR", "/tmp/apts-crawl-cache")
