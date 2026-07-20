"""Common logging configuration for every service."""
from __future__ import annotations

import logging
import os
import sys


def configure(component: str) -> None:
    """Configure the root logger with a single stderr handler.

    Log level comes from ``APTS_LOG_LEVEL`` (default ``INFO``).  Every line is
    prefixed with the component name so all containers' logs are searchable
    when tailed together.
    """
    level_name = os.environ.get("APTS_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    fmt = f"%(asctime)s [{component}] %(levelname)s %(name)s: %(message)s"
    handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S%z"))
    root.addHandler(handler)

    # Quiet down chatty libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
