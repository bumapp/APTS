"""Common logging configuration for every service.

Reads the desired log level from the mounted config file at
``/etc/apts/config/log_level`` (a single line: ``DEBUG``, ``INFO``,
``WARNING``, ``ERROR``).  Falls back to ``INFO`` if the file is missing.
"""
from __future__ import annotations

import logging
import sys


CONFIG_DIR = "/etc/apts/config"


def _read_config_line(name: str, default: str) -> str:
    """Read a single-line config value from the mounted config directory."""
    try:
        with open(f"{CONFIG_DIR}/{name}", "r", encoding="utf-8") as fh:
            value = fh.read().strip()
    except (FileNotFoundError, OSError):
        return default
    return value or default


def configure(component: str) -> None:
    """Configure the root logger with a single stderr handler.

    Log level comes from ``/etc/apts/config/log_level`` (default ``INFO``).
    Every line is prefixed with the component name so all containers' logs
    are searchable when tailed together.
    """
    level_name = _read_config_line("log_level", "INFO").upper()
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
