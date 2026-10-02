"""The engagement pipeline: stage order, criticality, and retry budget.

This was declared twice — once in ``orchestrator/main.py`` and once in
``agent/main.py`` — which is exactly the duplication that drifts silently and
then routes an engagement into a stage that no longer exists. One definition,
imported by both.

Shape. PRD §5.1 specifies a directed acyclic task graph, but the v1.0 order it
mandates (Recon → Vulnerability Assessment → Exploitation → Reporting) is a
straight line, so this is modelled as an ordered sequence with graph-shaped
accessors. When a stage genuinely fans out — MITRE mapping and Exploitation can
both run off the Vulnerability Register — :func:`successors` grows to return
more than one name and the orchestrator gains join logic. Building a general
DAG executor before there is a fan-out to execute would be waste.
"""
from __future__ import annotations

# Stage order. Index position is execution order; the tuple is immutable so a
# caller cannot reorder the pipeline at runtime.
CHAIN: tuple[str, ...] = ("recon", "vuln", "mitre", "exploit", "script", "adviser")

# Critical = exhausting retries here stops the whole engagement (§2.2.4).
#
# Exploitation is deliberately absent. It is "minor, but special": if it fails
# every retry the run continues, but the Adviser must mark the report
# "weaknesses found but not confirmed" rather than presenting a confirmed test.
CRITICAL_AGENTS: frozenset[str] = frozenset({"recon", "vuln"})

MAX_RETRIES = 3


def is_known(agent: str) -> bool:
    return agent in CHAIN


def successors(agent: str) -> tuple[str, ...]:
    """Stages to dispatch once ``agent`` completes. Empty for the last stage."""
    idx = CHAIN.index(agent)
    return (CHAIN[idx + 1],) if idx + 1 < len(CHAIN) else ()


def next_agent(agent: str) -> str | None:
    """The single successor, or ``None`` at the end of the chain.

    Convenience for the current linear pipeline. Code that should survive a
    fan-out ought to use :func:`successors` instead.
    """
    nxt = successors(agent)
    return nxt[0] if nxt else None


def previous_agent(agent: str) -> str | None:
    """The predecessor whose stored output feeds ``agent``, or ``None`` first."""
    idx = CHAIN.index(agent)
    return CHAIN[idx - 1] if idx > 0 else None


def is_terminal(agent: str) -> bool:
    """True for the stage whose completion completes the engagement."""
    return not successors(agent)


def is_critical(agent: str) -> bool:
    return agent in CRITICAL_AGENTS
