"""Renders an execution trace to Markdown — the flow file that ships with the report.

Two audiences, one document. The timeline at the top answers "what happened, in
what order, and where did the time go?" at a glance. The per-stage sections
below it answer "why did this stage produce that?" with the actual prompts,
model replies, and tool exchanges.

Every prompt and response body is inside a collapsed ``<details>`` block. A
single engagement can carry a hundred kilobytes of prompt text; inlined, the
interesting structure — six stages, their inputs, their outputs — would be
unreadable between the walls of text. GitHub, most Markdown viewers, and every
browser render ``<details>``, and a viewer that does not falls back to showing
the content expanded, which is degraded but never lossy.

Nothing here re-derives a conclusion. The report is the claim about the target;
this is the record of how the claim was reached, and if the two disagree the
flow file is the one telling the truth.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from agent.repositories.trace_repository import TraceEvent

#: How much of a payload string to show in the expandable blocks. The trace rows
#: themselves are already capped by ``shared.trace``; this is a second, tighter
#: bound so one crawled page cannot dominate the document.
_BLOCK_CHARS = 4000

#: Stage-level events, in the order they occur within a stage run. Used to keep
#: the per-stage sections in a predictable shape rather than raw insertion order.
_STAGE_EVENTS = ("stage_input", "llm_call", "tool_call", "stage_output",
                 "handoff", "stage_failed")

_ONE_LINERS = {
    "engagement_requested": "engagement requested",
    "kickoff": "handed to first stage",
    "retry_launched": "retry launched",
    "engagement_complete": "engagement complete",
    "engagement_failed": "engagement failed",
    "report_written": "report written",
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _clip(text: str, limit: int = _BLOCK_CHARS) -> str:
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n… [clipped for display, {len(text)} chars in trace]"


def _fence(content: Any, language: str = "") -> list[str]:
    """A fenced block holding ``content``, rendered as text or pretty JSON."""
    if isinstance(content, str):
        body = _clip(content)
    else:
        body = _clip(json.dumps(content, indent=2, default=str, ensure_ascii=False))
        language = language or "json"
    return [f"```{language}", body, "```"]


def _details(summary: str, body: list[str]) -> list[str]:
    """A collapsed block. The blank lines are required for Markdown inside HTML."""
    return ["<details>", f"<summary>{summary}</summary>", "", *body, "",
            "</details>", ""]


def _duration(event: TraceEvent) -> str:
    if event.duration_ms is None:
        return ""
    if event.duration_ms < 1000:
        return f"{event.duration_ms} ms"
    return f"{event.duration_ms / 1000:.1f} s"


def _elapsed(event: TraceEvent, start: datetime) -> str:
    return f"+{(event.logged_at - start).total_seconds():6.1f}s"


def _summarise(event: TraceEvent) -> str:
    """One line describing an event, for the timeline table."""
    payload = event.payload
    kind = event.event_type

    if kind == "engagement_requested":
        scope = payload.get("scope") or {}
        domains = ", ".join(scope.get("domains") or []) or "(none)"
        return f"target `{payload.get('target_url', '?')}`, domains {domains}"
    if kind == "kickoff":
        return f"→ {payload.get('agent', '?')}"
    if kind == "stage_input":
        keys = sorted(payload.get("upstream_keys") or [])
        return (f"received {payload.get('upstream_bytes', 0)} B from "
                f"{payload.get('from_component', '?')}"
                + (f" ({', '.join(keys[:5])})" if keys else " (nothing upstream)"))
    if kind == "llm_call":
        usage = payload.get("usage") or {}
        if payload.get("error"):
            return f"model call FAILED — {payload['error'][:80]}"
        return (f"{payload.get('model', '?')} attempt {payload.get('attempt', 1)}: "
                f"in={usage.get('prompt_tokens', 0)} "
                f"out={usage.get('completion_tokens', 0)} "
                f"(reasoning={usage.get('reasoning_tokens', 0)})")
    if kind == "tool_call":
        tool = payload.get("tool", "?")
        if payload.get("error"):
            return f"`{tool}` FAILED — {payload['error'][:80]}"
        if payload.get("blocked"):
            return f"`{tool}` BLOCKED — {str(payload.get('reason', ''))[:80]}"
        return f"`{tool}` ok — {_outcome_hint(payload.get('output') or {})}"
    if kind == "stage_output":
        return f"produced {payload.get('summary') or payload.get('artifact', '?')}"
    if kind == "handoff":
        return f"→ {payload.get('next_agent', '?')}"
    if kind == "stage_failed":
        return f"**{str(payload.get('error', 'failed'))[:100]}**"
    if kind == "report_written":
        return ", ".join(f"`{p}`" for p in payload.get("paths") or []) or "(no files)"
    if kind == "retry_launched":
        return (f"{payload.get('agent', '?')} attempt "
                f"{payload.get('attempt', '?')}: {str(payload.get('reason', ''))[:60]}")
    if kind in _ONE_LINERS:
        return _ONE_LINERS[kind]
    return json.dumps(payload, default=str)[:120]


def _outcome_hint(output: dict[str, Any]) -> str:
    """A few words about what a tool actually returned."""
    if "status_code" in output:
        body = str(output.get("body") or "")
        return f"HTTP {output['status_code']}, {len(body)} B body"
    if "exit_code" in output:
        return f"exit {output['exit_code']}"
    if "pages" in output:
        return f"{len(output.get('pages') or [])} pages"
    keys = sorted(k for k in output if k != "error")
    return ", ".join(keys[:4]) or "empty"


# --------------------------------------------------------------------------- #
# Document
# --------------------------------------------------------------------------- #

def render_markdown(engagement_id: str, events: list[TraceEvent]) -> str:
    """Return the whole flow as one Markdown document."""
    out: list[str] = [
        "# Execution flow",
        "",
        f"**Engagement:** `{engagement_id}`  ",
    ]

    if not events:
        out += [
            "",
            "_No trace events were recorded._ Either `APTS_TRACE_ENABLED=0` was "
            "set for this run, or the `agent_trace` table is missing — check "
            "that `database/bootstrap/init_db.sql` has been applied.",
            "",
        ]
        return "\n".join(out)

    start = events[0].logged_at
    end = events[-1].logged_at
    out += [
        f"**Started:** {start:%Y-%m-%d %H:%M:%S UTC}  ",
        f"**Wall clock:** {(end - start).total_seconds():.1f}s  ",
        f"**Events:** {len(events)}",
        "",
        "Every model call, tool call, and stage handoff in this engagement, in "
        "the order it happened. Prompts and response bodies are truncated — see "
        "`shared/trace.py` for the caps.",
        "",
    ]

    out += _timeline(events)
    out += _cost(events)
    out += _stages(events, start)
    return "\n".join(out)


def _timeline(events: list[TraceEvent]) -> list[str]:
    start = events[0].logged_at
    out = ["## Timeline", "",
           "| Elapsed | Agent | Event | Took | What |",
           "|---|---|---|---|---|"]
    for event in events:
        out.append(f"| `{_elapsed(event, start)}` | {event.agent} | "
                   f"{event.event_type} | {_duration(event)} | "
                   f"{_summarise(event)} |")
    out.append("")
    return out


def _cost(events: list[TraceEvent]) -> list[str]:
    """Per-agent model spend.

    Reasoning tokens are billed as output but reported separately, so they are
    broken out here rather than folded into the completion count — an agent
    whose cost is mostly hidden reasoning looks cheap in any other view.
    """
    calls = [e for e in events if e.event_type == "llm_call"]
    if not calls:
        return ["## Model usage", "",
                "_No model calls were made in this engagement._", ""]

    per_agent: dict[str, dict[str, int]] = {}
    for event in calls:
        usage = event.payload.get("usage") or {}
        row = per_agent.setdefault(event.agent, {
            "calls": 0, "in": 0, "out": 0, "reasoning": 0, "ms": 0})
        row["calls"] += 1
        row["in"] += usage.get("prompt_tokens", 0)
        row["out"] += usage.get("completion_tokens", 0)
        row["reasoning"] += usage.get("reasoning_tokens", 0)
        row["ms"] += event.duration_ms or 0

    out = ["## Model usage", "",
           "| Agent | Calls | Prompt | Completion | Reasoning | Time |",
           "|---|---|---|---|---|---|"]
    for agent, row in per_agent.items():
        out.append(f"| {agent} | {row['calls']} | {row['in']} | {row['out']} | "
                   f"{row['reasoning']} | {row['ms'] / 1000:.1f}s |")
    total = {k: sum(r[k] for r in per_agent.values())
             for k in ("calls", "in", "out", "reasoning", "ms")}
    out += [f"| **total** | **{total['calls']}** | **{total['in']}** | "
            f"**{total['out']}** | **{total['reasoning']}** | "
            f"**{total['ms'] / 1000:.1f}s** |", ""]
    return out


def _stages(events: list[TraceEvent], start: datetime) -> list[str]:
    """One section per agent, in the order each first appears."""
    order: list[str] = []
    grouped: dict[str, list[TraceEvent]] = {}
    for event in events:
        if event.agent not in grouped:
            order.append(event.agent)
            grouped[event.agent] = []
        grouped[event.agent].append(event)

    out = ["## Stage detail", ""]
    for agent in order:
        out.append(f"### {agent}")
        out.append("")
        for event in grouped[agent]:
            out += _event_detail(event, start)
    return out


def _event_detail(event: TraceEvent, start: datetime) -> list[str]:
    payload = event.payload
    kind = event.event_type
    head = f"`{_elapsed(event, start)}` **{kind}**"
    took = _duration(event)
    if took:
        head += f" · {took}"

    if kind == "llm_call":
        usage = payload.get("usage") or {}
        out = [f"{head} · {payload.get('model', '?')} · attempt "
               f"{payload.get('attempt', 1)} · "
               f"in={usage.get('prompt_tokens', 0)} "
               f"out={usage.get('completion_tokens', 0)} "
               f"reasoning={usage.get('reasoning_tokens', 0)}", ""]
        if payload.get("error"):
            out += [f"Call failed: `{payload['error']}`", ""]
        out += _details("system prompt", _fence(payload.get("system_prompt", "")))
        out += _details("user prompt", _fence(payload.get("user_prompt", "")))
        out += _details("raw response", _fence(payload.get("raw_response", "")))
        return out

    if kind == "tool_call":
        verdict = ("FAILED" if payload.get("error")
                   else "BLOCKED" if payload.get("blocked")
                   else "ok" if payload.get("ok") else "not ok")
        out = [f"{head} · `{payload.get('tool', '?')}` · {verdict}", ""]
        if payload.get("error"):
            out += [f"`{payload['error']}`", ""]
        if payload.get("blocked"):
            out += [f"Guardrails: {payload.get('reason', '')}", ""]
        out += _details("arguments", _fence(payload.get("args") or {}))
        if "output" in payload:
            out += _details("output", _fence(payload["output"]))
        return out

    if kind == "stage_input":
        out = [f"{head} · from {payload.get('from_component', '?')} · "
               f"target `{payload.get('target_url', '?')}`", ""]
        out += _details("scope", _fence(payload.get("scope") or {}))
        out += _details("upstream artifact", _fence(payload.get("upstream") or {}))
        return out

    if kind == "stage_output":
        out = [f"{head} · {payload.get('summary', '')}", ""]
        out += _details("artifact", _fence(payload.get("artifact") or {}))
        return out

    if kind == "stage_failed":
        return [f"{head} — **{payload.get('error', 'failed')}**", "",
                *_fence(payload.get("traceback") or "(no traceback recorded)"), ""]

    return [f"{head} · {_summarise(event)}", ""]
