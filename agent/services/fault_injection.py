"""Synthetic failures, for exercising the orchestrator's retry path.

Read from ``config/stub_failure_rate`` (see :func:`agent.config.stub_failure_rate`)
and applied at the start of every stage, so a run with the rate set to 0.3
exercises retries, the three-strikes rule, and the critical/minor distinction of
§2.2.4 without anything actually being broken. README §10 is the procedure.

This was the one live function in ``workers/stub_worker.py``, a module whose
other 77 lines were canned artifacts for "the five stages that have no model
yet". All six stages have real workers now, so those went; a fault injector is
not a worker and this is where it belongs.
"""
from __future__ import annotations

import random


async def maybe_fail(probability: float = 0.0) -> None:
    """Raise with probability ``probability``. A no-op at the default 0.

    Deliberately a plain ``RuntimeError`` rather than ``WorkFailed``: the point
    is to simulate an *unanticipated* crash, which is the case the provider's
    catch-all and the orchestrator's retry logic exist to handle. A ``WorkFailed``
    would only test the path the workers already take on purpose.
    """
    if probability > 0 and random.random() < probability:
        raise RuntimeError("synthetic failure (config/stub_failure_rate)")
