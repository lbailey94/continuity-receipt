"""CPR Trace & State Shrinking Engine (cpr-trace-shrink).
Finds the minimal subset of files or event sequence that reproduces a semantic predicate violation.
"""
from __future__ import annotations

def shrink_counterexample(captured: dict[str, bytes], predicate) -> dict[str, bytes]:
    """Greedy delta-debugging shrinking over a dictionary of captured files/state."""
    keys = list(captured.keys())
    if len(keys) <= 1:
        return captured

    minimal = dict(captured)

    # 1. Try single keys: is one single file alone sufficient to fail the predicate?
    for k in keys:
        trial = {k: captured[k]}
        try:
            res = predicate(trial)
            ok = res[0] if isinstance(res, tuple) else bool(res)
            if not ok:
                return trial
        except Exception:
            return trial

    # 2. Try 1-deletion (removing one key at a time)
    for k in keys:
        trial = {x: captured[x] for x in keys if x != k}
        try:
            res = predicate(trial)
            ok = res[0] if isinstance(res, tuple) else bool(res)
            if not ok:
                minimal = trial
        except Exception:
            minimal = trial

    return minimal

def shrink_trace(events: list[dict], predicate) -> list[dict]:
    """Greedy binary-search / delta-debugging over an ordered event stream."""
    if len(events) <= 1:
        return events

    # 1. Binary search for minimal failing prefix
    low, high = 1, len(events)
    failing_prefix = events
    while low <= high:
        mid = (low + high) // 2
        prefix = events[:mid]
        try:
            res = predicate(prefix)
            ok = res[0] if isinstance(res, tuple) else bool(res)
        except Exception:
            ok = False

        if not ok:
            failing_prefix = prefix
            high = mid - 1
        else:
            low = mid + 1

    # 2. Try removing intermediate events from the failing prefix (1-omission)
    shrunk = list(failing_prefix)
    i = 0
    while i < len(shrunk):
        candidate = shrunk[:i] + shrunk[i + 1:]
        if not candidate:
            break
        try:
            res = predicate(candidate)
            ok = res[0] if isinstance(res, tuple) else bool(res)
        except Exception:
            ok = False

        if not ok:
            shrunk = candidate
        else:
            i += 1

    return shrunk
