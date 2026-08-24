"""Counters for /metrics and /healthz, over a pluggable state store.

Everything here is deliberately unlabelled by anything user-supplied. The only
strings that become keys are the fixed verdict names, the fixed backend names,
and the fixed algorithm names, so no counter can ever be a side channel for a
password or a hash.

With a MemoryStore the numbers are per worker process and a scrape sees one
worker's view. With a shared store they are the whole deployment's. Uptime is
per-process either way -- see `uptime_seconds`.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from amiweak.store import StateStore

#: Backend and algorithm are both fixed identifiers containing no colon, so a
#: composite label splits unambiguously on the first one.
ALGORITHM_LABEL_SEPARATOR = ":"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


class Metrics:
    """Counters shared by every request handler, and possibly every worker."""

    def __init__(self, store: StateStore) -> None:
        self._store = store
        self._started = time.monotonic()

    def record_check(self, verdict: str) -> None:
        self._store.incr("checks_total", "", 1)
        self._store.incr("verdicts_total", verdict, 1)

    def record_backend(self, name: str, ok: bool, seconds: float, error: str | None) -> None:
        self._store.incr("backend_requests_total", name, 1)
        if not ok:
            self._store.incr("backend_errors_total", name, 1)
        self._store.observe(name, seconds)
        if ok:
            self._store.set_health(name, last_ok=_now_iso(), last_error=None)
        else:
            # Preserves last_ok across a failure, matching the behaviour /healthz
            # already reports. The snapshot read is the expensive part on a
            # shared store, and it is deliberately on the error path only --
            # backend failures are rare, and a check that is already failing can
            # afford one extra query.
            existing = self._store.snapshot().health.get(name, {})
            self._store.set_health(name, last_ok=existing.get("last_ok"), last_error=error)

    def record_cache(self, name: str, hit: bool) -> None:
        self._store.incr("cache_hits_total" if hit else "cache_misses_total", name, 1)

    def record_batch(self, items: int) -> None:
        self._store.incr("batch_requests_total", "", 1)
        self._store.incr("batch_items_total", "", items)

    def record_algorithm(self, name: str, algorithm: str) -> None:
        """Counted separately from backend_requests_total, whose key shape
        /healthz depends on."""
        self._store.incr(
            "backend_algorithm_total", f"{name}{ALGORITHM_LABEL_SEPARATOR}{algorithm}", 1
        )

    def uptime_seconds(self) -> float:
        """Per-process, always.

        A shared store cannot distinguish "this row belongs to the run that
        started twenty seconds ago" from "this row is left over from last week"
        without a boot marker, and the process that would write one differs
        between gunicorn's master and run.py. A per-worker uptime is correct and
        slightly less useful; a stored one would be subtly wrong.
        """
        return round(time.monotonic() - self._started, 3)

    def health(self) -> dict[str, dict[str, Any]]:
        return {name: dict(state) for name, state in self._store.snapshot().health.items()}

    def snapshot(self) -> dict[str, Any]:
        state = self._store.snapshot()
        counters = state.counters

        def scalar(name: str) -> int:
            return counters.get(name, {}).get("", 0)

        def labelled(name: str) -> dict[str, int]:
            return dict(counters.get(name, {}))

        algorithms: dict[str, dict[str, int]] = {}
        for label, value in counters.get("backend_algorithm_total", {}).items():
            backend, _, algorithm = label.partition(ALGORITHM_LABEL_SEPARATOR)
            algorithms.setdefault(backend, {})[algorithm] = value

        return {
            "uptime_seconds": self.uptime_seconds(),
            "checks_total": scalar("checks_total"),
            "verdicts_total": labelled("verdicts_total"),
            "backend_requests_total": labelled("backend_requests_total"),
            "backend_errors_total": labelled("backend_errors_total"),
            "backend_latency_seconds": {
                name: {
                    "count": int(entry["count"]),
                    "sum": round(entry["sum"], 4),
                    "max": round(entry["max"], 4),
                }
                for name, entry in state.latency.items()
            },
            "cache_hits_total": labelled("cache_hits_total"),
            "cache_misses_total": labelled("cache_misses_total"),
            "batch_requests_total": scalar("batch_requests_total"),
            "batch_items_total": scalar("batch_items_total"),
            "backend_algorithm_total": algorithms,
            "store_errors_total": scalar("store_errors_total"),
        }
