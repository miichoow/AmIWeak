"""A token bucket, keyed by client address, over a pluggable state store.

With a MemoryStore this is per-process and the effective allowance across
several gunicorn workers is roughly `requests` times the worker count -- the
behaviour this application shipped with. With a shared store the allowance is
what the configuration says it is.

The clock is wall clock, not monotonic. A monotonic reading has no shared epoch
across processes, so a value one worker writes means nothing to another. The
trade is that a clock step backwards briefly grants extra allowance; for a
limiter that exists to stop casual hammering rather than a determined attacker,
that is a trade worth making.
"""

from __future__ import annotations

import time

from amiweak.store import StateStore

EVICTION_INTERVAL_SECONDS = 60.0


class TokenBucket:
    def __init__(
        self,
        requests: int,
        per_seconds: int,
        store: StateStore,
        namespace: str,
    ) -> None:
        self._capacity = float(requests)
        self._refill_rate = requests / per_seconds
        self._idle_ttl = per_seconds * 10
        self._store = store
        self._namespace = namespace
        self._next_eviction = 0.0

    def allow(self, key: str, cost: int = 1) -> bool:
        """Spend `cost` tokens for `key`, returning False when too few remain.

        All-or-nothing: a rejected request spends nothing, so a batch that is
        too expensive right now can be retried whole rather than half-charged.
        A cost above capacity can never pass, which is why the batch bucket is
        sized against `batch.max_items` rather than against request count.
        """
        if cost <= 0:
            return True
        now = time.time()
        self._maybe_evict(now)
        return self._store.spend(
            f"{self._namespace}:{key}",
            float(cost),
            self._capacity,
            self._refill_rate,
            now,
        )

    def _maybe_evict(self, now: float) -> None:
        """Drop buckets nobody has touched, so the table cannot grow unbounded.

        Rate-limited rather than run per request: on a shared store this is a
        DELETE, and issuing one on every check would put write traffic on the
        hot path for no benefit.
        """
        if now < self._next_eviction:
            return
        self._next_eviction = now + EVICTION_INTERVAL_SECONDS
        self._store.evict_buckets(self._namespace, now - self._idle_ttl)
