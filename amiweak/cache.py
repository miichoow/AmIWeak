"""An LRU cache of parsed upstream ranges, keyed by prefix.

A range covers roughly 2000 hashes and changes only when a provider loads new
data, so caching it turns a repeated audit into almost no network traffic. The
key is `(backend, algorithm, prefix)` — all three public, all three already sent
upstream — so nothing here is more sensitive than the request that filled it.

Memory is the operational cost: each entry is a few hundred kilobytes, so the
default bound of 256 entries is roughly 40-60 MB per worker process. Raising it
multiplies by the worker count.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

from amiweak.checks.base import RangeData
from amiweak.config import CacheConfig

#: (backend name, algorithm, prefix)
CacheKey = tuple[str, str, str]


class PrefixCache:
    """Thread-safe, bounded, TTL'd cache of parsed ranges."""

    def __init__(self, config: CacheConfig) -> None:
        self._enabled = config.enabled
        self._max_entries = config.max_entries
        self._ttl = config.ttl_seconds
        self._lock = threading.Lock()
        self._entries: OrderedDict[CacheKey, tuple[RangeData, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    def get(self, key: CacheKey) -> RangeData | None:
        """Return a live entry and mark it most-recently-used, or None."""
        if not self._enabled:
            return None
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._misses += 1
                return None
            data, expires_at = entry
            if expires_at <= now:
                del self._entries[key]
                self._misses += 1
                return None
            self._entries.move_to_end(key)
            self._hits += 1
            return data

    def contains(self, key: CacheKey) -> bool:
        """Whether a live entry exists, without counting a hit or reordering.

        Used to decide what a batch owes the rate limiter, which must not be
        distorted by the accounting it triggers.
        """
        if not self._enabled:
            return False
        now = time.monotonic()
        with self._lock:
            entry = self._entries.get(key)
            return entry is not None and entry[1] > now

    def put(self, key: CacheKey, data: RangeData) -> None:
        if not self._enabled:
            return
        expires_at = time.monotonic() + self._ttl
        with self._lock:
            self._entries[key] = (data, expires_at)
            self._entries.move_to_end(key)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"hits": self._hits, "misses": self._misses, "entries": len(self._entries)}
