from __future__ import annotations

import threading

from amiweak.rate_limit import TokenBucket
from amiweak.store import MemoryStore, SqliteStore


def _bucket(requests: int, per_seconds: int, store=None, namespace: str = "test"):  # type: ignore[no-untyped-def]
    return TokenBucket(
        requests=requests,
        per_seconds=per_seconds,
        store=store or MemoryStore(),
        namespace=namespace,
    )


def test_allows_up_to_capacity_then_refuses() -> None:
    bucket = _bucket(3, 60)
    assert bucket.allow("1.2.3.4") is True
    assert bucket.allow("1.2.3.4") is True
    assert bucket.allow("1.2.3.4") is True
    assert bucket.allow("1.2.3.4") is False


def test_rejected_request_spends_nothing() -> None:
    bucket = _bucket(5, 60)
    assert bucket.allow("k", cost=5) is True
    assert bucket.allow("k", cost=3) is False
    assert bucket.allow("k", cost=1) is False


def test_cost_above_capacity_never_passes() -> None:
    assert _bucket(10, 60).allow("k", cost=11) is False


def test_zero_cost_always_allowed() -> None:
    bucket = _bucket(1, 60)
    assert bucket.allow("k", cost=1) is True
    assert bucket.allow("k", cost=0) is True


def test_keys_are_independent() -> None:
    bucket = _bucket(1, 60)
    assert bucket.allow("a") is True
    assert bucket.allow("b") is True
    assert bucket.allow("a") is False


def test_namespaces_do_not_collide() -> None:
    """The interactive and batch limiters share a store, not an allowance."""
    store = MemoryStore()
    interactive = _bucket(1, 60, store=store, namespace="policy")
    batch = _bucket(1, 60, store=store, namespace="batch")

    assert interactive.allow("1.2.3.4") is True
    assert batch.allow("1.2.3.4") is True
    assert interactive.allow("1.2.3.4") is False


def test_two_buckets_on_one_sqlite_store_share_an_allowance(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The bug: two workers must not each get the full allowance."""
    path = str(tmp_path / "state.db")
    worker_a = _bucket(2, 60, store=SqliteStore(path, busy_timeout=5.0), namespace="policy")
    worker_b = _bucket(2, 60, store=SqliteStore(path, busy_timeout=5.0), namespace="policy")

    assert worker_a.allow("1.2.3.4") is True
    assert worker_b.allow("1.2.3.4") is True
    assert worker_a.allow("1.2.3.4") is False
    assert worker_b.allow("1.2.3.4") is False


def test_eviction_does_not_cross_namespaces() -> None:
    """Interactive's short idle TTL must not evict batch's still-live bucket.

    Interactive (per_seconds=60) has an idle TTL of 600s; batch
    (per_seconds=3600) has an idle TTL of 36000s. A batch bucket spent 700s
    ago is stale under interactive's TTL but very much alive under batch's
    own TTL. Interactive's `_maybe_evict` firing must not reset it.
    """
    import time

    store = MemoryStore()
    interactive = _bucket(1, 60, store=store, namespace="policy")
    batch = _bucket(1, 3600, store=store, namespace="batch")

    now = time.time()
    # Batch drains its one-token allowance 700 seconds ago.
    assert store.spend("batch:1.2.3.4", 1, batch._capacity, batch._refill_rate, now - 700) is True

    # MemoryStore only evicts once it holds >= 1024 buckets; pad it out so
    # the eviction this test triggers actually does something.
    for i in range(1100):
        store.spend(f"policy:filler{i}", 0.0, 10.0, 0.0, now - 700)

    # Force interactive's next eviction to fire right away, and have it
    # evict using its own (short) idle ttl relative to "now".
    interactive._next_eviction = 0.0

    real_time = time.time
    try:
        time.time = lambda: now  # type: ignore[assignment]
        interactive.allow("9.9.9.9")  # unrelated call, triggers _maybe_evict
    finally:
        time.time = real_time

    # The batch bucket, drained 700s ago (well within its 36000s ttl), must
    # still be drained -- not reset to full by interactive's eviction.
    assert batch.allow("1.2.3.4") is False


def test_concurrent_callers_never_exceed_capacity() -> None:
    bucket = _bucket(100, 3600)
    granted: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(50):
            if bucket.allow("shared"):
                with lock:
                    granted.append(1)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(granted) == 100
