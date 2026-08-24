from __future__ import annotations

import sqlite3

import pytest

from amiweak.config import StateConfig
from amiweak.store import MemoryStore, ResilientStore, SqliteStore, StateStore, build_store


@pytest.fixture(params=["memory", "sqlite"])
def store(request: pytest.FixtureRequest, tmp_path) -> StateStore:  # type: ignore[no-untyped-def]
    if request.param == "memory":
        return MemoryStore()
    return SqliteStore(str(tmp_path / "state.db"), busy_timeout=5.0)


def test_incr_accumulates_per_label(store: StateStore) -> None:
    store.incr("verdicts_total", "leaked", 1)
    store.incr("verdicts_total", "leaked", 2)
    store.incr("verdicts_total", "safe", 5)

    counters = store.snapshot().counters
    assert counters["verdicts_total"] == {"leaked": 3, "safe": 5}


def test_unlabelled_counter_uses_empty_label(store: StateStore) -> None:
    store.incr("checks_total", "", 4)
    assert store.snapshot().counters["checks_total"] == {"": 4}


def test_observe_tracks_count_sum_and_max(store: StateStore) -> None:
    store.observe("hibp", 0.5)
    store.observe("hibp", 1.5)

    latency = store.snapshot().latency["hibp"]
    assert latency["count"] == 2
    assert latency["sum"] == pytest.approx(2.0)
    assert latency["max"] == pytest.approx(1.5)


def test_set_health_overwrites(store: StateStore) -> None:
    store.set_health("hibp", last_ok="2026-08-19T10:00:00Z", last_error=None)
    store.set_health("hibp", last_ok=None, last_error="timeout")

    assert store.snapshot().health["hibp"] == {"last_ok": None, "last_error": "timeout"}


def test_snapshot_of_empty_store_is_empty(store: StateStore) -> None:
    snapshot = store.snapshot()
    assert snapshot.counters == {}
    assert snapshot.latency == {}
    assert snapshot.health == {}


def test_spend_succeeds_until_capacity_is_exhausted(store: StateStore) -> None:
    # capacity 3, no refill within the test (now never advances)
    assert store.spend("1.2.3.4", 1, 3.0, 0.0, 100.0) is True
    assert store.spend("1.2.3.4", 1, 3.0, 0.0, 100.0) is True
    assert store.spend("1.2.3.4", 1, 3.0, 0.0, 100.0) is True
    assert store.spend("1.2.3.4", 1, 3.0, 0.0, 100.0) is False


def test_rejected_spend_costs_nothing(store: StateStore) -> None:
    assert store.spend("k", 5, 5.0, 0.0, 100.0) is True  # drains to 0
    assert store.spend("k", 3, 5.0, 0.0, 100.0) is False  # too expensive
    assert store.spend("k", 0.0001, 5.0, 0.0, 100.0) is False


def test_cost_above_capacity_can_never_pass(store: StateStore) -> None:
    assert store.spend("k", 11, 10.0, 1.0, 100.0) is False


def test_refill_is_capped_at_capacity(store: StateStore) -> None:
    assert store.spend("k", 10, 10.0, 1.0, 100.0) is True
    # 10_000 seconds later, refill would be 10_000 tokens; capacity is 10.
    assert store.spend("k", 10, 10.0, 1.0, 10_100.0) is True
    assert store.spend("k", 1, 10.0, 1.0, 10_100.0) is False


def test_buckets_are_independent_per_key(store: StateStore) -> None:
    assert store.spend("a", 2, 2.0, 0.0, 100.0) is True
    assert store.spend("b", 2, 2.0, 0.0, 100.0) is True
    assert store.spend("a", 1, 2.0, 0.0, 100.0) is False


def test_concurrent_spenders_never_exceed_capacity(store: StateStore) -> None:
    """The assertion that catches a lost update."""
    import threading

    granted = []
    lock = threading.Lock()

    def worker() -> None:
        for _ in range(50):
            if store.spend("shared", 1, 100.0, 0.0, 100.0):
                with lock:
                    granted.append(1)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(granted) == 100


def test_evict_buckets_is_scoped_to_its_namespace(store: StateStore) -> None:
    """A stale bucket in one namespace must not take down another namespace's
    bucket that is still within ITS OWN ttl, even though both would look
    stale under the evicting namespace's cutoff."""
    # Force the memory-store size guard to fire.
    for i in range(1100):
        store.spend(f"policy:filler{i}", 0.0, 10.0, 0.0, 0.0)

    store.spend("policy:1.2.3.4", 1, 10.0, 0.0, 0.0)  # last_seen = 0.0, stale
    store.spend("batch:1.2.3.4", 1, 10.0, 0.0, 500.0)  # last_seen = 500.0, fresh

    # A cutoff of 100 would treat both as "seen before 100" is false for
    # batch, but make sure only the policy namespace is touched.
    store.evict_buckets("policy", 100.0)

    # The evicted policy bucket resets to full capacity on next use.
    assert store.spend("policy:1.2.3.4", 10, 10.0, 0.0, 100.0) is True
    # The batch bucket, untouched, still reflects its earlier spend.
    assert store.spend("batch:1.2.3.4", 10, 10.0, 0.0, 500.0) is False


def test_evict_buckets_evicts_a_genuinely_stale_bucket_in_its_namespace(
    store: StateStore,
) -> None:
    for i in range(1100):
        store.spend(f"policy:filler{i}", 0.0, 10.0, 0.0, 0.0)

    store.spend("policy:9.9.9.9", 1, 10.0, 0.0, 0.0)  # last_seen = 0.0

    store.evict_buckets("policy", 100.0)

    # Evicted bucket is back at full capacity.
    assert store.spend("policy:9.9.9.9", 10, 10.0, 0.0, 100.0) is True


def test_sqlite_state_survives_reopen(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = str(tmp_path / "state.db")

    first = SqliteStore(path, busy_timeout=5.0)
    first.incr("checks_total", "", 7)
    first.close()

    second = SqliteStore(path, busy_timeout=5.0)
    assert second.snapshot().counters["checks_total"] == {"": 7}
    second.close()


def test_two_sqlite_stores_on_one_file_share_counters(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Two connections stand in for two gunicorn workers."""
    path = str(tmp_path / "state.db")
    worker_a = SqliteStore(path, busy_timeout=5.0)
    worker_b = SqliteStore(path, busy_timeout=5.0)

    worker_a.incr("checks_total", "", 3)
    worker_b.incr("checks_total", "", 4)

    assert worker_a.snapshot().counters["checks_total"] == {"": 7}
    assert worker_b.snapshot().counters["checks_total"] == {"": 7}

    worker_a.close()
    worker_b.close()


def test_two_sqlite_stores_share_one_allowance(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The bug this whole plan exists to fix, at store level."""
    path = str(tmp_path / "state.db")
    worker_a = SqliteStore(path, busy_timeout=5.0)
    worker_b = SqliteStore(path, busy_timeout=5.0)

    assert worker_a.spend("1.2.3.4", 1, 2.0, 0.0, 100.0) is True
    assert worker_b.spend("1.2.3.4", 1, 2.0, 0.0, 100.0) is True
    assert worker_a.spend("1.2.3.4", 1, 2.0, 0.0, 100.0) is False
    assert worker_b.spend("1.2.3.4", 1, 2.0, 0.0, 100.0) is False

    worker_a.close()
    worker_b.close()


class _BrokenStore:
    """Every operation raises, standing in for a wedged database."""

    def incr(self, name: str, label: str, amount: int) -> None:
        raise sqlite3.OperationalError("database is locked")

    def observe(self, name: str, seconds: float) -> None:
        raise sqlite3.OperationalError("database is locked")

    def set_health(self, name: str, last_ok: str | None, last_error: str | None) -> None:
        raise sqlite3.OperationalError("database is locked")

    def spend(self, key: str, cost: float, capacity: float, refill_rate: float, now: float) -> bool:
        raise sqlite3.OperationalError("database is locked")

    def evict_buckets(self, namespace: str, cutoff: float) -> None:
        raise sqlite3.OperationalError("database is locked")

    def snapshot(self):  # type: ignore[no-untyped-def]
        raise sqlite3.OperationalError("database is locked")

    def close(self) -> None:
        pass


def test_broken_primary_falls_back_and_still_counts() -> None:
    resilient = ResilientStore(_BrokenStore(), MemoryStore())
    resilient.incr("checks_total", "", 1)

    counters = resilient.snapshot().counters
    assert counters["checks_total"] == {"": 1}
    assert counters["store_errors_total"][""] >= 1


def test_broken_primary_still_rate_limits() -> None:
    """Fail-open means the fallback limiter, not no limiter."""
    resilient = ResilientStore(_BrokenStore(), MemoryStore())

    assert resilient.spend("k", 1, 2.0, 0.0, 100.0) is True
    assert resilient.spend("k", 1, 2.0, 0.0, 100.0) is True
    assert resilient.spend("k", 1, 2.0, 0.0, 100.0) is False


def test_healthy_primary_is_not_shadowed() -> None:
    primary, fallback = MemoryStore(), MemoryStore()
    resilient = ResilientStore(primary, fallback)
    resilient.incr("checks_total", "", 3)

    assert primary.snapshot().counters["checks_total"] == {"": 3}
    assert fallback.snapshot().counters == {}


def test_recovered_primary_health_is_not_shadowed_by_stale_fallback() -> None:
    """A fallback entry written during a single transient blip must not
    permanently shadow a primary that has since recovered and recorded a
    fresh, healthy entry for the same backend."""
    primary, fallback = MemoryStore(), MemoryStore()
    resilient = ResilientStore(primary, fallback)

    # Simulate: one write failed while the backend was down, landing in the
    # fallback...
    fallback.set_health("hibp", last_ok=None, last_error="timeout")
    # ...and the primary has since recovered and recorded a healthy check.
    primary.set_health("hibp", last_ok="2026-08-19T10:00:00Z", last_error=None)

    health = resilient.snapshot().health
    assert health["hibp"] == {"last_ok": "2026-08-19T10:00:00Z", "last_error": None}


def test_fallback_health_still_surfaces_when_primary_has_nothing() -> None:
    """If the primary never recorded anything for a backend (broken from the
    very first write), the fallback's entry should still surface."""
    primary, fallback = MemoryStore(), MemoryStore()
    resilient = ResilientStore(primary, fallback)

    fallback.set_health("hibp", last_ok=None, last_error="timeout")

    health = resilient.snapshot().health
    assert health["hibp"] == {"last_ok": None, "last_error": "timeout"}


class _BrokenCloseStore:
    """A store whose close() raises."""

    def incr(self, name: str, label: str, amount: int) -> None:
        pass

    def observe(self, name: str, seconds: float) -> None:
        pass

    def set_health(self, name: str, last_ok: str | None, last_error: str | None) -> None:
        pass

    def spend(self, key: str, cost: float, capacity: float, refill_rate: float, now: float) -> bool:
        return True

    def evict_buckets(self, namespace: str, cutoff: float) -> None:
        pass

    def snapshot(self):  # type: ignore[no-untyped-def]
        return None

    def close(self) -> None:
        raise sqlite3.OperationalError("close failed")


def test_resilient_close_does_not_raise_if_primary_fails() -> None:
    """Failing primary close must not prevent fallback close or propagate."""
    resilient = ResilientStore(_BrokenCloseStore(), MemoryStore())
    # This should not raise, even though primary.close() will raise
    resilient.close()


def test_build_store_without_a_path_is_in_memory() -> None:
    store = build_store(StateConfig(path=None, busy_timeout=5.0))
    assert isinstance(store, MemoryStore)
    store.close()


def test_build_store_with_a_path_is_resilient_sqlite(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = build_store(StateConfig(path=str(tmp_path / "s.db"), busy_timeout=5.0))
    assert isinstance(store, ResilientStore)
    store.incr("checks_total", "", 1)
    assert store.snapshot().counters["checks_total"] == {"": 1}
    store.close()


def test_broken_primary_observe_falls_back() -> None:
    resilient = ResilientStore(_BrokenStore(), MemoryStore())
    resilient.observe("check_seconds", 1.5)

    latency = resilient.snapshot().latency["check_seconds"]
    assert latency["count"] == 1.0
    assert resilient.snapshot().counters["store_errors_total"][""] >= 1


def test_broken_primary_set_health_falls_back() -> None:
    resilient = ResilientStore(_BrokenStore(), MemoryStore())
    resilient.set_health("hibp", last_ok="now", last_error=None)

    assert resilient.snapshot().health["hibp"] == {"last_ok": "now", "last_error": None}


def test_broken_primary_evict_buckets_falls_back_without_raising() -> None:
    resilient = ResilientStore(_BrokenStore(), MemoryStore())
    resilient.evict_buckets("policy", 0.0)  # must not raise


def test_snapshot_merges_latency_from_both_stores_for_the_same_name() -> None:
    primary, fallback = MemoryStore(), MemoryStore()
    resilient = ResilientStore(primary, fallback)
    primary.observe("check_seconds", 1.0)
    fallback.observe("check_seconds", 3.0)

    latency = resilient.snapshot().latency["check_seconds"]
    assert latency["count"] == 2.0
    assert latency["sum"] == 4.0
    assert latency["max"] == 3.0


def test_sqlite_schema_lock_timeout_is_a_runtime_error(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from filelock import Timeout

    import amiweak.store as store_module

    class _AlwaysTimesOut:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            raise Timeout("lockfile")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(store_module, "FileLock", _AlwaysTimesOut)
    with pytest.raises(RuntimeError, match="timed out"):
        SqliteStore(str(tmp_path / "s.db"), busy_timeout=5.0)


def test_sqlite_spend_rolls_back_and_reraises_on_a_broken_table(tmp_path) -> None:  # type: ignore[no-untyped-def]
    store = SqliteStore(str(tmp_path / "s.db"), busy_timeout=5.0)
    store._conn.execute("DROP TABLE buckets")
    with pytest.raises(sqlite3.OperationalError):
        store.spend("k", 1, 2.0, 0.0, 100.0)
    store.close()
