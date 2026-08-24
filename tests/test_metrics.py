import pytest

from amiweak.metrics import Metrics
from amiweak.store import MemoryStore, SqliteStore


def test_counts_checks_and_verdicts():
    metrics = Metrics(MemoryStore())
    metrics.record_check("leaked")
    metrics.record_check("safe")
    metrics.record_check("leaked")
    snapshot = metrics.snapshot()
    assert snapshot["checks_total"] == 3
    assert snapshot["verdicts_total"]["leaked"] == 2
    assert snapshot["verdicts_total"]["safe"] == 1


def test_counts_backend_requests_and_errors():
    metrics = Metrics(MemoryStore())
    metrics.record_backend("hibp", ok=True, seconds=0.1, error=None)
    metrics.record_backend("hibp", ok=False, seconds=5.0, error="timeout")
    snapshot = metrics.snapshot()
    assert snapshot["backend_requests_total"]["hibp"] == 2
    assert snapshot["backend_errors_total"]["hibp"] == 1
    assert snapshot["backend_latency_seconds"]["hibp"]["count"] == 2
    assert snapshot["backend_latency_seconds"]["hibp"]["max"] == 5.0


def test_health_tracks_last_outcome_per_backend():
    metrics = Metrics(MemoryStore())
    metrics.record_backend("hibp", ok=True, seconds=0.1, error=None)
    metrics.record_backend("weakpass", ok=False, seconds=5.0, error="timeout")
    health = metrics.health()
    assert health["hibp"]["last_ok"] is not None
    assert health["hibp"]["last_error"] is None
    assert health["weakpass"]["last_error"] == "timeout"
    assert health["weakpass"]["last_ok"] is None


def test_a_recovery_clears_the_last_error():
    metrics = Metrics(MemoryStore())
    metrics.record_backend("hibp", ok=False, seconds=5.0, error="timeout")
    metrics.record_backend("hibp", ok=True, seconds=0.1, error=None)
    assert metrics.health()["hibp"]["last_error"] is None


def test_snapshot_is_json_serialisable():
    import json

    metrics = Metrics(MemoryStore())
    metrics.record_check("safe")
    metrics.record_backend("hibp", ok=True, seconds=0.1, error=None)
    assert json.loads(json.dumps(metrics.snapshot()))


def test_uptime_is_non_negative():
    assert Metrics(MemoryStore()).uptime_seconds() >= 0


def test_cache_hits_and_misses_are_counted_per_backend():
    metrics = Metrics(MemoryStore())
    metrics.record_cache("hibp", hit=True)
    metrics.record_cache("hibp", hit=False)
    metrics.record_cache("weakpass", hit=True)
    snapshot = metrics.snapshot()
    assert snapshot["cache_hits_total"] == {"hibp": 1, "weakpass": 1}
    assert snapshot["cache_misses_total"] == {"hibp": 1}


def test_batch_counters():
    metrics = Metrics(MemoryStore())
    metrics.record_batch(items=250)
    metrics.record_batch(items=10)
    snapshot = metrics.snapshot()
    assert snapshot["batch_requests_total"] == 2
    assert snapshot["batch_items_total"] == 260


def test_algorithm_dimension_is_nested_under_the_backend():
    metrics = Metrics(MemoryStore())
    metrics.record_algorithm("hibp", "ntlm")
    metrics.record_algorithm("hibp", "ntlm")
    metrics.record_algorithm("hibp", "sha1")
    assert metrics.snapshot()["backend_algorithm_total"] == {"hibp": {"ntlm": 2, "sha1": 1}}


def test_health_shape_is_unchanged_by_the_algorithm_counter():
    metrics = Metrics(MemoryStore())
    metrics.record_backend("hibp", ok=True, seconds=0.1, error=None)
    metrics.record_algorithm("hibp", "ntlm")
    assert set(metrics.health()) == {"hibp"}


def test_snapshot_shape_is_unchanged() -> None:
    metrics = Metrics(MemoryStore())
    metrics.record_check("leaked")
    metrics.record_backend("hibp", ok=True, seconds=0.25, error=None)
    metrics.record_cache("hibp", hit=True)
    metrics.record_batch(10)
    metrics.record_algorithm("hibp", "ntlm")

    snapshot = metrics.snapshot()
    assert snapshot["checks_total"] == 1
    assert snapshot["verdicts_total"] == {"leaked": 1}
    assert snapshot["backend_requests_total"] == {"hibp": 1}
    assert snapshot["backend_errors_total"] == {}
    assert snapshot["backend_latency_seconds"]["hibp"]["count"] == 1
    assert snapshot["backend_latency_seconds"]["hibp"]["sum"] == pytest.approx(0.25)
    assert snapshot["backend_latency_seconds"]["hibp"]["max"] == pytest.approx(0.25)
    assert snapshot["cache_hits_total"] == {"hibp": 1}
    assert snapshot["batch_requests_total"] == 1
    assert snapshot["batch_items_total"] == 10
    assert snapshot["backend_algorithm_total"] == {"hibp": {"ntlm": 1}}
    assert "uptime_seconds" in snapshot


def test_health_records_last_ok_and_last_error() -> None:
    metrics = Metrics(MemoryStore())
    metrics.record_backend("hibp", ok=True, seconds=0.1, error=None)
    assert metrics.health()["hibp"]["last_ok"] is not None
    assert metrics.health()["hibp"]["last_error"] is None

    metrics.record_backend("hibp", ok=False, seconds=0.1, error="timeout")
    assert metrics.health()["hibp"]["last_error"] == "timeout"


def test_two_metrics_on_one_sqlite_store_report_one_total(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The bug: a scrape must not see one worker's quarter of the traffic."""
    path = str(tmp_path / "state.db")
    worker_a = Metrics(SqliteStore(path, busy_timeout=5.0))
    worker_b = Metrics(SqliteStore(path, busy_timeout=5.0))

    worker_a.record_check("safe")
    worker_a.record_check("leaked")
    worker_b.record_check("safe")

    for metrics in (worker_a, worker_b):
        snapshot = metrics.snapshot()
        assert snapshot["checks_total"] == 3
        assert snapshot["verdicts_total"] == {"safe": 2, "leaked": 1}


def test_uptime_is_process_local(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Documented limitation, asserted so it is a decision and not a bug."""
    path = str(tmp_path / "state.db")
    Metrics(SqliteStore(path, busy_timeout=5.0))
    fresh = Metrics(SqliteStore(path, busy_timeout=5.0))
    assert fresh.uptime_seconds() < 1.0
