import threading

from amiweak.cache import PrefixCache
from amiweak.config import CacheConfig

KEY = ("hibp", "sha1", "ABCDE")
OTHER = ("hibp", "ntlm", "ABCDE")


def cache(max_entries=4, ttl_seconds=60.0, enabled=True):
    return PrefixCache(
        CacheConfig(enabled=enabled, max_entries=max_entries, ttl_seconds=ttl_seconds)
    )


def test_a_miss_returns_none():
    assert cache().get(KEY) is None


def test_a_stored_range_comes_back():
    instance = cache()
    instance.put(KEY, {"AAA": 1})
    assert instance.get(KEY) == {"AAA": 1}


def test_the_algorithm_is_part_of_the_key():
    instance = cache()
    instance.put(KEY, {"AAA": 1})
    assert instance.get(OTHER) is None


def test_contains_does_not_count_as_a_hit():
    instance = cache()
    instance.put(KEY, {"AAA": 1})
    assert instance.contains(KEY) is True
    assert instance.stats()["hits"] == 0


def test_entries_expire_after_the_ttl(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr("amiweak.cache.time.monotonic", lambda: clock[0])
    instance = cache(ttl_seconds=10.0)
    instance.put(KEY, {"AAA": 1})
    clock[0] += 9.0
    assert instance.get(KEY) == {"AAA": 1}
    clock[0] += 2.0
    assert instance.get(KEY) is None


def test_the_least_recently_used_entry_is_evicted_at_the_bound():
    instance = cache(max_entries=2)
    instance.put(("a", "sha1", "1"), {})
    instance.put(("b", "sha1", "2"), {})
    instance.get(("a", "sha1", "1"))  # 'a' is now the most recent
    instance.put(("c", "sha1", "3"), {})  # evicts 'b'
    assert instance.get(("a", "sha1", "1")) == {}
    assert instance.get(("b", "sha1", "2")) is None


def test_hits_and_misses_are_counted():
    instance = cache()
    instance.get(KEY)
    instance.put(KEY, {})
    instance.get(KEY)
    assert instance.stats() == {"hits": 1, "misses": 1, "entries": 1}


def test_a_disabled_cache_stores_nothing():
    instance = cache(enabled=False)
    instance.put(KEY, {"AAA": 1})
    assert instance.get(KEY) is None
    assert instance.contains(KEY) is False


def test_concurrent_access_is_safe():
    instance = cache(max_entries=64)
    errors = []

    def hammer(n):
        try:
            for i in range(500):
                key = ("hibp", "sha1", str((n + i) % 128))
                if instance.get(key) is None:
                    instance.put(key, {"AAA": i})
        except Exception as exc:  # pragma: no cover - only fires on a real race
            errors.append(exc)

    threads = [threading.Thread(target=hammer, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert instance.stats()["entries"] <= 64
