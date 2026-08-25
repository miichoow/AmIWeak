import time

import pytest

from amiweak.algorithms import Algorithm
from amiweak.cache import PrefixCache
from amiweak.checks.base import CheckResult, RangeChecker, RangeFetch
from amiweak.checks.runner import BatchItem, CheckRunner, Verdict
from amiweak.config import CacheConfig, load_config
from amiweak.hashing import sha1_hex
from amiweak.strength import ScoreResult

LONG_ENOUGH = "correcthorsebattery"


class FakeChecker(RangeChecker):
    """A RangeChecker double: `hit`/`count` drive `lookup`, `error` makes
    `fetch` fail outright, and `delay` stalls `fetch` for deadline tests."""

    def __init__(self, name, hit=False, count=None, error=None, delay=0.0, algorithms=None):
        self.name = name
        self._hit = hit
        self._count = count
        self._error = error
        self._delay = delay
        # None means "supports everything", which is what every existing test wants.
        self._algorithms = algorithms

    def supports(self, algorithm):
        return self._algorithms is None or algorithm in self._algorithms

    def prefix_of(self, digest, algorithm):
        return digest[:5]

    def fetch(self, prefix, algorithm):
        if self._delay:
            time.sleep(self._delay)
        if self._error is not None:
            return RangeFetch(None, self._error)
        return RangeFetch({}, None)

    def lookup(self, data, digest):
        return CheckResult(self.name, True, self._hit, self._count, None)


@pytest.fixture
def config():
    return load_config(None, env={})


def config_from(tmp_path, text):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return load_config(path, env={})


def run(checkers, config, password=LONG_ENOUGH):
    return CheckRunner(checkers, config).evaluate(password)


def test_all_clear_is_safe(config):
    result = run([FakeChecker("hibp"), FakeChecker("weakpass")], config)
    assert result.verdict is Verdict.SAFE
    assert result.degraded is False


def test_hibp_hit_is_leaked(config):
    assert run([FakeChecker("hibp", hit=True)], config).verdict is Verdict.LEAKED


def test_weakpass_hit_is_precomputed(config):
    assert run([FakeChecker("weakpass", hit=True)], config).verdict is Verdict.PRECOMPUTED


def test_leaked_wins_over_precomputed(config):
    checkers = [FakeChecker("hibp", hit=True), FakeChecker("weakpass", hit=True)]
    assert run(checkers, config).verdict is Verdict.LEAKED


def test_breach_count_is_carried_through(config):
    result = run([FakeChecker("hibp", hit=True, count=42)], config)
    assert next(r for r in result.results if r.name == "hibp").count == 42


def test_short_password_short_circuits_without_calling_checkers(config):
    called = []

    class Spy(FakeChecker):
        def fetch(self, prefix, algorithm):
            called.append(prefix)
            return super().fetch(prefix, algorithm)

    result = CheckRunner([Spy("hibp", hit=True)], config).evaluate("abc")
    assert result.verdict is Verdict.TOO_SHORT
    assert called == []


def test_fail_open_yields_degraded_safe(config):
    checkers = [FakeChecker("hibp", hit=None, error="timeout"), FakeChecker("weakpass")]
    result = run(checkers, config)
    assert result.verdict is Verdict.SAFE
    assert result.degraded is True


def test_fail_open_still_reports_a_hit_from_the_other_check(config):
    checkers = [
        FakeChecker("hibp", hit=None, error="timeout"),
        FakeChecker("weakpass", hit=True),
    ]
    result = run(checkers, config)
    assert result.verdict is Verdict.PRECOMPUTED
    assert result.degraded is True


def test_fail_closed_yields_error(tmp_path):
    config = config_from(tmp_path, "checks:\n  hibp:\n    on_error: fail_closed\n")
    checkers = [FakeChecker("hibp", hit=None, error="timeout"), FakeChecker("weakpass")]
    assert CheckRunner(checkers, config).evaluate(LONG_ENOUGH).verdict is Verdict.ERROR


def test_fail_closed_on_a_healthy_check_is_not_an_error(tmp_path):
    config = config_from(tmp_path, "checks:\n  hibp:\n    on_error: fail_closed\n")
    checkers = [FakeChecker("hibp"), FakeChecker("weakpass", hit=None, error="timeout")]
    assert CheckRunner(checkers, config).evaluate(LONG_ENOUGH).verdict is Verdict.SAFE


def test_results_are_returned_in_configured_order(config):
    result = run([FakeChecker("weakpass"), FakeChecker("hibp")], config)
    assert [r.name for r in result.results] == ["hibp", "weakpass", "denylist"]


def test_checks_run_concurrently(config):
    checkers = [FakeChecker("hibp", delay=0.4), FakeChecker("weakpass", delay=0.4)]
    started = time.monotonic()
    run(checkers, config)
    assert time.monotonic() - started < 0.7


def test_overall_deadline_marks_slow_check_as_timeout(tmp_path):
    config = config_from(tmp_path, "policy:\n  overall_deadline: 0.2\n")
    checkers = [FakeChecker("hibp", delay=2.0), FakeChecker("weakpass")]
    result = CheckRunner(checkers, config).evaluate(LONG_ENOUGH)
    hibp = next(r for r in result.results if r.name == "hibp")
    assert hibp.hit is None
    assert hibp.error == "timeout"
    assert result.degraded is True


def test_deadline_returns_without_waiting_for_the_slow_check(tmp_path):
    config = config_from(tmp_path, "policy:\n  overall_deadline: 0.2\n")
    checkers = [FakeChecker("hibp", delay=3.0), FakeChecker("weakpass")]
    started = time.monotonic()
    CheckRunner(checkers, config).evaluate(LONG_ENOUGH)
    assert time.monotonic() - started < 1.0


def test_checker_raising_is_contained(config):
    class Exploding(RangeChecker):
        name = "hibp"

        def supports(self, algorithm):
            return True

        def prefix_of(self, digest, algorithm):
            return digest[:5]

        def fetch(self, prefix, algorithm):
            raise RuntimeError("boom")

        def lookup(self, data, digest):
            raise AssertionError("unreachable: fetch always raises first")

    result = run([Exploding(), FakeChecker("weakpass")], config)
    assert result.verdict is Verdict.SAFE
    assert result.degraded is True
    assert next(r for r in result.results if r.name == "hibp").error == "internal"


def test_disabled_checks_appear_as_disabled_entries(tmp_path):
    config = config_from(tmp_path, "checks:\n  hibp:\n    enabled: false\n")
    result = CheckRunner([FakeChecker("weakpass")], config).evaluate(LONG_ENOUGH)
    entries = {r.name: r for r in result.results}
    assert entries["hibp"].enabled is False
    assert entries["hibp"].hit is None
    assert result.degraded is False


def test_no_checkers_at_all_still_yields_a_verdict(config):
    result = run([], config)
    assert result.verdict is Verdict.SAFE
    assert [r.name for r in result.results] == ["hibp", "weakpass", "denylist"]


def test_checkers_receive_the_hash_not_the_password(config):
    from amiweak.hashing import sha1_hex

    password = "SuperSecret!Passphrase42"
    seen = []

    class Spy(FakeChecker):
        def lookup(self, data, digest):
            seen.append(digest)
            return super().lookup(data, digest)

    run([Spy("hibp")], config, password=password)
    assert seen == [sha1_hex(password)]


def test_metrics_are_recorded_when_supplied(config):
    from amiweak.metrics import Metrics
    from amiweak.store import MemoryStore

    metrics = Metrics(MemoryStore())
    CheckRunner([FakeChecker("hibp")], config, metrics=metrics).evaluate(LONG_ENOUGH)
    snapshot = metrics.snapshot()
    assert snapshot["checks_total"] == 1
    assert snapshot["verdicts_total"]["safe"] == 1
    assert snapshot["backend_requests_total"]["hibp"] == 1


class CountingChecker(RangeChecker):
    def __init__(self, name, hits=(), supported=(Algorithm.SHA1, Algorithm.NTLM), error=None):
        self.name = name
        self._hits = set(hits)
        self._supported = supported
        self._error = error
        self.fetched = []

    def supports(self, algorithm):
        return algorithm in self._supported

    def prefix_of(self, digest, algorithm):
        return digest[:5]

    def fetch(self, prefix, algorithm):
        self.fetched.append(prefix)
        if self._error:
            return RangeFetch(None, self._error)
        return RangeFetch({h: None for h in self._hits if h.startswith(prefix)}, None)

    def lookup(self, data, digest):
        return CheckResult(self.name, True, digest in data, None, None)


def item(label, digest):
    return BatchItem(label=label, digest=digest)


def cache():
    return PrefixCache(CacheConfig(enabled=True, max_entries=64, ttl_seconds=60.0))


A = "aaaaa" + "1" * 27
B = "aaaaa" + "2" * 27
C = "bbbbb" + "3" * 27


def test_items_sharing_a_prefix_cause_one_fetch(config):
    checker = CountingChecker("hibp", hits=[A])
    runner = CheckRunner([checker], config, cache=cache())
    runner.evaluate_batch([item("x", A), item("y", B)], Algorithm.NTLM)
    assert checker.fetched == ["aaaaa"], "two items, one prefix, one fetch"


def test_distinct_prefixes_each_fetch_once(config):
    checker = CountingChecker("hibp")
    runner = CheckRunner([checker], config, cache=cache())
    runner.evaluate_batch([item("x", A), item("y", C)], Algorithm.NTLM)
    assert sorted(checker.fetched) == ["aaaaa", "bbbbb"]


def test_labels_are_echoed_and_verdicts_resolved(config):
    checker = CountingChecker("hibp", hits=[A])
    runner = CheckRunner([checker], config, cache=cache())
    outcomes = runner.evaluate_batch([item("x", A), item("y", B)], Algorithm.NTLM)
    by_label = {o.label: o.evaluation.verdict for o in outcomes}
    assert by_label == {"x": Verdict.LEAKED, "y": Verdict.SAFE}


def test_a_second_batch_is_served_from_the_cache(config):
    checker = CountingChecker("hibp", hits=[A])
    runner = CheckRunner([checker], config, cache=cache())
    runner.evaluate_batch([item("x", A)], Algorithm.NTLM)
    runner.evaluate_batch([item("x", A)], Algorithm.NTLM)
    assert checker.fetched == ["aaaaa"], "the second batch must not refetch"


def test_a_backend_that_cannot_do_the_algorithm_is_not_degraded(config):
    checker = CountingChecker("hibp", supported=(Algorithm.SHA1,))
    runner = CheckRunner([checker], config, cache=cache())
    outcome = runner.evaluate_batch([item("x", A)], Algorithm.NTLM)[0]
    assert checker.fetched == []
    assert outcome.evaluation.degraded is False
    assert outcome.evaluation.results[0].applicable is False


def test_a_failing_fetch_degrades_every_item_that_needed_it(config):
    checker = CountingChecker("hibp", error="timeout")
    runner = CheckRunner([checker], config, cache=cache())
    outcomes = runner.evaluate_batch([item("x", A), item("y", C)], Algorithm.NTLM)
    assert all(o.evaluation.degraded for o in outcomes)
    assert all(o.evaluation.results[0].error == "timeout" for o in outcomes)


def test_a_failed_fetch_is_not_cached(config):
    checker = CountingChecker("hibp", error="timeout")
    runner = CheckRunner([checker], config, cache=cache())
    runner.evaluate_batch([item("x", A)], Algorithm.NTLM)
    runner.evaluate_batch([item("x", A)], Algorithm.NTLM)
    assert checker.fetched == ["aaaaa", "aaaaa"], "an error must be retried"


def test_prefix_cost_counts_unique_uncached_prefixes(config):
    checker = CountingChecker("hibp")
    instance = cache()
    runner = CheckRunner([checker], config, cache=instance)
    items = [item("x", A), item("y", B), item("z", C)]
    assert runner.prefix_cost(items, Algorithm.NTLM) == 2
    runner.evaluate_batch(items, Algorithm.NTLM)
    assert runner.prefix_cost(items, Algorithm.NTLM) == 0


def test_prefix_cost_ignores_backends_that_cannot_answer(config):
    checker = CountingChecker("hibp", supported=(Algorithm.SHA1,))
    runner = CheckRunner([checker], config, cache=cache())
    assert runner.prefix_cost([item("x", A)], Algorithm.NTLM) == 0


def test_prefix_cost_without_a_cache_counts_every_cacheable_prefix(config):
    checker = CountingChecker("hibp")
    runner = CheckRunner([checker], config)
    items = [item("x", A), item("y", C), item("z", A)]
    assert runner.prefix_cost(items, Algorithm.NTLM) == 2


def test_an_empty_batch_is_an_empty_result(config):
    runner = CheckRunner([CountingChecker("hibp")], config, cache=cache())
    assert runner.evaluate_batch([], Algorithm.NTLM) == []


def test_the_single_check_path_uses_the_cache(config, monkeypatch):
    checker = CountingChecker("hibp")
    runner = CheckRunner([checker], config, cache=cache())
    monkeypatch.setattr("amiweak.checks.runner.sha1_hex", lambda password: A)
    runner.evaluate("a-long-enough-password")
    runner.evaluate("a-long-enough-password")
    assert checker.fetched == ["aaaaa"], "the second check must not refetch"


def test_the_single_check_path_still_uses_the_policy_deadline(config):
    """A single check must not wait out batch.deadline, which is 120s."""
    captured = {}
    checker = CountingChecker("hibp")
    runner = CheckRunner([checker], config, cache=cache())
    original = runner._fetch_plan

    def spy(plan, algorithm, deadline, max_workers):
        captured["deadline"] = deadline
        return original(plan, algorithm, deadline, max_workers)

    runner._fetch_plan = spy  # type: ignore[method-assign]
    runner.evaluate("a-long-enough-password")
    assert captured["deadline"] == config.policy.overall_deadline


def test_a_short_password_still_short_circuits(config):
    checker = CountingChecker("hibp")
    runner = CheckRunner([checker], config, cache=cache())
    outcome = runner.evaluate("short")
    assert outcome.verdict == Verdict.TOO_SHORT
    assert checker.fetched == [], "no network for a password we already reject"


class VaryingDelayChecker(RangeChecker):
    """A fetch that sleeps a different amount per prefix, to prove latency is
    recorded per-fetch rather than as the whole fan-out's duration."""

    def __init__(self, name, delays):
        self.name = name
        self._delays = delays

    def supports(self, algorithm):
        return True

    def prefix_of(self, digest, algorithm):
        return digest[:5]

    def fetch(self, prefix, algorithm):
        time.sleep(self._delays[prefix])
        return RangeFetch({}, None)

    def lookup(self, data, digest):
        return CheckResult(self.name, True, False, None, None)


def test_backend_latency_is_recorded_per_fetch_not_per_fan_out(config):
    from amiweak.metrics import Metrics
    from amiweak.store import MemoryStore

    # "aaaaa" sleeps briefly, "bbbbb" sleeps much longer. If latency were
    # still measured against the shared fan-out start, both fetches would
    # report roughly the same (long) elapsed time.
    checker = VaryingDelayChecker("hibp", delays={"aaaaa": 0.05, "bbbbb": 0.4})
    metrics = Metrics(MemoryStore())
    runner = CheckRunner([checker], config, metrics=metrics, cache=cache())
    fast = "aaaaa" + "1" * 27
    slow = "bbbbb" + "2" * 27
    runner.evaluate_batch([item("x", fast), item("y", slow)], Algorithm.NTLM)
    bucket = metrics.snapshot()["backend_latency_seconds"]["hibp"]
    # The slowest single fetch is ~0.4s; if latency were fan-out-relative both
    # samples would be pinned near the same (larger) value and max would sit
    # well above what any individual fetch actually took.
    assert bucket["max"] < 0.6
    assert bucket["count"] == 2


def test_a_batch_timeout_records_one_backend_error_per_backend(tmp_path):
    from amiweak.metrics import Metrics
    from amiweak.store import MemoryStore

    config = config_from(tmp_path, "batch:\n  deadline: 0.1\n")
    checker = VaryingDelayChecker("hibp", delays={f"{n:05d}": 1.0 for n in range(10)})
    metrics = Metrics(MemoryStore())
    runner = CheckRunner([checker], config, metrics=metrics, cache=cache())
    items = [item(str(n), f"{n:05d}" + "1" * 27) for n in range(10)]
    outcomes = runner.evaluate_batch(items, Algorithm.NTLM)
    assert all(o.evaluation.results[0].error == "timeout" for o in outcomes)
    snapshot = metrics.snapshot()
    # Ten distinct prefixes all timed out on the same backend, but only one
    # ERROR_TIMEOUT record should have been written for it, not ten -- writing
    # ten would flip /healthz to degraded and keep it there long after the
    # slow batch that caused it.
    assert snapshot["backend_errors_total"]["hibp"] == 1
    assert snapshot["backend_requests_total"]["hibp"] == 1


def test_evaluate_digest_resolves_a_hit(config):
    runner = CheckRunner([FakeChecker("hibp", hit=True)], config)
    result = runner.evaluate_digest("a" * 40, Algorithm.SHA1)
    assert result.verdict is Verdict.LEAKED


def test_evaluate_digest_resolves_a_miss(config):
    runner = CheckRunner([FakeChecker("hibp"), FakeChecker("weakpass")], config)
    assert runner.evaluate_digest("a" * 40, Algorithm.SHA1).verdict is Verdict.SAFE


def test_evaluate_digest_carries_the_algorithm_to_the_checkers(config):
    """NTLM must reach fetch(), or the endpoint would silently query SHA-1 ranges."""
    seen = []

    class Recording(FakeChecker):
        def fetch(self, prefix, algorithm):
            seen.append(algorithm)
            return RangeFetch({}, None)

    CheckRunner([Recording("hibp")], config).evaluate_digest("b" * 32, Algorithm.NTLM)
    assert seen == [Algorithm.NTLM]


def test_evaluate_digest_never_returns_too_short(config):
    """A digest carries no length, so the min_length gate cannot apply here."""
    runner = CheckRunner([FakeChecker("hibp")], config)
    short = sha1_hex("a")
    assert runner.evaluate_digest(short, Algorithm.SHA1).verdict is not Verdict.TOO_SHORT


def test_evaluate_still_gates_on_min_length(config):
    """The refactor must not move the plaintext length check."""
    assert run([FakeChecker("hibp")], config, password="ab").verdict is Verdict.TOO_SHORT


def test_supports_is_true_when_a_checker_covers_the_algorithm(config):
    runner = CheckRunner([FakeChecker("hibp", algorithms=[Algorithm.SHA1])], config)
    assert runner.supports(Algorithm.SHA1) is True


def test_supports_is_false_when_no_checker_covers_the_algorithm(config):
    runner = CheckRunner([FakeChecker("hibp", algorithms=[Algorithm.SHA1])], config)
    assert runner.supports(Algorithm.NTLM) is False


def test_supports_is_false_with_no_checkers_at_all(config):
    assert CheckRunner([], config).supports(Algorithm.SHA1) is False


class FakeStrengthScorer:
    def __init__(self, score=4, error=None):
        self._score = score
        self._error = error
        self.calls = []

    def score(self, password):
        self.calls.append(password)
        if self._error is not None:
            return ScoreResult(None, self._error)
        return ScoreResult(self._score, None)


def test_weak_password_short_circuits_without_calling_checkers(config):
    called = []

    class Spy(FakeChecker):
        def fetch(self, prefix, algorithm):
            called.append(prefix)
            return super().fetch(prefix, algorithm)

    runner = CheckRunner([Spy("hibp", hit=True)], config, strength=FakeStrengthScorer(score=0))
    result = runner.evaluate(LONG_ENOUGH)
    assert result.verdict is Verdict.WEAK
    assert called == []


def test_weak_short_circuit_takes_priority_over_too_short(config):
    runner = CheckRunner([FakeChecker("hibp")], config, strength=FakeStrengthScorer(score=0))
    assert runner.evaluate("ab").verdict is Verdict.WEAK


def test_strong_password_is_not_gated_by_strength(config):
    result = CheckRunner(
        [FakeChecker("hibp")], config, strength=FakeStrengthScorer(score=4)
    ).evaluate(LONG_ENOUGH)
    assert result.verdict is Verdict.SAFE


def test_scorer_error_falls_open_and_marks_degraded(config):
    runner = CheckRunner(
        [FakeChecker("hibp")], config, strength=FakeStrengthScorer(error="timeout")
    )
    result = runner.evaluate(LONG_ENOUGH)
    assert result.verdict is Verdict.SAFE
    assert result.degraded is True


def test_scorer_error_on_a_too_short_password_still_marks_degraded(config):
    runner = CheckRunner(
        [FakeChecker("hibp")], config, strength=FakeStrengthScorer(error="timeout")
    )
    result = runner.evaluate("ab")
    assert result.verdict is Verdict.TOO_SHORT
    assert result.degraded is True


def test_strength_disabled_in_config_skips_scoring_even_when_wired(tmp_path):
    config = config_from(tmp_path, "strength:\n  enabled: false\n")
    scorer = FakeStrengthScorer(score=0)
    result = CheckRunner([FakeChecker("hibp")], config, strength=scorer).evaluate(LONG_ENOUGH)
    assert result.verdict is Verdict.SAFE
    assert scorer.calls == []


def test_no_scorer_wired_behaves_exactly_as_before(config):
    result = CheckRunner([FakeChecker("hibp")], config, strength=None).evaluate(LONG_ENOUGH)
    assert result.verdict is Verdict.SAFE
    assert result.degraded is False


def test_zxcvbn_metrics_are_recorded_on_score(config):
    from amiweak.metrics import Metrics
    from amiweak.store import MemoryStore

    metrics = Metrics(MemoryStore())
    CheckRunner(
        [FakeChecker("hibp")], config, metrics=metrics, strength=FakeStrengthScorer(score=4)
    ).evaluate(LONG_ENOUGH)
    snapshot = metrics.snapshot()
    assert snapshot["backend_requests_total"]["zxcvbn"] == 1
    assert snapshot["backend_errors_total"].get("zxcvbn", 0) == 0


DENYLIST_DIGEST = "a" * 40


def test_non_cacheable_checker_never_touches_the_cache(config, monkeypatch):
    """A cacheable=False checker must not be read from, written to, or counted."""
    instance = cache()
    puts: list = []
    monkeypatch.setattr(instance, "put", lambda key, data: puts.append(key))

    class Free(RangeChecker):
        name = "free"
        cacheable = False

        def supports(self, algorithm):
            return algorithm is Algorithm.SHA1

        def prefix_of(self, digest, algorithm):
            return digest[:5]

        def fetch(self, prefix, algorithm):
            return RangeFetch({DENYLIST_DIGEST[5:]: None}, None)

        def lookup(self, data, digest):
            return CheckResult("free", True, digest[5:] in data, None, None)

    runner = CheckRunner([Free()], config, cache=instance)
    runner.evaluate_digest(DENYLIST_DIGEST, Algorithm.SHA1)
    runner.evaluate_digest(DENYLIST_DIGEST, Algorithm.SHA1)
    assert puts == []
    assert runner.prefix_cost([BatchItem("", DENYLIST_DIGEST)], Algorithm.SHA1) == 0


def test_denylisted_verdict_exists():
    from amiweak.checks.runner import Verdict

    assert Verdict.DENYLISTED == "denylisted"


def test_plaintext_denylist_gate_short_circuits_before_network(config):
    from amiweak.denylist import Denylist

    class Boom(FakeChecker):  # any fan-out is a bug: the gate must fire first
        def fetch(self, prefix, algorithm):
            raise AssertionError("network must not run")

        def lookup(self, data, digest):
            raise AssertionError("network must not run")

    dl = Denylist(tokens=("acme",), buckets={})
    runner = CheckRunner([Boom("hibp")], config, denylist=dl)
    evaluation = runner.evaluate("ACME2026!")
    assert evaluation.verdict is Verdict.DENYLISTED
    assert all(result.skipped for result in evaluation.results)


def test_gate_is_off_when_match_plaintext_false(tmp_path):
    from amiweak.denylist import Denylist

    config = config_from(tmp_path, "denylist:\n  match_plaintext: false\n")
    dl = Denylist(tokens=("acme",), buckets={})
    runner = CheckRunner([FakeChecker("hibp"), FakeChecker("weakpass")], config, denylist=dl)
    result = runner.evaluate("ACME2026!")
    assert result.verdict is Verdict.SAFE


def test_digest_denylist_loses_to_leaked_in_precedence(config):
    checkers = [FakeChecker("hibp", hit=True), FakeChecker("denylist", hit=True)]
    assert run(checkers, config).verdict is Verdict.LEAKED


def test_zxcvbn_errors_are_recorded_too(config):
    from amiweak.metrics import Metrics
    from amiweak.store import MemoryStore

    metrics = Metrics(MemoryStore())
    CheckRunner(
        [FakeChecker("hibp")], config, metrics=metrics, strength=FakeStrengthScorer(error="timeout")
    ).evaluate(LONG_ENOUGH)
    snapshot = metrics.snapshot()
    assert snapshot["backend_errors_total"]["zxcvbn"] == 1
