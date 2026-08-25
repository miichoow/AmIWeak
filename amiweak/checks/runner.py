"""Fan out to every enabled checker at once and resolve a single verdict.

The two upstreams are independent, so running them in sequence would make the
user wait for the sum of two network round trips instead of the slower of them.

The password reaches this module and goes no further: it is measured, scored,
hashed, and dropped. Checkers only ever see the hash.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from amiweak.algorithms import Algorithm
from amiweak.cache import CacheKey, PrefixCache
from amiweak.checks.base import ERROR_INTERNAL, ERROR_TIMEOUT, Checker, CheckResult, RangeFetch
from amiweak.config import Config
from amiweak.denylist import Denylist
from amiweak.hashing import sha1_hex
from amiweak.metrics import Metrics
from amiweak.strength import ScoreResult

logger = logging.getLogger(__name__)


class Scorer(Protocol):
    """What `CheckRunner` needs from a strength scorer -- satisfied by
    `StrengthScorer` in production and by a fake in tests."""

    def score(self, password: str) -> ScoreResult: ...


def _timed_fetch(checker: Checker, prefix: str, algorithm: Algorithm) -> tuple[RangeFetch, float]:
    """Run one fetch and hand back its own duration, not the whole pool's.

    Submitted to the executor in place of `checker.fetch` directly, so that
    `backend_latency_seconds` reflects this single fetch instead of however
    long the entire fan-out (up to `batch.deadline`) happened to take.
    """
    began = time.monotonic()
    result = checker.fetch(prefix, algorithm)
    return result, time.monotonic() - began


class Verdict(StrEnum):
    SAFE = "safe"
    LEAKED = "leaked"
    PRECOMPUTED = "precomputed"
    DENYLISTED = "denylisted"
    TOO_SHORT = "too_short"
    WEAK = "weak"
    ERROR = "error"


#: Which backend produces which verdict, worst first. A new checker needs an
#: entry here or its hits will never surface. "denylist" is last so a digest
#: hit there loses to a hibp/weakpass hit on the same password.
VERDICT_BY_CHECK: tuple[tuple[str, Verdict], ...] = (
    ("hibp", Verdict.LEAKED),
    ("weakpass", Verdict.PRECOMPUTED),
    ("denylist", Verdict.DENYLISTED),
)


@dataclass(frozen=True)
class Evaluation:
    verdict: Verdict
    degraded: bool
    results: list[CheckResult]


@dataclass(frozen=True)
class BatchItem:
    label: str
    digest: str


@dataclass(frozen=True)
class BatchOutcome:
    label: str
    evaluation: Evaluation


class CheckRunner:
    """Runs the configured checkers concurrently and resolves their verdict."""

    def __init__(
        self,
        checkers: Sequence[Checker],
        config: Config,
        metrics: Metrics | None = None,
        cache: PrefixCache | None = None,
        strength: Scorer | None = None,
        denylist: Denylist | None = None,
    ) -> None:
        self._checkers = list(checkers)
        self._config = config
        self._metrics = metrics
        self._cache = cache
        self._strength = strength
        self._denylist = denylist

    def evaluate(self, password: str) -> Evaluation:
        strength_degraded = False
        if self._strength is not None and self._config.strength.enabled:
            began = time.monotonic()
            result = self._strength.score(password)
            elapsed = time.monotonic() - began
            if self._metrics is not None:
                self._metrics.record_backend(
                    "zxcvbn", ok=result.error is None, seconds=elapsed, error=result.error
                )
            if result.error is not None:
                strength_degraded = True
            elif result.score is not None and result.score < self._config.strength.min_score:
                # Short-circuit exactly as `app.js`'s `onSubmit` does before it
                # ever calls the API: skip the length check and both network
                # calls on a password we are going to reject regardless.
                return self._finish(Verdict.WEAK, False, self._placeholder_results())

        if len(password) < self._config.policy.min_length:
            # Short-circuit: no point spending two network calls on a password
            # we are going to reject anyway, and it keeps the hash off the wire.
            return self._finish(Verdict.TOO_SHORT, strength_degraded, self._placeholder_results())

        if (
            self._denylist is not None
            and self._config.denylist.match_plaintext
            and self._denylist.matches(password)
        ):
            # hibp/weakpass are skipped for the same reason as the gates above:
            # no point spending a network call on a password already rejected,
            # and it keeps the hash off the wire. The denylist digest checker is
            # different -- it is local, free, and cannot fail (see
            # DenylistChecker.fetch) -- so it still runs for real instead of
            # reporting a placeholder. It can come back a miss even though the
            # plaintext gate hit: the plaintext match (with l33t-decoding) can
            # catch mutations the precomputed digest set does not.
            return self._finish(
                Verdict.DENYLISTED, strength_degraded, self._denylist_hit_results(password)
            )

        evaluation = self.evaluate_digest(sha1_hex(password), Algorithm.SHA1)
        if strength_degraded and not evaluation.degraded:
            return Evaluation(verdict=evaluation.verdict, degraded=True, results=evaluation.results)
        return evaluation

    def evaluate_digest(self, digest: str, algorithm: Algorithm) -> Evaluation:
        """Resolve one digest the caller already computed.

        `policy.overall_deadline`, not `batch.deadline`: this is one prefix per
        backend and a caller is waiting on it, exactly like `evaluate`.

        There is no length gate here and there cannot be one — a digest does not
        carry the length of the password it came from. See the endpoint docs.
        """
        plan = self._plan([BatchItem(label="", digest=digest)], algorithm)
        ranges = self._fetch_plan(
            plan,
            algorithm,
            deadline=self._config.policy.overall_deadline,
            # Concurrency is the plan size because a single check fans out to at
            # most one prefix per backend.
            max_workers=max(1, len(plan)),
        )
        return self._evaluate_from(ranges, digest, algorithm)

    def _applicable(self, algorithm: Algorithm) -> list[Checker]:
        return [c for c in self._checkers if c.supports(algorithm)]

    def supports(self, algorithm: Algorithm) -> bool:
        """True when at least one enabled checker can answer for `algorithm`.

        When this is false the plan comes out empty, every check reports
        `applicable: false`, and `_resolve` falls through to SAFE — a confident
        all-clear nothing actually checked. Routes consult this and reject the
        request instead.
        """
        return bool(self._applicable(algorithm))

    def _plan(
        self, items: Sequence[BatchItem], algorithm: Algorithm
    ) -> dict[CacheKey, tuple[Checker, str]]:
        """Every distinct (backend, prefix) pair the batch needs, deduplicated."""
        plan: dict[CacheKey, tuple[Checker, str]] = {}
        for checker in self._applicable(algorithm):
            for entry in items:
                prefix = checker.prefix_of(entry.digest, algorithm)
                plan[(checker.name, str(algorithm), prefix)] = (checker, prefix)
        return plan

    def prefix_cost(self, items: Sequence[BatchItem], algorithm: Algorithm) -> int:
        """How many uncached prefix fetches this batch would need.

        The rate limiter charges this rather than the item count, so it meters
        actual upstream egress. Re-running an audit inside the cache TTL is free.
        """
        plan = self._plan(items, algorithm)
        if self._cache is None:
            return sum(1 for checker, _prefix in plan.values() if checker.cacheable)
        return sum(
            1
            for key, (checker, _prefix) in plan.items()
            if checker.cacheable and not self._cache.contains(key)
        )

    def evaluate_batch(
        self, items: Sequence[BatchItem], algorithm: Algorithm
    ) -> list[BatchOutcome]:
        """Fetch every distinct prefix once, then resolve each item with no I/O."""
        if not items:
            return []
        ranges = self._fetch_plan(
            self._plan(items, algorithm),
            algorithm,
            deadline=self._config.batch.deadline,
            max_workers=self._config.batch.max_concurrency,
        )
        return [
            BatchOutcome(entry.label, self._evaluate_from(ranges, entry.digest, algorithm))
            for entry in items
        ]

    def _fetch_plan(
        self,
        plan: dict[CacheKey, tuple[Checker, str]],
        algorithm: Algorithm,
        deadline: float,
        max_workers: int,
    ) -> dict[CacheKey, RangeFetch]:
        """Resolve every planned prefix, from cache or from the network."""
        ranges: dict[CacheKey, RangeFetch] = {}
        pending: dict[CacheKey, tuple[Checker, str]] = {}

        for key, (checker, prefix) in plan.items():
            cached = self._cache.get(key) if self._cache is not None and checker.cacheable else None
            if cached is not None:
                ranges[key] = RangeFetch(cached, None)
                self._record_cache(checker.name, hit=True)
            else:
                pending[key] = (checker, prefix)
                if checker.cacheable:
                    self._record_cache(checker.name, hit=False)

        if not pending:
            return ranges

        started = time.monotonic()
        pool = ThreadPoolExecutor(max_workers=min(max_workers, len(pending)))
        timed_out_backends: set[str] = set()
        try:
            futures = {
                pool.submit(_timed_fetch, checker, prefix, algorithm): key
                for key, (checker, prefix) in pending.items()
            }
            done, _ = wait(futures, timeout=deadline)
            for future, key in futures.items():
                checker, _prefix = pending[key]
                if future not in done:
                    future.cancel()
                    ranges[key] = RangeFetch(None, ERROR_TIMEOUT)
                    # A blown deadline can strand up to `len(pending)` futures at
                    # once; recording one backend error per future would write
                    # thousands of sticky ERROR_TIMEOUT states in a single call
                    # and leave /healthz reporting degraded long after the batch
                    # that caused it. One record per backend per call is enough
                    # to flip health state without the multiplication.
                    if checker.name not in timed_out_backends:
                        timed_out_backends.add(checker.name)
                        elapsed = time.monotonic() - started
                        self._record_backend(checker.name, elapsed, ERROR_TIMEOUT)
                    continue
                ranges[key] = self._collect_fetch(future, checker, key, algorithm, started)
        finally:
            # Never block on shutdown: a fetch that has blown the deadline must
            # not also hold up the response.
            pool.shutdown(wait=False)
        return ranges

    def _collect_fetch(
        self,
        future: Future[tuple[RangeFetch, float]],
        checker: Checker,
        key: CacheKey,
        algorithm: Algorithm,
        started: float,
    ) -> RangeFetch:
        try:
            fetched, elapsed = future.result()
        except Exception:
            # The checker raised before _timed_fetch could hand back its own
            # duration, so there is no per-fetch figure to report. Fall back
            # to the fan-out-relative elapsed, same as the timeout branch: an
            # approximation of "how long we waited," not this fetch's own time.
            elapsed = time.monotonic() - started
            # The exception text is dropped deliberately: it can embed the URL,
            # and the URL embeds a hash prefix.
            logger.warning("fetch %s raised", checker.name, exc_info=False)
            self._record_backend(checker.name, elapsed, ERROR_INTERNAL)
            return RangeFetch(None, ERROR_INTERNAL)
        self._record_backend(checker.name, elapsed, fetched.error)
        self._record_algorithm(checker.name, algorithm)
        # Only a success is cached. Caching a timeout would turn one bad minute
        # into an hour of false "safe" answers.
        if fetched.data is not None and self._cache is not None and checker.cacheable:
            self._cache.put(key, fetched.data)
        return fetched

    def _evaluate_from(
        self, ranges: dict[CacheKey, RangeFetch], digest: str, algorithm: Algorithm
    ) -> Evaluation:
        """Resolve one digest purely, from ranges already in hand."""
        completed: dict[str, CheckResult] = {}
        for checker in self._checkers:
            if not checker.supports(algorithm):
                completed[checker.name] = CheckResult(
                    checker.name, True, None, None, None, applicable=False
                )
                continue
            key = (checker.name, str(algorithm), checker.prefix_of(digest, algorithm))
            fetched = ranges.get(key)
            if fetched is None or fetched.data is None:
                error = fetched.error if fetched is not None else ERROR_INTERNAL
                completed[checker.name] = CheckResult(checker.name, True, None, None, error)
                continue
            completed[checker.name] = checker.lookup(fetched.data, digest)
        results = self._ordered(completed)
        return self._finish(*self._resolve(results), results)

    def _record_cache(self, name: str, hit: bool) -> None:
        if self._metrics is not None:
            self._metrics.record_cache(name, hit=hit)

    def _record_algorithm(self, name: str, algorithm: Algorithm) -> None:
        if self._metrics is not None:
            self._metrics.record_algorithm(name, str(algorithm))

    def _record_backend(self, name: str, elapsed: float, error: str | None) -> None:
        if self._metrics is not None:
            self._metrics.record_backend(name, ok=error is None, seconds=elapsed, error=error)

    def _placeholder_results(self) -> list[CheckResult]:
        """Results for a verdict decided by an earlier gate: every check was
        skipped, not attempted-and-unreachable."""
        return self._ordered({}, skipped=True)

    def _denylist_hit_results(self, password: str) -> list[CheckResult]:
        """Results for a verdict decided by the plaintext denylist gate.

        hibp/weakpass are skipped -- reporting them would cost a real network
        call for a password already rejected. The denylist digest checker
        costs nothing to run, so it answers for real rather than reporting a
        placeholder alongside them.
        """
        completed: dict[str, CheckResult] = {}
        denylist_checker = next((c for c in self._checkers if c.name == "denylist"), None)
        if denylist_checker is not None and denylist_checker.supports(Algorithm.SHA1):
            completed["denylist"] = denylist_checker.check(sha1_hex(password), Algorithm.SHA1)
        return self._ordered(completed, skipped=True)

    def _ordered(
        self, completed: dict[str, CheckResult], skipped: bool = False
    ) -> list[CheckResult]:
        """Order results by the config, filling in any check that did not run."""
        results = []
        for name, check_config in self._config.checks.items():
            if name in completed:
                results.append(completed[name])
            else:
                results.append(
                    CheckResult(name, check_config.enabled, None, None, None, skipped=skipped)
                )
        for name, result in completed.items():
            if name not in self._config.checks:
                results.append(result)
        return results

    def _resolve(self, results: list[CheckResult]) -> tuple[Verdict, bool]:
        by_name = {result.name: result for result in results}

        failed = [
            r
            for r in results
            if r.enabled and r.applicable and r.hit is None and r.error is not None
        ]
        degraded = bool(failed)
        for result in failed:
            check_config = self._config.checks.get(result.name)
            if check_config is not None and check_config.on_error == "fail_closed":
                return Verdict.ERROR, degraded

        for name, verdict in VERDICT_BY_CHECK:
            candidate = by_name.get(name)
            if candidate is not None and candidate.hit:
                return verdict, degraded

        return Verdict.SAFE, degraded

    def _finish(self, verdict: Verdict, degraded: bool, results: list[CheckResult]) -> Evaluation:
        if self._metrics is not None:
            self._metrics.record_check(str(verdict))
        return Evaluation(verdict=verdict, degraded=degraded, results=results)
