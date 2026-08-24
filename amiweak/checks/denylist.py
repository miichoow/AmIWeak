"""The organisation denylist as a SHA-1 range backend.

Implements the Checker protocol directly rather than subclassing RangeChecker:
there is no network fetch to split off. `fetch` returns a precomputed bucket in
O(1), cannot fail, and is never cached (`cacheable = False`) — a batch would
otherwise evict every genuinely expensive HIBP/weakpass range from the LRU.
"""

from __future__ import annotations

from amiweak.algorithms import Algorithm
from amiweak.checks.base import CheckResult, RangeData, RangeFetch
from amiweak.config import CheckConfig

PREFIX_LENGTH = 5


class DenylistChecker:
    name = "denylist"
    cacheable = False

    def __init__(self, buckets: dict[str, RangeData], config: CheckConfig) -> None:
        self._buckets = buckets
        self._config = config

    def supports(self, algorithm: Algorithm) -> bool:
        return algorithm is Algorithm.SHA1 and algorithm in self._config.algorithms

    def prefix_of(self, digest: str, algorithm: Algorithm) -> str:
        return digest.lower()[:PREFIX_LENGTH]

    def fetch(self, prefix: str, algorithm: Algorithm) -> RangeFetch:
        # Pure and infallible: the bucket is already in memory. An absent prefix
        # is an empty range, not an error, so on_error can never fire.
        return RangeFetch(self._buckets.get(prefix, {}), None)

    def lookup(self, data: RangeData, digest: str) -> CheckResult:
        return CheckResult(self.name, True, digest.lower()[PREFIX_LENGTH:] in data, None, None)

    def check(self, digest: str, algorithm: Algorithm) -> CheckResult:
        if not self.supports(algorithm):
            return CheckResult(self.name, True, None, None, None, applicable=False)
        fetched = self.fetch(self.prefix_of(digest, algorithm), algorithm)
        # Always holds: `fetch` always returns RangeFetch(self._buckets.get(prefix, {}), None)
        # -- data is a dict (possibly empty), never None, and error is never set. Documented
        # here rather than relied upon silently because -O strips asserts.
        assert fetched.data is not None
        return self.lookup(fetched.data, digest)
