"""The checker protocol and the result type every checker returns.

A range lookup has two halves with very different costs: one network fetch per
*prefix*, and a pure lookup per *digest*. They are separate methods here so that
caching, deduplication, metering, and concurrency limiting can all attach to the
expensive half and nowhere else.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol

import requests

from amiweak.algorithms import Algorithm

#: The only reasons a check is allowed to report. Keeping this vocabulary closed
#: means no upstream exception text — which can embed the requested URL — can
#: ever reach a log line or an API response.
ERROR_TIMEOUT = "timeout"
ERROR_NETWORK = "network"
ERROR_INTERNAL = "internal"

#: A parsed range: suffix or full hash, mapped to an occurrence count when the
#: provider reports one and None when it does not.
RangeData = dict[str, int | None]


@dataclass(frozen=True)
class RangeFetch:
    """One prefix fetch. Exactly one of `data` and `error` is set.

    Errors are returned rather than raised so the caller can distinguish a
    result worth caching from one that must not be.
    """

    data: RangeData | None
    error: str | None


@dataclass(frozen=True)
class CheckResult:
    """The outcome of one backend lookup.

    `hit` is None when the check did not complete; `error` then carries a short,
    non-sensitive reason such as "timeout", "network", or "http_503".

    `applicable` is False when the backend cannot answer for the requested
    algorithm at all. That is not an error and must not mark a result degraded.
    """

    name: str
    enabled: bool
    hit: bool | None
    count: int | None
    error: str | None
    applicable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "applicable": self.applicable,
            "hit": self.hit,
            "count": self.count,
            "error": self.error,
        }


class Checker(Protocol):
    name: str
    cacheable: bool

    def supports(self, algorithm: Algorithm) -> bool: ...
    def prefix_of(self, digest: str, algorithm: Algorithm) -> str: ...
    def fetch(self, prefix: str, algorithm: Algorithm) -> RangeFetch: ...
    def lookup(self, data: RangeData, digest: str) -> CheckResult: ...
    def check(self, digest: str, algorithm: Algorithm) -> CheckResult: ...


class RangeChecker(ABC):
    """Base for range-API backends. Supplies `check` from the four primitives."""

    name: str
    cacheable: bool = True

    @abstractmethod
    def supports(self, algorithm: Algorithm) -> bool: ...

    @abstractmethod
    def prefix_of(self, digest: str, algorithm: Algorithm) -> str: ...

    @abstractmethod
    def fetch(self, prefix: str, algorithm: Algorithm) -> RangeFetch: ...

    @abstractmethod
    def lookup(self, data: RangeData, digest: str) -> CheckResult: ...

    def check(self, digest: str, algorithm: Algorithm) -> CheckResult:
        """The single-digest path: one fetch, one lookup, no cache."""
        if not self.supports(algorithm):
            return CheckResult(self.name, True, None, None, None, applicable=False)
        fetched = self.fetch(self.prefix_of(digest, algorithm), algorithm)
        if fetched.data is None:
            return CheckResult(self.name, True, None, None, fetched.error)
        return self.lookup(fetched.data, digest)


def classify_error(exc: BaseException) -> str:
    """Map an exception to one of the closed set of reason strings."""
    if isinstance(exc, requests.exceptions.Timeout):
        return ERROR_TIMEOUT
    if isinstance(exc, requests.exceptions.HTTPError):
        status = exc.response.status_code if exc.response is not None else None
        return f"http_{status}" if status else ERROR_NETWORK
    if isinstance(exc, requests.exceptions.RequestException):
        return ERROR_NETWORK
    return ERROR_INTERNAL
