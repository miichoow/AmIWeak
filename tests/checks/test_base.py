from amiweak.algorithms import Algorithm
from amiweak.checks.base import (
    ERROR_INTERNAL,
    CheckResult,
    RangeChecker,
    RangeFetch,
    classify_error,
)


class FakeChecker(RangeChecker):
    name = "fake"

    def __init__(self, fetched: RangeFetch, supported=(Algorithm.SHA1,)):
        self._fetched = fetched
        self._supported = supported
        self.fetch_calls = []

    def supports(self, algorithm):
        return algorithm in self._supported

    def prefix_of(self, digest, algorithm):
        return digest[:5]

    def fetch(self, prefix, algorithm):
        self.fetch_calls.append((prefix, algorithm))
        return self._fetched

    def lookup(self, data, digest):
        return CheckResult(self.name, True, digest in data, data.get(digest), None)


DIGEST = "abcdef" + "0" * 34


def test_check_fetches_then_looks_up():
    checker = FakeChecker(RangeFetch({DIGEST: 7}, None))
    result = checker.check(DIGEST, Algorithm.SHA1)
    assert checker.fetch_calls == [(DIGEST[:5], Algorithm.SHA1)]
    assert result.hit is True
    assert result.count == 7
    assert result.applicable is True


def test_check_reports_a_fetch_error_without_looking_up():
    checker = FakeChecker(RangeFetch(None, "timeout"))
    result = checker.check(DIGEST, Algorithm.SHA1)
    assert result.hit is None
    assert result.error == "timeout"
    assert result.applicable is True


def test_an_unsupported_algorithm_is_not_an_error():
    checker = FakeChecker(RangeFetch({}, None))
    result = checker.check(DIGEST, Algorithm.NTLM)
    assert checker.fetch_calls == [], "must not touch the network"
    assert result.applicable is False
    assert result.error is None
    assert result.hit is None


def test_result_dict_carries_applicable():
    result = CheckResult("x", True, None, None, None, applicable=False)
    assert result.to_dict()["applicable"] is False


def test_classify_error_falls_back_to_internal_for_a_non_request_exception():
    assert classify_error(ValueError("boom")) == ERROR_INTERNAL
