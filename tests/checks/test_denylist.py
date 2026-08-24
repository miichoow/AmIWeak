import hashlib

from amiweak.algorithms import Algorithm
from amiweak.checks.denylist import DenylistChecker
from amiweak.config import CheckConfig


def sha1_hex(word: str) -> str:
    return hashlib.sha1(word.encode("utf-8")).hexdigest()


def buckets_for(*words):
    buckets = {}
    for w in words:
        h = sha1_hex(w)
        buckets.setdefault(h[:5], {})[h[5:]] = None
    return buckets


def checker(words=("acme",), algorithms=(Algorithm.SHA1,)):
    config = CheckConfig(enabled=True, timeout=5.0, on_error="fail_open", algorithms=algorithms)
    return DenylistChecker(buckets_for(*words), config)


def test_is_not_cacheable():
    assert checker().cacheable is False


def test_sha1_hit():
    result = checker(("acme",)).check(sha1_hex("acme"), Algorithm.SHA1)
    assert result.hit is True
    assert result.count is None
    assert result.name == "denylist"


def test_sha1_miss():
    assert checker(("acme",)).check(sha1_hex("nope"), Algorithm.SHA1).hit is False


def test_hit_is_case_insensitive():
    assert checker(("acme",)).check(sha1_hex("acme").upper(), Algorithm.SHA1).hit is True


def test_ntlm_is_not_applicable_and_not_degraded():
    # 32 hex chars; algorithms is sha1-only.
    result = checker(("acme",)).check("8846f7eaee8fb117ad06bdd830b7586c", Algorithm.NTLM)
    assert result.applicable is False
    assert result.hit is None
    assert result.error is None


def test_supports_respects_configured_algorithms():
    assert checker(algorithms=(Algorithm.SHA1,)).supports(Algorithm.SHA1) is True
    assert checker(algorithms=(Algorithm.SHA1,)).supports(Algorithm.NTLM) is False
