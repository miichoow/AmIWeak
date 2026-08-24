"""The hash algorithms a check can be performed against.

NTLM is a parameter here, not a separate backend: both upstreams answer range
queries for either algorithm on the same endpoint.

Nothing in this codebase computes an NTLM digest. Every endpoint that accepts
NTLM is hash-only -- the batch endpoint and /check/hash -- and the one endpoint
that takes a plaintext password hashes it as SHA-1, so an NTLM digest only ever
arrives from a client that already had it. That is deliberate: MD4 is absent
from `hashlib` on OpenSSL 3 builds, and not needing it avoids the question.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

_HEX = frozenset("0123456789abcdef")


class Algorithm(StrEnum):
    SHA1 = "sha1"
    NTLM = "ntlm"

    @property
    def digest_length(self) -> int:
        """Length of this algorithm's digest in hex characters."""
        return 40 if self is Algorithm.SHA1 else 32


def parse_algorithm(value: Any) -> Algorithm:
    """Resolve a client-supplied name to an Algorithm, or raise ValueError."""
    if not isinstance(value, str):
        raise ValueError("algorithm must be a string")
    try:
        return Algorithm(value.strip().lower())
    except ValueError:
        raise ValueError(f"unknown algorithm: {value!r}") from None


def is_valid_digest(value: Any, algorithm: Algorithm) -> bool:
    """True when `value` is hex of exactly the right length for `algorithm`."""
    if not isinstance(value, str):
        return False
    candidate = value.strip().lower()
    return len(candidate) == algorithm.digest_length and set(candidate) <= _HEX
