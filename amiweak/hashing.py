"""Hashing for range-query lookups.

SHA-1 is used here because both upstream providers index their corpora by it.
This is a lookup key into a public dataset, not password storage — nothing in
this file should be read as a recommendation to store SHA-1 password hashes.
"""

from __future__ import annotations

import hashlib


def sha1_hex(password: str) -> str:
    """Return the lowercase hex SHA-1 of `password`, UTF-8 encoded."""
    # nosemgrep: insecure-hash-algorithm-sha1 -- lookup key, not password storage
    return hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest()
