"""The organisation denylist: a custom word file expanded through hashcat rules.

Two products from one file. `tokens` are normalized entries for substring
matching against a submitted plaintext (the hard ban on /api/v1/check).
`buckets` are the SHA-1 of every entry and every rule expansion, pre-bucketed
by prefix for O(1) digest lookup. The expensive `buckets` half is persisted to
disk and regenerated only when the file or its rules change; see digest_store.
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
from dataclasses import dataclass

import hcrulepy
from filelock import FileLock, Timeout
from hcrulepy import InvalidRule, RuleEngine

from amiweak.checks.base import RangeData
from amiweak.config import Config, ConfigError, DenylistConfig
from amiweak.digest_store import read_cache, write_cache

logger = logging.getLogger(__name__)

#: Bump when normalization or generation logic changes the produced digest set,
#: so a code change invalidates any cache built by the old logic.
GENERATOR_VERSION = 1

#: Generous — one worker may generate for minutes while the others wait.
LOCK_TIMEOUT = 600.0

_LEET = {
    "4": "a",
    "@": "a",
    "3": "e",
    "1": "i",
    "!": "i",
    "0": "o",
    "5": "s",
    "$": "s",
    "7": "t",
}


def normalize(text: str) -> str:
    """Casefold, l33t-decode, then keep only alphanumerics.

    Applied identically to entries and to submitted passwords, so that
    `ACME-2026!` and `a.c.m.e` both contain the token `acme`.
    """
    lowered = text.casefold()
    decoded = "".join(_LEET.get(ch, ch) for ch in lowered)
    return "".join(ch for ch in decoded if ch.isalnum())


def _read_entries(path: str | os.PathLike[str], min_token_length: int) -> list[str]:
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        raise ConfigError(f"denylist: cannot read {path}") from None
    entries: list[str] = []
    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if len(normalize(line)) < min_token_length:
            # Never echo the entry: it may itself be a known-bad password.
            raise ConfigError(
                f"denylist: entry on line {lineno} normalizes to fewer than "
                f"min_token_length ({min_token_length}) characters"
            )
        entries.append(line)
    return entries


def generate_digests(
    entries: list[str], rule_paths: tuple[str, ...], max_digests: int
) -> list[bytes]:
    """SHA-1 of every entry and every rule expansion, sorted and de-duplicated.

    Counts as it goes and aborts at the cap: `apply()` is lazy, so an oversized
    expansion fails fast instead of exhausting memory on the way to discovering
    it. An invalid or missing rule file is a hard error, never a silent skip.
    """
    try:
        engine = RuleEngine.from_files(rule_paths) if rule_paths else None
    except InvalidRule as exc:
        raise ConfigError(f"denylist: invalid hashcat rule ({exc})") from None
    except OSError:
        raise ConfigError("denylist: cannot read a rule file") from None

    seen: set[bytes] = set()

    def add(word: str) -> None:
        # nosemgrep: insecure-hash-algorithm-sha1 -- in-memory dedup key, not password storage
        seen.add(hashlib.sha1(word.encode("utf-8"), usedforsecurity=False).digest())
        if len(seen) > max_digests:
            raise ConfigError(f"denylist: rule expansion exceeds max_digests ({max_digests})")

    for entry in entries:
        add(entry)
        if engine is not None:
            for candidate in engine.apply(entry):
                add(candidate)
    return sorted(seen)


def _bucket(digests: list[bytes]) -> dict[str, RangeData]:
    buckets: dict[str, RangeData] = {}
    for digest in digests:
        hexed = digest.hex()
        buckets.setdefault(hexed[:5], {})[hexed[5:]] = None
    return buckets


def _fingerprint(dict_path: str | os.PathLike[str], rule_paths: tuple[str, ...]) -> bytes:
    """SHA-256 over the generator version, hcrulepy version, and the exact bytes
    of the dictionary and each rule file. Content-based, so it is correct across
    copies, redeploys, and edits that preserve mtime."""
    hasher = hashlib.sha256()

    def feed(blob: bytes) -> None:
        hasher.update(struct.pack("<Q", len(blob)))  # length-prefixed: unambiguous
        hasher.update(blob)

    feed(struct.pack("<I", GENERATOR_VERSION))
    feed(hcrulepy.__version__.encode("utf-8"))
    for path in (dict_path, *rule_paths):
        try:
            with open(path, "rb") as handle:
                feed(handle.read())
        except OSError:
            raise ConfigError(f"denylist: cannot read {path}") from None
    return hasher.digest()


def _load_or_generate(
    cache_path: str,
    fingerprint: bytes,
    entries: list[str],
    rule_paths: tuple[str, ...],
    max_digests: int,
) -> list[bytes]:
    cached = read_cache(cache_path)
    if cached is not None and cached.fingerprint == fingerprint:
        return cached.digests

    try:
        lock = FileLock(f"{cache_path}.lock", timeout=LOCK_TIMEOUT)
        with lock:
            # A sibling worker may have generated it between the check above and
            # the lock; re-check before spending the generation cost.
            cached = read_cache(cache_path)
            if cached is not None and cached.fingerprint == fingerprint:
                return cached.digests
            digests = generate_digests(entries, rule_paths, max_digests)
            write_cache(cache_path, fingerprint, digests)
            return digests
    except Timeout:
        raise ConfigError(
            f"denylist: timed out acquiring the cache lock {cache_path}.lock"
        ) from None
    except OSError:
        raise ConfigError(f"denylist: cannot write the digest cache at {cache_path}") from None


@dataclass(frozen=True)
class Denylist:
    tokens: tuple[str, ...]
    buckets: dict[str, RangeData]

    def matches(self, password: str) -> bool:
        candidate = normalize(password)
        return any(token in candidate for token in self.tokens)

    @classmethod
    def load(cls, config: Config) -> Denylist | None:
        dcfg: DenylistConfig = config.denylist
        if dcfg.path is None:
            return None
        entries = _read_entries(dcfg.path, dcfg.min_token_length)
        tokens = tuple(normalize(entry) for entry in entries)
        cache_path = dcfg.cache_path or f"{dcfg.path}.amwk-digests"
        fingerprint = _fingerprint(dcfg.path, dcfg.rules)
        digests = _load_or_generate(cache_path, fingerprint, entries, dcfg.rules, dcfg.max_digests)
        buckets = _bucket(digests)
        logger.info("denylist: %d entries, %d digests", len(entries), len(digests))
        return cls(tokens=tokens, buckets=buckets)
