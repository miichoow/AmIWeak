"""weakpass range lookup.

Same k-anonymity idea as HIBP, with a six-character prefix and a body of full
hashes rather than suffixes. weakpass indexes public cracking wordlists, so a
hit means the password is already in someone's dictionary even if it has never
appeared in a breach dump.
"""

from __future__ import annotations

import logging

import requests

from amiweak.algorithms import Algorithm
from amiweak.checks.base import CheckResult, RangeChecker, RangeData, RangeFetch, classify_error
from amiweak.config import CheckConfig

RANGE_URL = "https://weakpass.com/api/v1/range/{prefix}.txt"
PREFIX_LENGTH = 6
_HEX = set("0123456789abcdef")

logger = logging.getLogger(__name__)


def parse_weakpass_range(body: str) -> RangeData:
    """Parse a body of one hash per line into a lowercase mapping.

    Rows that are not plain hex are skipped, on the same reasoning as the HIBP
    parser: a malformed line should not cost us the whole lookup. weakpass never
    reports an occurrence count, so every present hash maps to None.
    """
    hashes: RangeData = {}
    for line in body.splitlines():
        candidate = line.strip().lower()
        if candidate and set(candidate) <= _HEX:
            hashes[candidate] = None
    return hashes


class WeakpassChecker(RangeChecker):
    """Checks a hash against the weakpass precomputed wordlist corpus."""

    name = "weakpass"

    def __init__(
        self,
        session: requests.Session,
        config: CheckConfig,
        name: str = "weakpass",
    ) -> None:
        self._session = session
        self._config = config
        self.name = name

    def supports(self, algorithm: Algorithm) -> bool:
        return algorithm in self._config.algorithms

    def prefix_of(self, digest: str, algorithm: Algorithm) -> str:
        return digest.lower()[:PREFIX_LENGTH]

    def fetch(self, prefix: str, algorithm: Algorithm) -> RangeFetch:
        # Cache hits never get here, so this line marks a real outbound
        # call to weakpass. The prefix is deliberately left out: it is
        # part of the hash.
        logger.info("%s: fetching range for %s", self.name, algorithm)
        try:
            response = self._session.get(
                RANGE_URL.format(prefix=prefix),
                # filter=hash is load-bearing: without it the API returns the
                # recovered plaintext alongside each hash.
                params={"filter": "hash", "type": str(algorithm)},
                timeout=self._config.timeout,
            )
            response.raise_for_status()
        except Exception as exc:  # noqa: BLE001 - reason is deliberately coarse
            return RangeFetch(None, classify_error(exc))
        return RangeFetch(parse_weakpass_range(response.text), None)

    def lookup(self, data: RangeData, digest: str) -> CheckResult:
        # weakpass reports membership only, never an occurrence count.
        return CheckResult(self.name, True, digest.lower() in data, None, None)
