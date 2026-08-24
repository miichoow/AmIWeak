"""Have I Been Pwned range lookup.

Only the first five hex characters of the hash are sent. HIBP answers with every
suffix sharing that prefix, so the service cannot tell which password was asked
about. `Add-Padding: true` makes it pad the response to a uniform size, so the
body length cannot be used to fingerprint the prefix either.

In NTLM mode, the prefix stays five characters, but the suffix length changes
from 35 to 27, making NTLM digests exactly 32 hex characters.
"""

from __future__ import annotations

import requests

from amiweak.algorithms import Algorithm
from amiweak.checks.base import CheckResult, RangeChecker, RangeData, RangeFetch, classify_error
from amiweak.config import CheckConfig

RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
PREFIX_LENGTH = 5


def parse_hibp_range(body: str) -> dict[str, int]:
    """Parse a `SUFFIX:COUNT` range body into a mapping.

    Malformed rows are skipped rather than raising: one bad line should not turn
    a real breach hit into an outage. Rows with a count of zero are padding added
    by `Add-Padding` and carry no information.
    """
    counts: dict[str, int] = {}
    for line in body.splitlines():
        suffix, separator, raw_count = line.strip().partition(":")
        if not separator or not suffix:
            continue
        try:
            count = int(raw_count)
        except ValueError:
            continue
        if count <= 0:
            continue
        counts[suffix.upper()] = count
    return counts


class HibpChecker(RangeChecker):
    """Checks a hash against the Have I Been Pwned breach corpus."""

    name = "hibp"

    def __init__(
        self,
        session: requests.Session,
        config: CheckConfig,
        name: str = "hibp",
    ) -> None:
        self._session = session
        self._config = config
        self.name = name

    def supports(self, algorithm: Algorithm) -> bool:
        return algorithm in self._config.algorithms

    def prefix_of(self, digest: str, algorithm: Algorithm) -> str:
        return digest.upper()[:PREFIX_LENGTH]

    def fetch(self, prefix: str, algorithm: Algorithm) -> RangeFetch:
        try:
            response = self._session.get(
                RANGE_URL.format(prefix=prefix),
                headers={"Add-Padding": "true"},
                params={"mode": "ntlm"} if algorithm is Algorithm.NTLM else None,
                timeout=self._config.timeout,
            )
            response.raise_for_status()
        except Exception as exc:  # noqa: BLE001 - reason is deliberately coarse
            return RangeFetch(None, classify_error(exc))
        return RangeFetch(dict(parse_hibp_range(response.text)), None)

    def lookup(self, data: RangeData, digest: str) -> CheckResult:
        count = data.get(digest.upper()[PREFIX_LENGTH:])
        return CheckResult(self.name, True, count is not None, count, None)
