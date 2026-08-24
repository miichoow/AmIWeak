import requests
import responses

from amiweak.algorithms import Algorithm
from amiweak.checks.base import CheckResult
from amiweak.checks.hibp import HibpChecker, parse_hibp_range
from amiweak.config import CheckConfig

# sha1("password")
PASSWORD_HASH = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
PREFIX = "5BAA6"
SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
URL = f"https://api.pwnedpasswords.com/range/{PREFIX}"
NTLM_DIGEST = "8846f7eaee8fb117ad06bdd830b7586c"


def checker(algorithms=(Algorithm.SHA1, Algorithm.NTLM)):
    config = CheckConfig(enabled=True, timeout=5.0, on_error="fail_open", algorithms=algorithms)
    return HibpChecker(requests.Session(), config)


def test_parse_extracts_counts():
    assert parse_hibp_range("ABC:12\nDEF:3\n") == {"ABC": 12, "DEF": 3}


def test_parse_tolerates_crlf_and_blank_lines():
    assert parse_hibp_range("ABC:12\r\n\r\nDEF:3\r\n") == {"ABC": 12, "DEF": 3}


def test_parse_skips_malformed_rows():
    assert parse_hibp_range("ABC:12\ngarbage\nDEF:notanumber\nGHI:4") == {
        "ABC": 12,
        "GHI": 4,
    }


def test_parse_discards_padding_rows():
    assert parse_hibp_range("ABC:12\nPAD:0\n") == {"ABC": 12}


def test_parse_empty_body():
    assert parse_hibp_range("") == {}


def test_parse_is_case_insensitive_on_suffixes():
    assert parse_hibp_range("abc:12\n") == {"ABC": 12}


@responses.activate
def test_hit_reports_count():
    responses.get(URL, body=f"{SUFFIX}:24230577\nAAAA:5\n")
    result = checker().check(PASSWORD_HASH, Algorithm.SHA1)
    assert result.hit is True
    assert result.count == 24230577
    assert result.error is None
    assert result.name == "hibp"
    assert result.enabled is True


@responses.activate
def test_miss():
    responses.get(URL, body="AAAA:5\nBBBB:9\n")
    result = checker().check(PASSWORD_HASH, Algorithm.SHA1)
    assert result.hit is False
    assert result.count is None


@responses.activate
def test_sends_only_uppercase_prefix_with_padding_header():
    responses.get(URL, body="AAAA:5\n")
    checker().check(PASSWORD_HASH, Algorithm.SHA1)
    request = responses.calls[0].request
    assert request.url == URL
    assert request.headers["Add-Padding"] == "true"
    assert PASSWORD_HASH not in request.url
    assert SUFFIX not in request.url


@responses.activate
def test_timeout_is_reported():
    responses.get(URL, body=requests.exceptions.ReadTimeout())
    result = checker().check(PASSWORD_HASH, Algorithm.SHA1)
    assert result.hit is None
    assert result.error == "timeout"


@responses.activate
def test_connection_error_is_reported():
    responses.get(URL, body=requests.exceptions.ConnectionError())
    result = checker().check(PASSWORD_HASH, Algorithm.SHA1)
    assert result.hit is None
    assert result.error == "network"


@responses.activate
def test_server_error_is_reported():
    responses.get(URL, status=503)
    result = checker().check(PASSWORD_HASH, Algorithm.SHA1)
    assert result.hit is None
    assert result.error == "http_503"


@responses.activate
def test_error_reason_never_carries_upstream_detail():
    responses.get(URL, body=requests.exceptions.ConnectionError(PASSWORD_HASH))
    result = checker().check(PASSWORD_HASH, Algorithm.SHA1)
    assert result.error == "network"


@responses.activate
def test_ntlm_mode_is_requested_and_parsed():
    suffix = NTLM_DIGEST.upper()[5:]
    responses.get(
        f"https://api.pwnedpasswords.com/range/{NTLM_DIGEST.upper()[:5]}",
        body=f"{suffix}:1337\n",
    )
    result = checker().check(NTLM_DIGEST, Algorithm.NTLM)
    assert responses.calls[0].request.params["mode"] == "ntlm"
    assert result.hit is True
    assert result.count == 1337


@responses.activate
def test_sha1_mode_sends_no_mode_parameter():
    responses.get(f"https://api.pwnedpasswords.com/range/{PASSWORD_HASH.upper()[:5]}", body="")
    checker().check(PASSWORD_HASH, Algorithm.SHA1)
    assert "mode" not in responses.calls[0].request.params


def test_an_unsupported_algorithm_makes_the_result_inapplicable():
    instance = checker(algorithms=(Algorithm.SHA1,))
    result = instance.check(NTLM_DIGEST, Algorithm.NTLM)
    assert result.applicable is False
    assert result.error is None


def test_result_serialises_to_api_shape():
    assert CheckResult("hibp", True, True, 7, None).to_dict() == {
        "name": "hibp",
        "enabled": True,
        "applicable": True,
        "hit": True,
        "count": 7,
        "error": None,
    }
