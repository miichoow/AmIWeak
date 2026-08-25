import logging

import requests
import responses

from amiweak.algorithms import Algorithm
from amiweak.checks.weakpass import WeakpassChecker, parse_weakpass_range
from amiweak.config import CheckConfig

PASSWORD_HASH = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
PREFIX = "5baa61"
URL = f"https://weakpass.com/api/v1/range/{PREFIX}.txt"
NTLM_DIGEST = "8846f7eaee8fb117ad06bdd830b7586c"


def checker(algorithms=(Algorithm.SHA1, Algorithm.NTLM)):
    config = CheckConfig(enabled=True, timeout=5.0, on_error="fail_open", algorithms=algorithms)
    return WeakpassChecker(requests.Session(), config)


def test_parse_lowercases_and_collects():
    assert parse_weakpass_range("AABB\ncc dd\n") == {"aabb": None}


def test_parse_tolerates_crlf_and_blanks():
    assert parse_weakpass_range("aabb\r\n\r\nccdd\r\n") == {"aabb": None, "ccdd": None}


def test_parse_empty_body():
    assert parse_weakpass_range("") == {}


def test_parse_keeps_only_hex_rows():
    assert parse_weakpass_range("aabb\nnot-a-hash!\n") == {"aabb": None}


@responses.activate
def test_hit_has_no_count():
    responses.get(URL, body=f"{PASSWORD_HASH}\ndeadbeef\n")
    result = checker().check(PASSWORD_HASH, Algorithm.SHA1)
    assert result.hit is True
    assert result.count is None
    assert result.name == "weakpass"


@responses.activate
def test_hit_is_case_insensitive():
    responses.get(URL, body=f"{PASSWORD_HASH.upper()}\n")
    assert checker().check(PASSWORD_HASH, Algorithm.SHA1).hit is True


@responses.activate
def test_miss():
    responses.get(URL, body="deadbeef\ncafebabe\n")
    assert checker().check(PASSWORD_HASH, Algorithm.SHA1).hit is False


@responses.activate
def test_sends_only_lowercase_six_char_prefix():
    responses.get(URL, body="deadbeef\n")
    checker().check(PASSWORD_HASH, Algorithm.SHA1)
    request = responses.calls[0].request
    assert PREFIX in request.url
    assert PASSWORD_HASH not in request.url
    assert PASSWORD_HASH[6:] not in request.url


@responses.activate
def test_query_selects_the_sha1_hash_filter():
    responses.get(URL, body="deadbeef\n")
    checker().check(PASSWORD_HASH, Algorithm.SHA1)
    url = responses.calls[0].request.url
    assert "filter=hash" in url
    assert "type=sha1" in url


@responses.activate
def test_timeout_is_reported():
    responses.get(URL, body=requests.exceptions.ReadTimeout())
    result = checker().check(PASSWORD_HASH, Algorithm.SHA1)
    assert result.hit is None
    assert result.error == "timeout"


@responses.activate
def test_connection_error_is_reported():
    responses.get(URL, body=requests.exceptions.ConnectionError())
    assert checker().check(PASSWORD_HASH, Algorithm.SHA1).error == "network"


@responses.activate
def test_rate_limit_status_is_reported():
    responses.get(URL, status=429)
    assert checker().check(PASSWORD_HASH, Algorithm.SHA1).error == "http_429"


@responses.activate
def test_ntlm_type_is_requested_and_parsed():
    responses.get(
        f"https://weakpass.com/api/v1/range/{NTLM_DIGEST[:6]}.txt",
        body=f"{NTLM_DIGEST}\n",
    )
    result = checker().check(NTLM_DIGEST, Algorithm.NTLM)
    assert responses.calls[0].request.params["type"] == "ntlm"
    assert responses.calls[0].request.params["filter"] == "hash"
    assert result.hit is True


@responses.activate
def test_fetch_logs_the_outbound_call_at_info(caplog):
    responses.get(URL, body=f"{PASSWORD_HASH}\n")
    with caplog.at_level(logging.INFO, logger="amiweak.checks.weakpass"):
        checker().check(PASSWORD_HASH, Algorithm.SHA1)
    messages = [record.getMessage() for record in caplog.records]
    assert messages == ["weakpass: fetching range for sha1"]
    # The prefix is part of the hash and must never reach a log line.
    assert PREFIX not in messages[0]
