"""Parse real captured range responses.

The hand-written parser tests use invented bodies, which only prove the parser
matches my assumptions about the format. These fixtures are verbatim slices of
live responses from both providers, so they prove the assumptions themselves —
that HIBP suffixes are 35 characters, that `Add-Padding` really does inject
count-zero rows (131 of them in the captured response), and that weakpass emits
lowercase full hashes.

Regenerate with the commands in the fixture README if a provider changes format.
"""

from pathlib import Path

from amiweak.checks.hibp import parse_hibp_range
from amiweak.checks.weakpass import parse_weakpass_range
from amiweak.hashing import sha1_hex

FIXTURES = Path(__file__).parent.parent / "fixtures"
PASSWORD_HASH = sha1_hex("password")


def read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_hibp_finds_the_known_password_in_a_real_response():
    body = (FIXTURES / "hibp_range_5BAA6.txt").read_text(encoding="utf-8")
    counts = parse_hibp_range(body)
    assert counts[PASSWORD_HASH[5:].upper()] == 52372427


def test_hibp_discards_the_real_padding_rows():
    body = (FIXTURES / "hibp_range_5BAA6.txt").read_text(encoding="utf-8")
    counts = parse_hibp_range(body)
    # Four of the eight captured rows are padding.
    assert len(counts) == 4
    assert all(count > 0 for count in counts.values())


def test_hibp_suffix_length_matches_the_hash_we_look_up():
    body = (FIXTURES / "hibp_range_5BAA6.txt").read_text(encoding="utf-8")
    assert all(len(suffix) == 35 for suffix in parse_hibp_range(body))
    assert len(PASSWORD_HASH[5:]) == 35


def test_weakpass_finds_the_known_password_in_a_real_response():
    body = (FIXTURES / "weakpass_range_5baa61.txt").read_text(encoding="utf-8")
    hashes = parse_weakpass_range(body)
    assert PASSWORD_HASH in hashes
    assert all(len(value) == 40 for value in hashes)


NTLM_PASSWORD_DIGEST = "8846f7eaee8fb117ad06bdd830b7586c"


def test_the_real_hibp_ntlm_range_parses_and_contains_a_known_hit():
    body = read_fixture("hibp_ntlm_range.txt")
    parsed = parse_hibp_range(body)
    assert parsed, "the fixture parsed to nothing — has the wire format changed?"
    assert all(len(suffix) == 27 for suffix in parsed), "NTLM suffixes are 27 characters"
    assert parsed[NTLM_PASSWORD_DIGEST.upper()[5:]] > 0


def test_the_real_weakpass_ntlm_range_parses_and_contains_a_known_hit():
    parsed = parse_weakpass_range(read_fixture("weakpass_ntlm_range.txt"))
    assert parsed, "the fixture parsed to nothing — has the wire format changed?"
    assert NTLM_PASSWORD_DIGEST in parsed


def test_the_weakpass_ntlm_fixture_carries_no_plaintext():
    """filter=hash suppresses the recovered password. Prove the fixture agrees."""
    body = read_fixture("weakpass_ntlm_range.txt")
    assert "password" not in body.lower()
    assert ":" not in body
