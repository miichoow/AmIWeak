import pytest

from amiweak.algorithms import Algorithm, is_valid_digest, parse_algorithm

SHA1_DIGEST = "a" * 40
NTLM_DIGEST = "8846f7eaee8fb117ad06bdd830b7586c"


def test_digest_length_per_algorithm():
    assert Algorithm.SHA1.digest_length == 40
    assert Algorithm.NTLM.digest_length == 32


def test_parse_algorithm_accepts_known_names():
    assert parse_algorithm("sha1") is Algorithm.SHA1
    assert parse_algorithm("ntlm") is Algorithm.NTLM


def test_parse_algorithm_is_case_insensitive():
    assert parse_algorithm("NTLM") is Algorithm.NTLM


def test_parse_algorithm_rejects_unknown():
    with pytest.raises(ValueError):
        parse_algorithm("md5")


def test_parse_algorithm_rejects_non_string():
    with pytest.raises(ValueError):
        parse_algorithm(None)


def test_valid_digest_accepts_correct_length_hex():
    assert is_valid_digest(SHA1_DIGEST, Algorithm.SHA1)
    assert is_valid_digest(NTLM_DIGEST, Algorithm.NTLM)


def test_valid_digest_is_case_insensitive():
    assert is_valid_digest(NTLM_DIGEST.upper(), Algorithm.NTLM)


def test_valid_digest_rejects_wrong_length():
    assert not is_valid_digest(SHA1_DIGEST, Algorithm.NTLM)
    assert not is_valid_digest(NTLM_DIGEST, Algorithm.SHA1)


def test_valid_digest_rejects_non_hex():
    assert not is_valid_digest("z" * 32, Algorithm.NTLM)


def test_valid_digest_rejects_non_string():
    assert not is_valid_digest(None, Algorithm.NTLM)
