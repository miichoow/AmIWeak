import hashlib

import pytest

from amiweak.digest_store import CacheFile, read_cache, write_cache

FP = hashlib.sha256(b"inputs").digest()
D1 = hashlib.sha1(b"a").digest()
D2 = hashlib.sha1(b"b").digest()
DIGESTS = sorted({D1, D2})


def test_round_trip(tmp_path):
    p = tmp_path / "c.bin"
    write_cache(p, FP, DIGESTS)
    got = read_cache(p)
    assert got == CacheFile(FP, DIGESTS)


def test_missing_file_returns_none(tmp_path):
    assert read_cache(tmp_path / "nope.bin") is None


def test_write_rejects_a_short_fingerprint(tmp_path):
    with pytest.raises(ValueError, match="32 bytes"):
        write_cache(tmp_path / "c.bin", b"too-short", DIGESTS)


def test_bad_magic_returns_none(tmp_path):
    p = tmp_path / "c.bin"
    write_cache(p, FP, DIGESTS)
    data = bytearray(p.read_bytes())
    data[0] = ord("X")
    p.write_bytes(bytes(data))
    assert read_cache(p) is None


def test_wrong_format_version_returns_none(tmp_path):
    p = tmp_path / "c.bin"
    write_cache(p, FP, DIGESTS)
    data = bytearray(p.read_bytes())
    data[4] = 99  # flip format_version byte to invalid value
    p.write_bytes(bytes(data))
    assert read_cache(p) is None


def test_truncated_body_returns_none(tmp_path):
    p = tmp_path / "c.bin"
    write_cache(p, FP, DIGESTS)
    data = p.read_bytes()
    p.write_bytes(data[:-1])  # drop one byte of the last digest
    assert read_cache(p) is None


def test_count_body_mismatch_returns_none(tmp_path):
    p = tmp_path / "c.bin"
    write_cache(p, FP, DIGESTS)
    data = p.read_bytes()
    p.write_bytes(data + D1)  # extra digest the header count does not cover
    assert read_cache(p) is None


def test_header_shorter_than_frame_returns_none(tmp_path):
    p = tmp_path / "c.bin"
    p.write_bytes(b"AMWK")  # only 4 bytes, header needs 41
    assert read_cache(p) is None


def test_write_is_atomic_no_temp_left(tmp_path):
    p = tmp_path / "c.bin"
    write_cache(p, FP, DIGESTS)
    leftovers = [q.name for q in tmp_path.iterdir() if ".tmp." in q.name]
    assert leftovers == []
