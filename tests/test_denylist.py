import hashlib
import os

import pytest

from amiweak.config import ConfigError, DenylistConfig, load_config
from amiweak.denylist import (
    Denylist,
    _bucket,
    _fingerprint,
    _read_entries,
    generate_digests,
    normalize,
)


def sha1(word: str) -> bytes:
    return hashlib.sha1(word.encode("utf-8")).digest()


def test_normalize_lowercases():
    assert normalize("ACME") == "acme"


def test_normalize_decodes_leet_and_strips_punctuation():
    # 4cm3-2026!  ->  acme2o26i (4 -> a, 3 -> e, 0 -> o, punctuation dropped)
    assert "acme" in normalize("4cm3!")


def test_normalize_symbol_leet_becomes_letters():
    assert normalize("@dm1n$") == "admins"


def test_normalize_drops_all_non_alphanumeric():
    assert normalize("h-s-m") == "hsm"


def test_normalize_empty_when_all_symbols_after_decode():
    assert normalize("._-") == ""


def test_generate_hashes_each_entry_with_no_rules():
    out = generate_digests(["acme", "hsm"], (), 100)
    assert set(out) == {sha1("acme"), sha1("hsm")}
    assert out == sorted(out)  # sorted


def test_generate_includes_rule_expansions(tmp_path):
    rule = tmp_path / "r.rule"
    rule.write_text(":\nu\n", encoding="utf-8")  # passthrough + uppercase
    out = set(generate_digests(["acme"], (str(rule),), 100))
    assert sha1("acme") in out
    assert sha1("ACME") in out


def test_generate_aborts_over_max_digests(tmp_path):
    rule = tmp_path / "r.rule"
    rule.write_text(":\nu\n$1\n$2\n$3\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        generate_digests(["acme", "hsm"], (str(rule),), 2)


def test_generate_invalid_rule_is_config_error(tmp_path):
    rule = tmp_path / "bad.rule"
    rule.write_text("$\n", encoding="utf-8")  # missing argument -> InvalidRule
    with pytest.raises(ConfigError):
        generate_digests(["acme"], (str(rule),), 100)


def test_generate_missing_rule_file_is_config_error():
    with pytest.raises(ConfigError):
        generate_digests(["acme"], ("does-not-exist.rule",), 100)


def test_read_entries_skips_comments_and_blanks(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("# comment\n\nacme\n  widget  \n", encoding="utf-8")
    assert _read_entries(f, 4) == ["acme", "widget"]


def test_read_entries_rejects_short_entry_by_line_number(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("acme\nhsm\n", encoding="utf-8")  # "hsm" normalizes to 3 chars < 4
    with pytest.raises(ConfigError) as exc:
        _read_entries(f, 4)
    assert "line 2" in str(exc.value)
    assert "hsm" not in str(exc.value)  # never echo the entry


def test_read_entries_missing_file_is_config_error_not_os_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        _read_entries(tmp_path / "nope.txt", 4)


def test_bucket_groups_by_five_char_prefix():
    d = sha1("acme")
    buckets = _bucket([d])
    hx = d.hex()
    assert buckets[hx[:5]] == {hx[5:]: None}


def test_denylist_matches_substring_after_normalization():
    dl = Denylist(tokens=("acme",), buckets={})
    assert dl.matches("ACME2026!") is True
    assert dl.matches("winter-blue-summer") is False


def _config(tmp_path, **overrides):
    """A Config whose denylist points at files under tmp_path."""
    cfg = load_config(None, env={})
    fields = {
        "path": str(tmp_path / "d.txt"),
        "min_token_length": 4,
        "match_plaintext": True,
        "rules": (),
        "max_digests": 1000,
        "cache_path": str(tmp_path / "d.bin"),
    }
    fields.update(overrides)
    dl = DenylistConfig(**fields)
    object.__setattr__(cfg, "denylist", dl)
    return cfg


def test_load_returns_none_when_path_is_null():
    cfg = load_config(None, env={})  # denylist.path defaults to None
    assert Denylist.load(cfg) is None


def test_load_with_missing_rule_file_raises_config_error_not_os_error(tmp_path):
    (tmp_path / "d.txt").write_text("acme\n", encoding="utf-8")
    cfg = _config(tmp_path, rules=("does-not-exist.rule",))
    with pytest.raises(ConfigError):
        Denylist.load(cfg)


def test_load_generates_then_reuses_cache(tmp_path, monkeypatch):
    (tmp_path / "d.txt").write_text("acme\nwidget\n", encoding="utf-8")
    cfg = _config(tmp_path)

    dl1 = Denylist.load(cfg)
    assert dl1 is not None
    assert (tmp_path / "d.bin").exists()
    assert sha1("acme") in {bytes.fromhex(p + s) for p, d in dl1.buckets.items() for s in d}

    import amiweak.denylist as mod

    calls = []
    real = mod.generate_digests
    monkeypatch.setattr(mod, "generate_digests", lambda *a: calls.append(1) or real(*a))
    dl2 = Denylist.load(cfg)
    assert dl2 is not None
    assert calls == []  # second load reused the cache, never regenerated


def test_editing_the_dictionary_invalidates_the_cache(tmp_path, monkeypatch):
    (tmp_path / "d.txt").write_text("acme\n", encoding="utf-8")
    cfg = _config(tmp_path)
    Denylist.load(cfg)

    (tmp_path / "d.txt").write_text("acme\ngadget\n", encoding="utf-8")
    import amiweak.denylist as mod

    calls = []
    real = mod.generate_digests
    monkeypatch.setattr(mod, "generate_digests", lambda *a: calls.append(1) or real(*a))
    Denylist.load(cfg)
    assert calls == [1]  # changed input forced regeneration


def test_generator_version_is_in_the_fingerprint(tmp_path, monkeypatch):
    (tmp_path / "d.txt").write_text("acme\n", encoding="utf-8")
    fp1 = _fingerprint(str(tmp_path / "d.txt"), ())
    monkeypatch.setattr("amiweak.denylist.GENERATOR_VERSION", 999)
    fp2 = _fingerprint(str(tmp_path / "d.txt"), ())
    assert fp1 != fp2


def test_corrupt_cache_is_rebuilt(tmp_path):
    (tmp_path / "d.txt").write_text("acme\n", encoding="utf-8")
    cfg = _config(tmp_path)
    Denylist.load(cfg)
    (tmp_path / "d.bin").write_bytes(b"garbage")  # not a valid cache file
    dl = Denylist.load(cfg)  # must not raise; regenerates
    assert dl is not None and dl.buckets


def test_touching_mtime_without_content_change_does_not_regenerate(tmp_path, monkeypatch):
    (tmp_path / "d.txt").write_text("acme\n", encoding="utf-8")
    cfg = _config(tmp_path)
    Denylist.load(cfg)
    os.utime(tmp_path / "d.txt", None)  # bump mtime, identical bytes
    import amiweak.denylist as mod

    calls = []
    real = mod.generate_digests
    monkeypatch.setattr(mod, "generate_digests", lambda *a: calls.append(1) or real(*a))
    Denylist.load(cfg)
    assert calls == []


def test_a_sibling_worker_winning_the_race_is_reused(tmp_path, monkeypatch):
    """Between the pre-lock check and acquiring the lock, a sibling worker may
    have already generated and written the cache; the re-check under the lock
    must reuse it rather than regenerating."""
    import amiweak.denylist as mod
    from amiweak.digest_store import CacheFile

    (tmp_path / "d.txt").write_text("acme\n", encoding="utf-8")
    cfg = _config(tmp_path)
    fingerprint = mod._fingerprint(cfg.denylist.path, cfg.denylist.rules)
    winning = CacheFile(fingerprint=fingerprint, digests=[sha1("acme")])

    calls = []
    responses = iter([None, winning])
    monkeypatch.setattr(mod, "read_cache", lambda path: next(responses))
    monkeypatch.setattr(mod, "generate_digests", lambda *a: calls.append(1))

    dl = Denylist.load(cfg)
    assert dl is not None
    assert calls == []  # never regenerated: the re-check under the lock won


def test_a_lock_timeout_is_a_config_error(tmp_path, monkeypatch):
    from filelock import Timeout

    import amiweak.denylist as mod

    (tmp_path / "d.txt").write_text("acme\n", encoding="utf-8")
    cfg = _config(tmp_path)

    class _AlwaysTimesOut:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            raise Timeout("lockfile")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(mod, "FileLock", _AlwaysTimesOut)
    with pytest.raises(ConfigError, match="timed out"):
        Denylist.load(cfg)


def test_a_write_failure_is_a_config_error(tmp_path, monkeypatch):
    import amiweak.denylist as mod

    (tmp_path / "d.txt").write_text("acme\n", encoding="utf-8")
    cfg = _config(tmp_path)

    def broken_write(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(mod, "write_cache", broken_write)
    with pytest.raises(ConfigError, match="cannot write the digest cache"):
        Denylist.load(cfg)


def test_shipped_corporate_rule_loads_and_expands():
    from pathlib import Path

    rule = str(Path(__file__).resolve().parents[1] / "rules" / "corporate.rule")
    out = generate_digests(["acme"], (rule,), 100_000)
    assert sha1("acme") in out  # passthrough kept the literal
    assert sha1("ACME") in out  # a case variant was produced
    assert len(out) > 5  # several mutations, not just the literal
