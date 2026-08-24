from __future__ import annotations

import re

import pytest

from amiweak import __version__
from amiweak.algorithms import Algorithm
from amiweak.prometheus import escape_label_value, format_family, format_sample, render


def test_escape_handles_backslash_quote_and_newline() -> None:
    assert escape_label_value(r"a\b") == r"a\\b"
    assert escape_label_value('a"b') == r"a\"b"
    assert escape_label_value("a\nb") == r"a\nb"


def test_escape_leaves_ordinary_values_alone() -> None:
    assert escape_label_value("hibp") == "hibp"


def test_sample_without_labels_has_no_braces() -> None:
    assert format_sample("amiweak_checks_total", {}, 7) == "amiweak_checks_total 7"


def test_sample_with_labels_renders_them_sorted() -> None:
    line = format_sample(
        "amiweak_backend_algorithm_total", {"backend": "hibp", "algorithm": "ntlm"}, 3
    )
    assert line == 'amiweak_backend_algorithm_total{algorithm="ntlm",backend="hibp"} 3'


def test_integral_values_render_without_a_decimal_point() -> None:
    assert format_sample("m", {}, 1000000.0) == "m 1000000"


def test_fractional_values_keep_precision() -> None:
    assert format_sample("m", {}, 0.25) == "m 0.25"


def test_family_emits_help_and_type_then_samples() -> None:
    lines = format_family(
        "amiweak_verdicts_total",
        "counter",
        "Verdicts resolved, by verdict.",
        [({"verdict": "safe"}, 2), ({"verdict": "leaked"}, 1)],
    )
    assert lines == [
        "# HELP amiweak_verdicts_total Verdicts resolved, by verdict.",
        "# TYPE amiweak_verdicts_total counter",
        'amiweak_verdicts_total{verdict="safe"} 2',
        'amiweak_verdicts_total{verdict="leaked"} 1',
    ]


def test_family_with_no_samples_still_declares_itself() -> None:
    """A scraper should see the metric exists at zero, not that it vanished."""
    lines = format_family("amiweak_batch_items_total", "counter", "Items.", [])
    assert lines == [
        "# HELP amiweak_batch_items_total Items.",
        "# TYPE amiweak_batch_items_total counter",
    ]


def test_help_text_escapes_backslash_and_newline() -> None:
    lines = format_family("m", "gauge", "a\\b\nc", [])
    assert lines[0] == "# HELP m a\\\\b\\nc"


SNAPSHOT = {
    "uptime_seconds": 12.5,
    "checks_total": 3,
    "verdicts_total": {"safe": 2, "leaked": 1},
    "backend_requests_total": {"hibp": 2, "weakpass": 1},
    "backend_errors_total": {"weakpass": 1},
    "backend_latency_seconds": {"hibp": {"count": 2, "sum": 0.5, "max": 0.3}},
    "cache_hits_total": {"hibp": 4},
    "cache_misses_total": {"hibp": 1},
    "batch_requests_total": 1,
    "batch_items_total": 10,
    "backend_algorithm_total": {"hibp": {"sha1": 1, "ntlm": 1}},
    "store_errors_total": 0,
}
HEALTH = {
    "hibp": {"last_ok": "2026-08-19T10:00:00Z", "last_error": None},
    "weakpass": {"last_ok": None, "last_error": "timeout"},
}


def _lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line and not line.startswith("#")]


def test_render_emits_scalar_counters() -> None:
    lines = _lines(render(SNAPSHOT, HEALTH, "1.0.0"))
    assert "amiweak_checks_total 3" in lines
    assert "amiweak_batch_requests_total 1" in lines
    assert "amiweak_batch_items_total 10" in lines
    assert "amiweak_store_errors_total 0" in lines


def test_render_emits_labelled_counters() -> None:
    lines = _lines(render(SNAPSHOT, HEALTH, "1.0.0"))
    assert 'amiweak_verdicts_total{verdict="safe"} 2' in lines
    assert 'amiweak_verdicts_total{verdict="leaked"} 1' in lines
    assert 'amiweak_backend_requests_total{backend="hibp"} 2' in lines
    assert 'amiweak_cache_hits_total{backend="hibp"} 4' in lines


def test_render_splits_latency_into_count_sum_and_max() -> None:
    lines = _lines(render(SNAPSHOT, HEALTH, "1.0.0"))
    assert 'amiweak_backend_latency_seconds_count{backend="hibp"} 2' in lines
    assert 'amiweak_backend_latency_seconds_sum{backend="hibp"} 0.5' in lines
    assert 'amiweak_backend_latency_seconds_max{backend="hibp"} 0.3' in lines


def test_render_flattens_the_two_dimensional_algorithm_counter() -> None:
    lines = _lines(render(SNAPSHOT, HEALTH, "1.0.0"))
    assert 'amiweak_backend_algorithm_total{algorithm="sha1",backend="hibp"} 1' in lines
    assert 'amiweak_backend_algorithm_total{algorithm="ntlm",backend="hibp"} 1' in lines


def test_backend_healthy_mirrors_the_healthz_rule() -> None:
    lines = _lines(render(SNAPSHOT, HEALTH, "1.0.0"))
    assert 'amiweak_backend_healthy{backend="hibp"} 1' in lines
    assert 'amiweak_backend_healthy{backend="weakpass"} 0' in lines


def test_build_info_carries_the_version() -> None:
    lines = _lines(render(SNAPSHOT, HEALTH, "1.0.0"))
    assert 'amiweak_build_info{version="1.0.0"} 1' in lines


def test_every_family_declares_help_and_type() -> None:
    text = render(SNAPSHOT, HEALTH, "1.0.0")
    names = {line.split()[0] for line in _lines(text)}
    stripped = {n.split("{")[0] for n in names}
    for name in stripped:
        assert f"# HELP {name} " in text, f"{name} has no HELP"
        assert f"# TYPE {name} " in text, f"{name} has no TYPE"


def test_no_duplicate_series() -> None:
    lines = _lines(render(SNAPSHOT, HEALTH, "1.0.0"))
    series = [line.rsplit(" ", 1)[0] for line in lines]
    assert len(series) == len(set(series)), "a series is emitted twice"


def test_every_line_is_well_formed() -> None:
    for line in _lines(render(SNAPSHOT, HEALTH, "1.0.0")):
        name, _, value = line.rpartition(" ")
        assert name, f"no metric name in {line!r}"
        float(value)  # raises if the value is not a number


def test_render_survives_an_empty_snapshot() -> None:
    empty = {
        "uptime_seconds": 0.0,
        "checks_total": 0,
        "verdicts_total": {},
        "backend_requests_total": {},
        "backend_errors_total": {},
        "backend_latency_seconds": {},
        "cache_hits_total": {},
        "cache_misses_total": {},
        "batch_requests_total": 0,
        "batch_items_total": 0,
        "backend_algorithm_total": {},
        "store_errors_total": 0,
    }
    text = render(empty, {}, "1.0.0")
    assert "amiweak_checks_total 0" in _lines(text)
    assert "# TYPE amiweak_verdicts_total counter" in text


def test_numbers_agree_with_the_json_snapshot() -> None:
    """The two endpoints must never disagree, since they read one source."""
    lines = _lines(render(SNAPSHOT, HEALTH, "1.0.0"))
    by_series = {line.rsplit(" ", 1)[0]: float(line.rsplit(" ", 1)[1]) for line in lines}
    assert by_series["amiweak_checks_total"] == SNAPSHOT["checks_total"]
    assert by_series['amiweak_verdicts_total{verdict="safe"}'] == 2
    assert by_series["amiweak_uptime_seconds"] == pytest.approx(12.5)


LABEL_PATTERN = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

ALLOWED_LABEL_VALUES = {
    # Verdicts.
    "safe",
    "leaked",
    "precomputed",
    "denylisted",
    "weak",
    "too_short",
    "error",
    # Backends.
    "hibp",
    "weakpass",
    "denylist",
    "zxcvbn",
    # Algorithms.
    *(algorithm.value for algorithm in Algorithm),
    # Build.
    __version__,
}


def test_every_emitted_label_value_is_in_the_closed_set() -> None:
    text = render(SNAPSHOT, HEALTH, __version__)
    seen = {match.group(2) for match in LABEL_PATTERN.finditer(text)}
    unexpected = seen - ALLOWED_LABEL_VALUES
    assert not unexpected, (
        f"label values outside the closed set: {sorted(unexpected)}. "
        "A label derived from user input would be a side channel for a password."
    )


def test_a_hostile_label_value_cannot_break_the_format() -> None:
    """Escaping is applied even though nothing today needs it."""
    hostile = dict(SNAPSHOT)
    hostile["verdicts_total"] = {'evil" injected="yes': 1, "with\nnewline": 2}

    text = render(hostile, {}, __version__)
    for line in text.splitlines():
        if line.startswith("#") or not line:
            continue
        name, _, value = line.rpartition(" ")
        assert name
        float(value)  # still parseable: the injection did not create a new field

    assert r"\"" in text
    assert r"\n" in text
