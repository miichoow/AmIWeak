"""Prometheus text exposition, rendered from the same snapshot /metrics serves.

This module holds no state and imports no Flask. It reformats what
`amiweak.metrics.Metrics` already has, which is what guarantees the JSON and
text views can never disagree about a number.

Every label value emitted here comes from a closed set -- the fixed verdict
names, backend names, algorithm names, and the version string. None derives from
a password, a hash, an account label, or a client address. Values are escaped
anyway, and `tests/test_prometheus.py` asserts the closed set, because the
guarantee should hold structurally rather than because today's callers behave.
"""

from __future__ import annotations

from typing import Any

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def escape_label_value(value: str) -> str:
    """Escape per the exposition format: backslash, double quote, newline."""
    return value.replace("\\", r"\\").replace('"', r"\"").replace("\n", r"\n")


def _escape_help(text: str) -> str:
    """HELP escapes backslash and newline, but not quotes."""
    return text.replace("\\", r"\\").replace("\n", r"\n")


def _render_value(value: float) -> str:
    """Integral values render without a decimal point; others keep precision."""
    number = float(value)
    if number.is_integer():
        return str(int(number))
    return repr(number)


def format_sample(name: str, labels: dict[str, str], value: float) -> str:
    if not labels:
        return f"{name} {_render_value(value)}"
    rendered = ",".join(f'{key}="{escape_label_value(labels[key])}"' for key in sorted(labels))
    return f"{name}{{{rendered}}} {_render_value(value)}"


def format_family(
    name: str,
    kind: str,
    help_text: str,
    samples: list[tuple[dict[str, str], float]],
) -> list[str]:
    """A family always declares itself, even with no samples.

    A scraper should see that a metric exists and is empty rather than see it
    disappear, which is indistinguishable from the exporter breaking.
    """
    lines = [
        f"# HELP {name} {_escape_help(help_text)}",
        f"# TYPE {name} {kind}",
    ]
    lines.extend(format_sample(name, labels, value) for labels, value in samples)
    return lines


NAMESPACE = "amiweak"


def _scalar_families(snapshot: dict[str, Any], version: str) -> list[list[str]]:
    return [
        format_family(
            f"{NAMESPACE}_build_info",
            "gauge",
            "Build information. Always 1; read the version label.",
            [({"version": version}, 1)],
        ),
        format_family(
            f"{NAMESPACE}_uptime_seconds",
            "gauge",
            "Seconds since this worker process started. Per worker, not per deployment.",
            [({}, float(snapshot["uptime_seconds"]))],
        ),
        format_family(
            f"{NAMESPACE}_checks_total",
            "counter",
            "Verdicts resolved. Counts items, not requests: a 1000-item batch moves this by 1000.",
            [({}, float(snapshot["checks_total"]))],
        ),
        format_family(
            f"{NAMESPACE}_batch_requests_total",
            "counter",
            "Batch check requests served.",
            [({}, float(snapshot["batch_requests_total"]))],
        ),
        format_family(
            f"{NAMESPACE}_batch_items_total",
            "counter",
            "Items across every batch request, regardless of verdict.",
            [({}, float(snapshot["batch_items_total"]))],
        ),
        format_family(
            f"{NAMESPACE}_store_errors_total",
            "counter",
            "State store operations that fell back to per-process state.",
            [({}, float(snapshot.get("store_errors_total", 0)))],
        ),
    ]


def _labelled(mapping: dict[str, Any], label: str) -> list[tuple[dict[str, str], float]]:
    return [({label: key}, float(value)) for key, value in mapping.items()]


def _keyed_families(snapshot: dict[str, Any]) -> list[list[str]]:
    latency = snapshot["backend_latency_seconds"]
    return [
        format_family(
            f"{NAMESPACE}_verdicts_total",
            "counter",
            "Verdicts resolved, by verdict.",
            _labelled(snapshot["verdicts_total"], "verdict"),
        ),
        format_family(
            f"{NAMESPACE}_backend_requests_total",
            "counter",
            "Prefix fetches per backend, not checks: a cache hit does not increment this.",
            _labelled(snapshot["backend_requests_total"], "backend"),
        ),
        format_family(
            f"{NAMESPACE}_backend_errors_total",
            "counter",
            "Prefix fetches that failed, by backend.",
            _labelled(snapshot["backend_errors_total"], "backend"),
        ),
        # A summary without quantiles. Count and sum are the summary pair; max
        # is a separate gauge, because a quantile="1" label would claim a real
        # quantile estimate this data does not contain.
        format_family(
            f"{NAMESPACE}_backend_latency_seconds_count",
            "counter",
            "Prefix fetches timed, by backend.",
            [({"backend": name}, float(e["count"])) for name, e in latency.items()],
        ),
        format_family(
            f"{NAMESPACE}_backend_latency_seconds_sum",
            "counter",
            "Total seconds spent fetching prefixes, by backend.",
            [({"backend": name}, float(e["sum"])) for name, e in latency.items()],
        ),
        format_family(
            f"{NAMESPACE}_backend_latency_seconds_max",
            "gauge",
            "Slowest prefix fetch observed, by backend.",
            [({"backend": name}, float(e["max"])) for name, e in latency.items()],
        ),
        format_family(
            f"{NAMESPACE}_backend_algorithm_total",
            "counter",
            "Successful prefix fetches, by backend and digest algorithm.",
            [
                ({"backend": backend, "algorithm": algorithm}, float(value))
                for backend, algorithms in snapshot["backend_algorithm_total"].items()
                for algorithm, value in algorithms.items()
            ],
        ),
        format_family(
            f"{NAMESPACE}_cache_hits_total",
            "counter",
            "Prefix cache hits, by backend.",
            _labelled(snapshot["cache_hits_total"], "backend"),
        ),
        format_family(
            f"{NAMESPACE}_cache_misses_total",
            "counter",
            "Prefix cache misses, by backend.",
            _labelled(snapshot["cache_misses_total"], "backend"),
        ),
    ]


def _health_family(health: dict[str, dict[str, Any]]) -> list[str]:
    # 1 when the most recent outcome was not an error -- exactly the rule
    # /healthz uses to decide `degraded`, so that signal is alertable without
    # scraping and parsing a second endpoint.
    return format_family(
        f"{NAMESPACE}_backend_healthy",
        "gauge",
        "1 when the backend's most recent outcome was not an error, else 0.",
        [
            ({"backend": name}, 0.0 if state.get("last_error") else 1.0)
            for name, state in health.items()
        ],
    )


def render(snapshot: dict[str, Any], health: dict[str, dict[str, Any]], version: str) -> str:
    """Render one scrape. `snapshot` is Metrics.snapshot(), `health` is Metrics.health()."""
    families = [
        *_scalar_families(snapshot, version),
        *_keyed_families(snapshot),
        _health_family(health),
    ]
    lines: list[str] = []
    for family in families:
        lines.extend(family)
    return "\n".join(lines) + "\n"
