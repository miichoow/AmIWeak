"""Monitoring endpoints."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify
from flask.wrappers import Response

from amiweak import __version__
from amiweak.app import context
from amiweak.prometheus import CONTENT_TYPE, render

bp = Blueprint("ops", __name__)


@bp.get("/healthz")
def healthz() -> Response:
    """Liveness plus last-known backend state.

    This reports what real traffic has already observed rather than probing the
    upstreams itself. A health endpoint that made outbound calls would turn any
    monitoring system into an amplifier against HIBP.
    """
    ctx = context(current_app)
    health = ctx.metrics.health()

    checks = {}
    degraded = False
    for name, check_config in ctx.config.checks.items():
        state = health.get(name, {"last_ok": None, "last_error": None})
        checks[name] = {
            "enabled": check_config.enabled,
            "last_ok": state.get("last_ok"),
            "last_error": state.get("last_error"),
        }
        if check_config.enabled and state.get("last_error"):
            degraded = True

    if ctx.config.strength.enabled:
        state = health.get("zxcvbn", {"last_ok": None, "last_error": None})
        checks["zxcvbn"] = {
            "enabled": True,
            "last_ok": state.get("last_ok"),
            "last_error": state.get("last_error"),
        }
        if state.get("last_error"):
            degraded = True

    return jsonify(
        {
            "status": "degraded" if degraded else "ok",
            "version": __version__,
            "uptime_seconds": ctx.metrics.uptime_seconds(),
            "checks": checks,
        }
    )


@bp.get("/metrics")
def metrics() -> Response:
    ctx = context(current_app)
    return jsonify(ctx.metrics.snapshot())


@bp.get("/metrics/prometheus")
def metrics_prometheus() -> Response:
    """The same counters as /metrics, in the format every scraper reads.

    Deliberately a second path rather than a replacement: /metrics is documented
    and dashboards already read it, and adding a route costs a line where moving
    one costs every consumer.

    Not gated by docs.enabled -- that switch exists because the API console
    fires real requests at an endpoint taking plaintext passwords, which has
    nothing to do with a counter dump.
    """
    ctx = context(current_app)
    health = ctx.metrics.health()

    # render() is a pure function with no config access, so a disabled check's
    # stale last_error would otherwise report amiweak_backend_healthy as 0
    # forever -- even after a restart, since state.path persists health in
    # SQLite. Clear last_error here for anything /healthz would also exempt
    # from `degraded`, so the two endpoints agree on the same backend state.
    disabled_backends = {name for name, check in ctx.config.checks.items() if not check.enabled}
    if not ctx.config.strength.enabled:
        disabled_backends.add("zxcvbn")
    effective_health = {
        name: ({**state, "last_error": None} if name in disabled_backends else state)
        for name, state in health.items()
    }

    body = render(ctx.metrics.snapshot(), effective_health, __version__)
    response = current_app.response_class(body)
    response.headers["Content-Type"] = CONTENT_TYPE
    return response
