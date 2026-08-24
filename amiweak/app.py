"""The Flask application factory."""

from __future__ import annotations

import atexit
import mimetypes
import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from flask import Flask, Response

from amiweak.algorithms import Algorithm
from amiweak.cache import PrefixCache
from amiweak.checks.base import Checker
from amiweak.checks.denylist import DenylistChecker
from amiweak.checks.hibp import HibpChecker
from amiweak.checks.runner import BatchItem, BatchOutcome, CheckRunner, Evaluation
from amiweak.checks.weakpass import WeakpassChecker
from amiweak.config import Config, load_config
from amiweak.denylist import Denylist
from amiweak.http import build_session
from amiweak.logging_setup import configure_logging
from amiweak.metrics import Metrics
from amiweak.openapi import DEFAULT_SPEC_PATH, load_spec
from amiweak.rate_limit import TokenBucket
from amiweak.store import StateStore, build_store
from amiweak.strength import StrengthScorer

DEFAULT_CONFIG_PATH = "config.yaml"

# Windows has no registry entry for woff2, so the vendored theme fonts would go
# out as application/octet-stream. Browsers accept that for @font-face, but a
# caching proxy in front of us has no reason to.
mimetypes.add_type("font/woff2", ".woff2")

CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'none'; form-action 'none'; "
    "object-src 'none'; frame-ancestors 'none'"
)


class Evaluator(Protocol):
    def evaluate(self, password: str) -> Evaluation: ...
    def evaluate_digest(self, digest: str, algorithm: Algorithm) -> Evaluation: ...
    def supports(self, algorithm: Algorithm) -> bool: ...
    def prefix_cost(self, items: Sequence[BatchItem], algorithm: Algorithm) -> int: ...
    def evaluate_batch(
        self, items: Sequence[BatchItem], algorithm: Algorithm
    ) -> list[BatchOutcome]: ...


@dataclass(frozen=True)
class AppContext:
    """Everything a request handler needs, hung off `app.extensions`."""

    config: Config
    runner: Evaluator
    metrics: Metrics
    store: StateStore
    limiter: TokenBucket
    batch_limiter: TokenBucket
    strength: StrengthScorer | None
    openapi: dict[str, Any]


def context(app: Flask) -> AppContext:
    return app.extensions["amiweak"]  # type: ignore[no-any-return]


def _build_strength(config: Config) -> StrengthScorer | None:
    if not config.strength.enabled:
        return None
    scorer = StrengthScorer(timeout=config.strength.timeout)
    atexit.register(scorer.close)
    return scorer


def _build_runner(
    config: Config, metrics: Metrics, cache: PrefixCache, strength: StrengthScorer | None
) -> CheckRunner:
    session = build_session(config.http, config.proxy)
    denylist = Denylist.load(config)  # None when denylist.path is null; startup errors propagate
    checkers: list[Checker] = []
    if config.checks["hibp"].enabled:
        checkers.append(HibpChecker(session, config.checks["hibp"]))
    if config.checks["weakpass"].enabled:
        checkers.append(WeakpassChecker(session, config.checks["weakpass"]))
    if denylist is not None and config.checks["denylist"].enabled:
        checkers.append(DenylistChecker(denylist.buckets, config.checks["denylist"]))
    return CheckRunner(
        checkers,
        config,
        metrics=metrics,
        cache=cache,
        strength=strength,
        denylist=denylist,
    )


def _security_headers(response: Response) -> Response:
    # no-store matters most: a shared cache holding a check result would be a
    # small leak, and the browser back button replaying the form a bigger one.
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    return response


def create_app(
    config: Config | None = None,
    runner: Evaluator | None = None,
    metrics: Metrics | None = None,
    store: StateStore | None = None,
) -> Flask:
    """Build the application. Pass `runner`, `metrics`, or `store` to substitute them in tests."""
    if config is None:
        config = load_config(os.environ.get("AMIWEAK_CONFIG", DEFAULT_CONFIG_PATH))
    configure_logging(config.logging)

    # Parsed once, here, so a malformed document fails the process at startup
    # rather than 500ing the first request to /docs. Skipped entirely when docs
    # are disabled, so an operator who turns the feature off is not also on the
    # hook for shipping openapi.yaml.
    openapi = (
        load_spec(os.environ.get("AMIWEAK_OPENAPI", DEFAULT_SPEC_PATH))
        if config.docs.enabled
        else {}
    )

    store = store or build_store(config.state)
    atexit.register(store.close)
    metrics = metrics or Metrics(store)
    cache = PrefixCache(config.cache)
    strength = _build_strength(config)
    runner = runner or _build_runner(config, metrics, cache, strength)

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(
        __name__,
        static_folder=os.path.join(root, "static"),
        template_folder=os.path.join(root, "templates"),
    )

    # Unconditional, and after every other config path. The Werkzeug debugger is
    # an interactive Python console; it must never sit behind a form that
    # receives passwords, whatever FLASK_DEBUG happens to say.
    app.debug = False

    app.extensions["amiweak"] = AppContext(
        config=config,
        runner=runner,
        metrics=metrics,
        store=store,
        limiter=TokenBucket(
            requests=config.policy.rate_limit.requests,
            per_seconds=config.policy.rate_limit.per_seconds,
            store=store,
            namespace="policy",
        ),
        batch_limiter=TokenBucket(
            requests=config.batch.rate_limit.prefixes,
            per_seconds=config.batch.rate_limit.per_seconds,
            store=store,
            namespace="batch",
        ),
        strength=strength,
        openapi=openapi,
    )

    from amiweak.routes.api import bp as api_bp
    from amiweak.routes.docs import bp as docs_bp
    from amiweak.routes.ops import bp as ops_bp
    from amiweak.routes.web import bp as web_bp

    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(ops_bp)
    app.register_blueprint(docs_bp)
    app.after_request(_security_headers)
    return app


def envelope(error: bool, message: str, **extra: Any) -> dict[str, Any]:
    """The one response shape every API endpoint returns, success or failure."""
    return {"error": error, "errorMessage": message, **extra}
