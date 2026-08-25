"""The OpenAPI document and the in-browser console.

Both routes are registered unconditionally and check `docs.enabled` per
request, so the application has one shape rather than two and the disabled path
is reachable in tests without building the app differently.

Disabled returns 404, not 403: a 403 confirms the route exists, and a surface
an operator has switched off should not advertise itself. `check_batch` sets
the same precedent for `batch.enabled`.
"""

from __future__ import annotations

from flask import Blueprint, abort, current_app, jsonify, render_template, request
from flask.wrappers import Response

from amiweak.app import context

bp = Blueprint("docs", __name__)


def _require_enabled() -> None:
    if not context(current_app).config.docs.enabled:
        abort(404)


@bp.get("/api/v1/openapi.json")
def specification() -> Response:
    """The OpenAPI document, parsed at startup and served as JSON.

    `servers[0].url` is overridden per-request to `request.script_root`
    (empty at domain root, e.g. "/amiweak" behind a proxy mounting us under a
    path) so Swagger UI's "try it out" targets the right prefix instead of
    the hardcoded "/" baked into openapi.yaml.
    """
    _require_enabled()
    spec = dict(context(current_app).openapi)
    spec["servers"] = [{"url": request.script_root or "/", "description": "This server."}]
    return jsonify(spec)


@bp.get("/docs")
def console() -> str:
    """Swagger UI, pointed at this server's own specification."""
    _require_enabled()
    return render_template("docs.html")
