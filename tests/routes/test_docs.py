import json
import re
from pathlib import Path

from amiweak.app import create_app
from amiweak.config import load_config


def build(**overrides):
    """An app on the shipped defaults, with `docs.enabled` overridable."""
    env = {}
    if "docs_enabled" in overrides:
        env["AMIWEAK_DOCS__ENABLED"] = "true" if overrides["docs_enabled"] else "false"
    return create_app(config=load_config(None, env=env))


def test_the_specification_is_served_as_json():
    response = build().test_client().get("/api/v1/openapi.json")
    assert response.status_code == 200
    assert response.mimetype == "application/json"
    spec = json.loads(response.get_data(as_text=True))
    assert spec["openapi"].startswith("3.")
    assert "paths" in spec


def test_the_specification_is_404_when_docs_are_disabled():
    response = build(docs_enabled=False).test_client().get("/api/v1/openapi.json")
    assert response.status_code == 404


#: Endpoints that are deliberately absent from the specification. The web page
#: is not an API; the docs surface documenting itself is noise. Matched on
#: `rule.endpoint` rather than `rule.rule`, so this exempts specific
#: (path, method) operations rather than every method Flask ever registers on
#: these three paths -- a future `POST /`, say, would still need a spec entry.
UNDOCUMENTED = {"web.index", "docs.console", "docs.specification"}

#: Flask synthesises these; they are not operations.
SYNTHETIC_METHODS = {"HEAD", "OPTIONS"}


def _registered_operations(app):
    """(path, lowercase method) for every real route."""
    found = set()
    for rule in app.url_map.iter_rules():
        if rule.endpoint == "static" or rule.endpoint in UNDOCUMENTED:
            continue
        for method in rule.methods - SYNTHETIC_METHODS:
            found.add((rule.rule, method.lower()))
    return found


def _documented_operations(spec):
    return {
        (path, method)
        for path, operations in spec["paths"].items()
        for method in operations
        if method in {"get", "post", "put", "patch", "delete"}
    }


def test_every_registered_route_is_documented():
    app = build()
    spec = json.loads(app.test_client().get("/api/v1/openapi.json").get_data(as_text=True))
    missing = _registered_operations(app) - _documented_operations(spec)
    assert not missing, f"routes with no OpenAPI entry: {sorted(missing)}"


def test_every_documented_route_exists():
    app = build()
    spec = json.loads(app.test_client().get("/api/v1/openapi.json").get_data(as_text=True))
    phantom = _documented_operations(spec) - _registered_operations(app)
    assert not phantom, f"documented but not registered: {sorted(phantom)}"


VENDOR = Path("static/vendor/swagger-ui")


def test_vendored_swagger_ui_files_exist_and_are_not_stubs():
    css = VENDOR / "swagger-ui.css"
    assert css.is_file()
    assert css.stat().st_size > 50_000

    bundle = VENDOR / "swagger-ui-bundle.js"
    assert bundle.is_file()
    assert bundle.stat().st_size > 500_000


def test_the_vendored_bundle_exposes_the_global_the_page_uses():
    bundle = (VENDOR / "swagger-ui-bundle.js").read_text(encoding="utf-8", errors="replace")
    assert "SwaggerUIBundle" in bundle


def test_the_standalone_preset_is_not_vendored():
    # It renders a spec-URL input box, which would let a visitor aim the
    # try-it-out button at an arbitrary host.
    assert not (VENDOR / "swagger-ui-standalone-preset.js").exists()


def test_vendored_assets_are_served():
    client = build().test_client()
    for path in (
        "/static/vendor/swagger-ui/swagger-ui.css",
        "/static/vendor/swagger-ui/swagger-ui-bundle.js",
    ):
        assert client.get(path).status_code == 200, path


def test_the_console_page_is_served():
    response = build().test_client().get("/docs")
    assert response.status_code == 200
    assert "swagger-ui" in response.get_data(as_text=True)


def test_the_console_page_is_404_when_docs_are_disabled():
    assert build(docs_enabled=False).test_client().get("/docs").status_code == 404


def test_no_console_asset_is_loaded_from_another_origin():
    # Root-relative only. A scheme, or a protocol-relative "//host/path",
    # would reach off-origin; a bare leading "/" cannot. The prefix is not
    # narrowed to /static/ because the masthead links to the app's own root,
    # which is a navigation target rather than an asset.
    html = build().test_client().get("/docs").get_data(as_text=True)
    for attribute in re.findall(r'(?:src|href)="([^"]+)"', html):
        assert attribute.startswith("/"), attribute
        assert not attribute.startswith("//"), attribute


def test_the_console_page_has_no_inline_script():
    # script-src falls back to default-src 'self', so an inline script body
    # would be blocked outright. Every script loads from /static via src.
    html = Path("templates/docs.html").read_text(encoding="utf-8")
    for block in re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.S):
        assert not block.strip(), block


def test_the_console_warns_before_anything_is_typed_into_it():
    html = build().test_client().get("/docs").get_data(as_text=True)
    # Asserts on the banner's class and a distinctive phrase from its text, so
    # this fails if the `.docs-warning` paragraph is ever deleted rather than
    # just reworded.
    assert 'class="docs-warning"' in html
    assert "these are real requests" in html.lower()


def test_the_console_script_points_at_this_origin_only():
    js = Path("static/js/docs.js").read_text(encoding="utf-8")
    # Relative to <base>, not absolute -- see the comment in docs.js.
    assert "'api/v1/openapi.json'" in js
    # No absolute URL: try-it-out must stay on the origin that served the page.
    assert "http://" not in js
    assert "https://" not in js
