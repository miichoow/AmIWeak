import re
from pathlib import Path

import pytest

from amiweak.app import create_app
from amiweak.config import THEMES, load_config

VENDOR = Path("static/vendor")

# Every promise the page makes has to hold for every theme, so the whole
# contract below is parametrised. A theme that reached out to a font CDN, or
# dropped `autocomplete="new-password"`, would fail here rather than in review.
EVERY_THEME = pytest.mark.parametrize("theme", sorted(THEMES))


def page(theme="original"):
    app = create_app(config=load_config(None, env={"AMIWEAK_UI__THEME": theme}))
    return app.test_client().get("/").get_data(as_text=True)


@EVERY_THEME
def test_password_field_is_masked_and_not_autocompleted(theme):
    html = page(theme)
    assert 'type="password"' in html
    assert 'autocomplete="new-password"' in html
    assert 'spellcheck="false"' in html


@EVERY_THEME
def test_form_never_submits_by_get(theme):
    assert not re.search(r"<form[^>]*method=[\"']get", page(theme), re.I)


@EVERY_THEME
def test_no_asset_is_loaded_from_another_origin(theme):
    # Only src/href values matter here; an XML namespace URL in an inline SVG is
    # not a network request. In-page anchors and same-origin links (/docs) are
    # fine; what must never appear is an absolute or protocol-relative URL.
    for attribute in re.findall(r'(?:src|href)="([^"]+)"', page(theme)):
        assert not attribute.startswith("//"), attribute
        assert not re.match(r"[a-z][a-z0-9+.-]*:", attribute, re.I), attribute


@EVERY_THEME
def test_theme_keeps_the_dom_contract_the_client_script_depends_on(theme):
    # static/js/app.js is shared by every theme and looks these up by id. A
    # missing one is a silently dead control, not an exception the user sees.
    html = page(theme)
    for element_id in (
        "check-form",
        "password",
        "reveal",
        "meter",
        "strength-label",
        "strength-time",
        "hints",
        "submit",
        "verdict",
        "verdict-message",
        "verdict-note",
        "breakdown",
    ):
        assert f'id="{element_id}"' in html, f"{theme}: missing #{element_id}"
    assert html.count("data-seg=") == 5, f"{theme}: meter needs five segments"


@EVERY_THEME
def test_theme_stylesheet_is_served_and_respects_user_preferences(theme):
    app = create_app(config=load_config(None, env={"AMIWEAK_UI__THEME": theme}))
    href = re.search(r'<link rel="stylesheet" href="([^"]+)"', page(theme)).group(1)
    assert app.test_client().get(href).status_code == 200, href
    css = Path(href.lstrip("/")).read_text(encoding="utf-8")
    assert "prefers-reduced-motion" in css, theme


@EVERY_THEME
def test_theme_fonts_are_vendored(theme):
    """Any webfont a theme declares must resolve to a file we actually ship."""
    app = create_app(config=load_config(None, env={"AMIWEAK_UI__THEME": theme}))
    href = re.search(r'<link rel="stylesheet" href="([^"]+)"', page(theme)).group(1)
    css = Path(href.lstrip("/")).read_text(encoding="utf-8")
    for url in re.findall(r"src:\s*url\(([^)]+)\)", css):
        assert url.startswith("/static/"), f"{theme}: remote font {url}"
        assert app.test_client().get(url).status_code == 200, url


def test_vendored_zxcvbn_files_exist_and_are_not_stubs():
    for name in (
        "zxcvbn-ts-core.js",
        "zxcvbn-ts-language-common.js",
        "zxcvbn-ts-language-en.js",
    ):
        path = VENDOR / name
        assert path.is_file(), name
        assert path.stat().st_size > 10_000, name


def test_vendored_bundles_expose_the_globals_the_page_uses():
    core = (VENDOR / "zxcvbn-ts-core.js").read_text(encoding="utf-8")[:200]
    assert "zxcvbnts.core" in core
    common = (VENDOR / "zxcvbn-ts-language-common.js").read_text(encoding="utf-8")[:200]
    assert 'zxcvbnts["language-common"]' in common
    english = (VENDOR / "zxcvbn-ts-language-en.js").read_text(encoding="utf-8")[:200]
    assert 'zxcvbnts["language-en"]' in english


def test_static_assets_are_served():
    app = create_app(config=load_config(None, env={}))
    client = app.test_client()
    for path in (
        "/static/css/app.css",
        "/static/js/app.js",
        "/static/favicon.svg",
        "/static/vendor/zxcvbn-ts-core.js",
    ):
        assert client.get(path).status_code == 200, path


def test_client_script_sends_the_password_only_by_post():
    js = Path("static/js/app.js").read_text(encoding="utf-8")
    assert "method: 'POST'" in js
    assert "location.search" not in js
    assert "localStorage" not in js
    assert "sessionStorage" not in js
    assert "console." not in js


def test_client_script_reads_copy_from_the_server():
    js = Path("static/js/app.js").read_text(encoding="utf-8")
    assert "/api/v1/config" in js


def test_stylesheet_respects_reduced_motion():
    css = Path("static/css/app.css").read_text(encoding="utf-8")
    assert "prefers-reduced-motion" in css
    assert "prefers-color-scheme" in css


def test_woff2_is_served_with_a_font_content_type():
    # Windows has no woff2 mimetype registration; without the explicit one in
    # app.py these go out as application/octet-stream.
    app = create_app(config=load_config(None, env={}))
    font = next(Path("static/vendor/fonts").glob("*.woff2"))
    response = app.test_client().get(f"/static/vendor/fonts/{font.name}")
    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("font/woff2")
