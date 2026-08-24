"""The page itself."""

from __future__ import annotations

from flask import Blueprint, current_app, render_template

from amiweak.app import context

bp = Blueprint("web", __name__)

#: The shipped design lives at the top of templates/; the alternatives live in
#: templates/themes/. Keeping "original" where it has always been means the
#: default path is unchanged for anyone who never touches `ui.theme`.
DEFAULT_THEME = "original"


def template_for(theme: str) -> str:
    return "index.html" if theme == DEFAULT_THEME else f"themes/{theme}.html"


@bp.get("/")
def index() -> str:
    theme = context(current_app).config.ui.theme
    return render_template(template_for(theme))
