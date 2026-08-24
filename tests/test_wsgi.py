"""`wsgi.py`: the gunicorn entrypoint builds its app at import time."""

from __future__ import annotations

import sys
from collections.abc import Iterator

import pytest
from flask import Flask

import amiweak.app


@pytest.fixture
def _unimported_wsgi() -> Iterator[None]:
    """Drop `wsgi` before and after so the import below actually runs the module."""
    sys.modules.pop("wsgi", None)
    yield
    sys.modules.pop("wsgi", None)


def test_module_exposes_the_created_app(
    monkeypatch: pytest.MonkeyPatch, _unimported_wsgi: None
) -> None:
    built = Flask(__name__)
    monkeypatch.setattr(amiweak.app, "create_app", lambda *a, **k: built)

    import wsgi

    assert wsgi.app is built
