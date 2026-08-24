"""`create_app` behaviour around the OpenAPI document: when it is loaded, and
which file it is loaded from.
"""

from __future__ import annotations

import pytest

from amiweak.app import context, create_app
from amiweak.config import ConfigError, load_config
from amiweak.store import MemoryStore, ResilientStore


def test_create_app_succeeds_with_docs_disabled_and_no_spec_file(monkeypatch, tmp_path):
    # An operator who sets docs.enabled: false should not also be on the hook
    # for shipping openapi.yaml. The spec must not even be read in this case.
    monkeypatch.setenv("AMIWEAK_OPENAPI", str(tmp_path / "does-not-exist.yaml"))
    config = load_config(None, env={"AMIWEAK_DOCS__ENABLED": "false"})
    app = create_app(config=config)
    assert app.test_client().get("/api/v1/openapi.json").status_code == 404


def test_create_app_fails_loudly_when_docs_are_enabled_and_the_spec_is_missing(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("AMIWEAK_OPENAPI", str(tmp_path / "does-not-exist.yaml"))
    config = load_config(None, env={"AMIWEAK_DOCS__ENABLED": "true"})
    with pytest.raises(ConfigError):
        create_app(config=config)


def test_amiweak_openapi_redirects_which_document_is_served(monkeypatch, tmp_path):
    custom = tmp_path / "custom.yaml"
    custom.write_text(
        'openapi: "3.1.0"\ninfo:\n  title: Custom\n  version: "9.9.9"\npaths: {}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("AMIWEAK_OPENAPI", str(custom))
    config = load_config(None, env={"AMIWEAK_DOCS__ENABLED": "true"})
    app = create_app(config=config)
    body = app.test_client().get("/api/v1/openapi.json").get_json()
    assert body["info"]["title"] == "Custom"
    assert body["info"]["version"] == "9.9.9"


def test_no_config_argument_loads_from_the_amiweak_config_env_var(monkeypatch, tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("docs:\n  enabled: false\n", encoding="utf-8")
    monkeypatch.setenv("AMIWEAK_CONFIG", str(config_path))
    app = create_app()
    assert app.test_client().get("/api/v1/openapi.json").status_code == 404


def test_context_exposes_a_store() -> None:
    app = create_app(load_config(None, env={}))
    assert isinstance(context(app).store, MemoryStore)


def test_a_state_path_yields_a_shared_store(tmp_path) -> None:  # type: ignore[no-untyped-def]
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"state:\n  path: {str(tmp_path / 'state.db')!r}\n", encoding="utf-8")
    app = create_app(load_config(config_path, env={}))
    assert isinstance(context(app).store, ResilientStore)


def test_limiters_share_the_store_without_sharing_an_allowance(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """One store, two namespaces: the batch bucket must not drain the interactive one."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "policy:\n  rate_limit:\n    requests: 1\nbatch:\n  rate_limit:\n    prefixes: 1\n",
        encoding="utf-8",
    )
    ctx = context(create_app(load_config(config_path, env={})))

    assert ctx.limiter.allow("1.2.3.4") is True
    assert ctx.batch_limiter.allow("1.2.3.4") is True
    assert ctx.limiter.allow("1.2.3.4") is False


def test_metrics_and_limiters_are_backed_by_the_same_store(tmp_path) -> None:  # type: ignore[no-untyped-def]
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"state:\n  path: {str(tmp_path / 'state.db')!r}\n", encoding="utf-8")
    ctx = context(create_app(load_config(config_path, env={})))
    ctx.metrics.record_check("safe")

    assert ctx.store.snapshot().counters["checks_total"] == {"": 1}
