from amiweak.app import create_app
from amiweak.config import load_config
from amiweak.metrics import Metrics
from amiweak.prometheus import CONTENT_TYPE
from amiweak.store import MemoryStore


def client(metrics=None, config=None):
    app = create_app(
        config=config or load_config(None, env={}), metrics=metrics or Metrics(MemoryStore())
    )
    return app.test_client()


def test_healthz_reports_ok_and_version():
    body = client().get("/healthz").get_json()
    assert body["status"] == "ok"
    assert body["version"]
    assert body["uptime_seconds"] >= 0
    assert set(body["checks"]) == {"hibp", "weakpass", "denylist", "zxcvbn"}


def test_healthz_reports_denylist_disabled_when_path_is_unset():
    # Default config has denylist.path: null, so no Denylist is ever loaded and
    # no DenylistChecker is wired -- reporting enabled:true would be dishonest.
    body = client().get("/healthz").get_json()
    assert body["checks"]["denylist"]["enabled"] is False


def test_healthz_reports_denylist_enabled_when_path_is_set(tmp_path):
    # Goes through the real load_config -> _build path (not a post-hoc
    # object.__setattr__ swap), so the enabled/path reconciliation in _build
    # actually runs against a path that is set from the start.
    word_file = tmp_path / "words.txt"
    word_file.write_text("acme\n", encoding="utf-8")
    config = load_config(None, env={"AMIWEAK_DENYLIST__PATH": str(word_file)})
    body = client(config=config).get("/healthz").get_json()
    assert body["checks"]["denylist"]["enabled"] is True


def test_healthz_reports_degraded_after_a_zxcvbn_error():
    metrics = Metrics(MemoryStore())
    metrics.record_backend("zxcvbn", ok=False, seconds=1.0, error="timeout")
    body = client(metrics).get("/healthz").get_json()
    assert body["status"] == "degraded"
    assert body["checks"]["zxcvbn"]["last_error"] == "timeout"


def test_healthz_omits_zxcvbn_when_strength_disabled(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("strength:\n  enabled: false\n", encoding="utf-8")
    body = client(config=load_config(path, env={})).get("/healthz").get_json()
    assert "zxcvbn" not in body["checks"]


def test_healthz_reports_degraded_after_a_backend_error():
    metrics = Metrics(MemoryStore())
    metrics.record_backend("hibp", ok=False, seconds=5.0, error="timeout")
    body = client(metrics).get("/healthz").get_json()
    assert body["status"] == "degraded"
    assert body["checks"]["hibp"]["last_error"] == "timeout"


def test_healthz_ignores_a_disabled_backend(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("checks:\n  hibp:\n    enabled: false\n", encoding="utf-8")
    metrics = Metrics(MemoryStore())
    metrics.record_backend("hibp", ok=False, seconds=5.0, error="timeout")
    body = client(metrics, load_config(path, env={})).get("/healthz").get_json()
    assert body["status"] == "ok"
    assert body["checks"]["hibp"]["enabled"] is False


def test_healthz_makes_no_upstream_calls():
    # responses is not activated here, so a real outbound call would fail loudly.
    assert client().get("/healthz").status_code == 200


def test_metrics_shape():
    body = client().get("/metrics").get_json()
    for key in (
        "checks_total",
        "verdicts_total",
        "backend_requests_total",
        "backend_errors_total",
        "backend_latency_seconds",
    ):
        assert key in body


def test_ops_endpoints_are_not_cacheable():
    assert client().get("/metrics").headers["Cache-Control"] == "no-store"


def test_index_page_is_served():
    response = client().get("/")
    assert response.status_code == 200
    assert response.mimetype == "text/html"


def test_prometheus_endpoint_returns_exposition_content_type():
    response = client().get("/metrics/prometheus")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == CONTENT_TYPE


def test_prometheus_endpoint_body_is_parseable():
    body = client().get("/metrics/prometheus").get_data(as_text=True)
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.rpartition(" ")
        assert name
        float(value)


def test_prometheus_endpoint_declares_the_core_families():
    body = client().get("/metrics/prometheus").get_data(as_text=True)
    assert "# TYPE amiweak_checks_total counter" in body
    assert "# TYPE amiweak_backend_healthy gauge" in body
    assert "amiweak_build_info{version=" in body


def test_json_metrics_endpoint_is_unchanged():
    response = client().get("/metrics")
    assert response.status_code == 200
    assert response.is_json
    assert "checks_total" in response.get_json()


def test_prometheus_endpoint_is_not_gated_by_docs(tmp_path):
    """docs.enabled guards a console that takes passwords, not a counter dump."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("docs:\n  enabled: false\n", encoding="utf-8")
    test_client = client(config=load_config(config_path, env={}))

    assert test_client.get("/docs").status_code == 404
    assert test_client.get("/metrics/prometheus").status_code == 200


def test_prometheus_response_is_no_store():
    response = client().get("/metrics/prometheus")
    assert response.headers["Cache-Control"] == "no-store"


def test_prometheus_backend_healthy_ignores_a_disabled_backends_stale_error(tmp_path):
    # Mirrors test_healthz_ignores_a_disabled_backend: a backend that recorded
    # an error and was then disabled must not keep reporting unhealthy forever,
    # since /healthz would report "ok" for the exact same state.
    path = tmp_path / "config.yaml"
    path.write_text("checks:\n  hibp:\n    enabled: false\n", encoding="utf-8")
    metrics = Metrics(MemoryStore())
    metrics.record_backend("hibp", ok=False, seconds=5.0, error="timeout")
    body = (
        client(metrics, load_config(path, env={})).get("/metrics/prometheus").get_data(as_text=True)
    )
    assert 'amiweak_backend_healthy{backend="hibp"} 1' in body.splitlines()


def test_prometheus_backend_healthy_reports_zero_for_an_enabled_backends_real_error():
    metrics = Metrics(MemoryStore())
    metrics.record_backend("hibp", ok=False, seconds=5.0, error="timeout")
    body = client(metrics).get("/metrics/prometheus").get_data(as_text=True)
    assert 'amiweak_backend_healthy{backend="hibp"} 0' in body.splitlines()


def test_prometheus_ignores_a_stale_zxcvbn_error_when_strength_is_disabled(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("strength:\n  enabled: false\n", encoding="utf-8")
    metrics = Metrics(MemoryStore())
    metrics.record_backend("zxcvbn", ok=False, seconds=1.0, error="timeout")
    body = (
        client(metrics, load_config(path, env={})).get("/metrics/prometheus").get_data(as_text=True)
    )
    assert 'amiweak_backend_healthy{backend="zxcvbn"} 1' in body.splitlines()
