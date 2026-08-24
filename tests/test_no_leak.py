"""The one guarantee that has to survive every future change.

Anything failing here is a release blocker. Fix the source, never the assertion.
"""

import dataclasses
import logging

import responses

from amiweak.app import create_app
from amiweak.config import load_config
from amiweak.hashing import sha1_hex

PASSWORD = "SuperSecret!Passphrase42"
HASH = sha1_hex(PASSWORD)


def mock_upstreams():
    responses.get(f"https://api.pwnedpasswords.com/range/{HASH[:5].upper()}", body="AAAA:1\n")
    responses.get(f"https://weakpass.com/api/v1/range/{HASH[:6]}.txt", body="deadbeef\n")


def app():
    return create_app(config=load_config(None, env={}))


@responses.activate
def test_password_never_appears_in_logs(caplog):
    mock_upstreams()
    caplog.set_level(logging.DEBUG, logger="amiweak")
    app().test_client().post("/api/v1/check", json={"password": PASSWORD})
    captured = "\n".join(record.getMessage() for record in caplog.records)
    assert PASSWORD not in captured
    assert HASH not in captured


@responses.activate
def test_only_the_hash_prefix_reaches_upstream():
    mock_upstreams()
    app().test_client().post("/api/v1/check", json={"password": PASSWORD})
    assert len(responses.calls) == 2
    for call in responses.calls:
        assert PASSWORD not in call.request.url
        assert HASH not in call.request.url
        assert HASH[6:] not in call.request.url
        assert call.request.body is None


@responses.activate
def test_password_never_appears_in_the_response():
    mock_upstreams()
    response = app().test_client().post("/api/v1/check", json={"password": PASSWORD})
    body = response.get_data(as_text=True)
    assert PASSWORD not in body
    assert HASH not in body


@responses.activate
def test_password_never_appears_in_metrics_or_health():
    mock_upstreams()
    client = app().test_client()
    client.post("/api/v1/check", json={"password": PASSWORD})
    for path in ("/metrics", "/healthz"):
        body = client.get(path).get_data(as_text=True)
        assert PASSWORD not in body
        assert HASH not in body


@responses.activate
def test_a_failing_upstream_does_not_expose_the_hash_in_the_error():
    import requests

    responses.get(
        f"https://api.pwnedpasswords.com/range/{HASH[:5].upper()}",
        body=requests.exceptions.ConnectionError(f"failed for {HASH}"),
    )
    responses.get(f"https://weakpass.com/api/v1/range/{HASH[:6]}.txt", body="deadbeef\n")
    response = app().test_client().post("/api/v1/check", json={"password": PASSWORD})
    body = response.get_data(as_text=True)
    assert HASH not in body
    assert HASH[:5] not in body


def test_debug_mode_cannot_be_enabled(monkeypatch):
    monkeypatch.setenv("FLASK_DEBUG", "1")
    assert app().debug is False


def test_unhandled_error_response_carries_no_password():
    class Exploding:
        def evaluate(self, password):
            raise RuntimeError(f"boom {password}")

    instance = create_app(config=load_config(None, env={}), runner=Exploding())
    response = instance.test_client().post("/api/v1/check", json={"password": PASSWORD})
    assert response.status_code == 500
    assert PASSWORD not in response.get_data(as_text=True)


def test_unhandled_error_traceback_is_redacted_in_logs(caplog):
    """An exception message can carry whatever the raiser put in it.

    Checking `getMessage()` alone would pass while the traceback still spelled
    the password out, so this formats each record the way a handler would.
    """

    class Exploding:
        def evaluate(self, password):
            raise RuntimeError(f"boom {password}")

    caplog.set_level(logging.DEBUG)
    instance = create_app(config=load_config(None, env={}), runner=Exploding())
    instance.test_client().post("/api/v1/check", json={"password": PASSWORD})

    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    assert caplog.records, "expected the failure to be logged at all"
    for record in caplog.records:
        assert PASSWORD not in formatter.format(record)


@responses.activate
def test_the_check_response_forbids_caching():
    mock_upstreams()
    response = app().test_client().post("/api/v1/check", json={"password": PASSWORD})
    assert response.headers["Cache-Control"] == "no-store"


LABEL = "svc-payroll-admin"
NTLM_DIGEST = "8846f7eaee8fb117ad06bdd830b7586c"


def mock_ntlm_upstreams():
    responses.get(
        f"https://api.pwnedpasswords.com/range/{NTLM_DIGEST.upper()[:5]}",
        body=f"{NTLM_DIGEST.upper()[5:]}:9\n",
    )
    responses.get(
        f"https://weakpass.com/api/v1/range/{NTLM_DIGEST[:6]}.txt",
        body=f"{NTLM_DIGEST}\n",
    )


def batch_request(client):
    return client.post(
        "/api/v1/check/batch",
        json={"algorithm": "ntlm", "items": [{"label": LABEL, "hash": NTLM_DIGEST}]},
    )


@responses.activate
def test_a_label_never_appears_in_logs(caplog):
    """A label is a username. A log pairing one with `leaked` is a target list."""
    mock_ntlm_upstreams()
    caplog.set_level(logging.DEBUG, logger="amiweak")
    batch_request(app().test_client())
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    for record in caplog.records:
        assert LABEL not in formatter.format(record)


@responses.activate
def test_a_label_never_appears_in_metrics_or_health():
    mock_ntlm_upstreams()
    client = app().test_client()
    batch_request(client)
    for path in ("/metrics", "/healthz"):
        body = client.get(path).get_data(as_text=True)
        assert LABEL not in body
        assert NTLM_DIGEST not in body


@responses.activate
def test_only_the_ntlm_prefix_reaches_upstream():
    mock_ntlm_upstreams()
    batch_request(app().test_client())
    assert responses.calls, "expected the batch to reach both upstreams"
    for call in responses.calls:
        assert LABEL not in call.request.url
        assert NTLM_DIGEST not in call.request.url
        assert NTLM_DIGEST[6:] not in call.request.url
        assert call.request.body is None


@responses.activate
def test_a_batch_digest_never_appears_in_logs(caplog):
    mock_ntlm_upstreams()
    caplog.set_level(logging.DEBUG, logger="amiweak")
    batch_request(app().test_client())
    captured = "\n".join(record.getMessage() for record in caplog.records)
    assert NTLM_DIGEST not in captured


@responses.activate
def test_a_rejected_batch_does_not_echo_the_label_or_hash():
    """A 400 must not reflect client data back into the response body."""
    response = (
        app()
        .test_client()
        .post(
            "/api/v1/check/batch",
            json={"algorithm": "ntlm", "items": [{"label": LABEL, "hash": "nonsense"}]},
        )
    )
    assert response.status_code == 400
    body = response.get_data(as_text=True)
    assert LABEL not in body
    assert "nonsense" not in body


@responses.activate
def test_the_batch_response_forbids_caching():
    mock_ntlm_upstreams()
    assert batch_request(app().test_client()).headers["Cache-Control"] == "no-store"


def hash_request(client, digest=None):
    return client.post("/api/v1/check/hash", json={"hash": digest or HASH})


@responses.activate
def test_a_submitted_digest_never_appears_in_logs(caplog):
    mock_upstreams()
    caplog.set_level(logging.DEBUG, logger="amiweak")
    hash_request(app().test_client())
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    for record in caplog.records:
        assert HASH not in formatter.format(record)


@responses.activate
def test_only_the_prefix_of_a_submitted_digest_reaches_upstream():
    mock_upstreams()
    hash_request(app().test_client())
    assert len(responses.calls) == 2
    for call in responses.calls:
        assert HASH not in call.request.url
        assert HASH[6:] not in call.request.url
        assert call.request.body is None


@responses.activate
def test_a_submitted_digest_never_appears_in_the_response():
    mock_upstreams()
    assert HASH not in hash_request(app().test_client()).get_data(as_text=True)


@responses.activate
def test_a_submitted_digest_never_appears_in_metrics_or_health():
    mock_upstreams()
    client = app().test_client()
    hash_request(client)
    for path in ("/metrics", "/healthz"):
        body = client.get(path).get_data(as_text=True)
        assert HASH not in body


def test_a_rejected_hash_request_does_not_echo_the_digest():
    """A 400 must not reflect client data back into the response body."""
    bad = "z" * 40
    response = app().test_client().post("/api/v1/check/hash", json={"hash": bad})
    assert response.status_code == 400
    assert bad not in response.get_data(as_text=True)


def test_hash_endpoint_unhandled_error_traceback_is_redacted(caplog):
    """The 500 path must not spell the digest out through an exception message."""

    class Exploding:
        def evaluate(self, password):
            raise RuntimeError("unused")

        def supports(self, algorithm):
            return True

        def evaluate_digest(self, digest, algorithm):
            raise RuntimeError(f"boom {digest}")

    caplog.set_level(logging.DEBUG)
    instance = create_app(config=load_config(None, env={}), runner=Exploding())
    response = instance.test_client().post("/api/v1/check/hash", json={"hash": HASH})

    assert response.status_code == 500
    assert HASH not in response.get_data(as_text=True)
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    assert caplog.records, "expected the failure to be logged at all"
    for record in caplog.records:
        assert HASH not in formatter.format(record)


@responses.activate
def test_the_hash_response_forbids_caching():
    mock_upstreams()
    assert hash_request(app().test_client()).headers["Cache-Control"] == "no-store"


@responses.activate
def test_check_and_check_hash_agree_on_the_same_password():
    """The two routes must be the same evaluation with the hashing moved.

    Uses the real runner against mocked upstreams, so this catches a divergence
    a stubbed runner would hide -- a different deadline, a different plan, a
    dropped field.
    """
    mock_upstreams()
    plaintext = app().test_client().post("/api/v1/check", json={"password": PASSWORD}).get_json()
    hashed = hash_request(app().test_client()).get_json()
    assert plaintext["verdict"] == hashed["verdict"]
    assert plaintext["checks"] == hashed["checks"]
    assert plaintext["error"] == hashed["error"]


@responses.activate
def test_password_never_reaches_the_strength_worker_stderr():
    mock_upstreams()
    application = app()
    application.test_client().post("/api/v1/check", json={"password": PASSWORD})
    scorer = application.extensions["amiweak"].strength
    assert scorer is not None
    captured = "\n".join(scorer.debug_stderr())
    assert PASSWORD not in captured
    assert HASH not in captured


SECRET_ENTRY = "zzsecretorgtokenzz"


def denylist_app(tmp_path):
    from amiweak.config import DenylistConfig, load_config

    word_file = tmp_path / "d.txt"
    word_file.write_text(f"{SECRET_ENTRY}\n", encoding="utf-8")
    cfg = load_config(None, env={})
    object.__setattr__(
        cfg,
        "denylist",
        DenylistConfig(
            path=str(word_file),
            min_token_length=4,
            match_plaintext=True,
            rules=(),
            max_digests=1000,
            cache_path=str(tmp_path / "d.bin"),
        ),
    )
    # The path -> enabled reconciliation in config._build already ran (against
    # the original null path) before this post-hoc swap set a real path, so it
    # needs to be redone here for the DenylistChecker to actually get wired.
    object.__setattr__(
        cfg,
        "checks",
        {**cfg.checks, "denylist": dataclasses.replace(cfg.checks["denylist"], enabled=True)},
    )
    return create_app(config=cfg)


@responses.activate
def test_denylist_entry_never_leaks_through_any_surface(tmp_path, caplog):
    mock_upstreams()
    caplog.set_level(logging.DEBUG, logger="amiweak")
    client = denylist_app(tmp_path).test_client()
    client.post("/api/v1/check", json={"password": f"{SECRET_ENTRY.upper()}!9"})
    for path in ("/metrics", "/healthz", "/api/v1/config"):
        assert SECRET_ENTRY not in client.get(path).get_data(as_text=True)
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    for record in caplog.records:
        assert SECRET_ENTRY not in formatter.format(record)


def test_a_too_short_entry_error_names_the_line_not_the_entry(tmp_path):
    from amiweak.config import ConfigError
    from amiweak.denylist import _read_entries

    f = tmp_path / "d.txt"
    f.write_text(f"{SECRET_ENTRY}\nno\n", encoding="utf-8")
    try:
        _read_entries(f, 4)
    except ConfigError as exc:
        assert "line 2" in str(exc)
        assert SECRET_ENTRY not in str(exc)  # the entry text is not echoed
    else:
        raise AssertionError("expected a startup error")


def test_state_database_never_contains_a_password(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A full check against a shared store leaves no trace of the secret on disk."""
    import hashlib
    import sqlite3
    from pathlib import Path

    from amiweak.app import context, create_app
    from amiweak.config import load_config

    secret = "correct-horse-battery-staple-8842"
    db_path = tmp_path / "state.db"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"state:\n  path: {str(db_path)!r}\n"
        "checks:\n"
        "  hibp:\n    enabled: false\n"
        "  weakpass:\n    enabled: false\n"
        "strength:\n  enabled: false\n",
        encoding="utf-8",
    )

    app = create_app(load_config(config_path, env={}))
    client = app.test_client()
    client.post("/api/v1/check", json={"password": secret})
    context(app).store.close()

    # Checkpoint WAL into the main file to ensure all data is in one place.
    checkpoint_conn = sqlite3.connect(str(db_path))
    try:
        checkpoint_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        checkpoint_conn.close()

    # Check the main database file and any WAL/SHM side files.
    blobs_to_check = [db_path.read_bytes()]
    for suffix in ["-wal", "-shm"]:
        side_file = Path(str(db_path) + suffix)
        if side_file.exists():
            blobs_to_check.append(side_file.read_bytes())

    combined = b"".join(blobs_to_check)
    assert secret.encode() not in combined
    # The SHA-1 of the password must not be there either.
    assert hashlib.sha1(secret.encode()).hexdigest().upper().encode() not in combined


def test_store_labels_come_from_a_closed_set(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """A future counter keyed by user input fails here rather than leaking quietly."""
    from amiweak.app import context, create_app
    from amiweak.config import load_config

    db_path = tmp_path / "state.db"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"state:\n  path: {str(db_path)!r}\n"
        "checks:\n"
        "  hibp:\n    enabled: false\n"
        "  weakpass:\n    enabled: false\n"
        "strength:\n  enabled: false\n",
        encoding="utf-8",
    )

    app = create_app(load_config(config_path, env={}))
    client = app.test_client()
    client.post("/api/v1/check", json={"password": "correct-horse-battery-staple-8842"})

    allowed = {
        "",  # unlabelled scalars
        "safe",
        "leaked",
        "precomputed",
        "denylisted",
        "weak",
        "too_short",
        "error",
        "hibp",
        "weakpass",
        "denylist",
        "hibp:sha1",
        "hibp:ntlm",
        "weakpass:sha1",
        "weakpass:ntlm",
        "denylist:sha1",
    }
    counters = context(app).store.snapshot().counters
    seen = {label for labels in counters.values() for label in labels}
    assert seen <= allowed, f"unexpected counter labels: {sorted(seen - allowed)}"
    context(app).store.close()
