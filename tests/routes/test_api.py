import dataclasses

import pytest
import responses

from amiweak.algorithms import Algorithm
from amiweak.app import create_app
from amiweak.checks.base import CheckResult
from amiweak.checks.runner import BatchOutcome, Evaluation, Verdict
from amiweak.config import DenylistConfig, StrengthConfig, load_config
from amiweak.hashing import sha1_hex


class StubRunner:
    def __init__(self, evaluation):
        self.evaluation = evaluation
        self.calls = []

    def evaluate(self, password):
        self.calls.append(password)
        return self.evaluation

    def supports(self, algorithm):
        return True


def evaluation(verdict, degraded=False, results=None):
    return Evaluation(
        verdict=verdict,
        degraded=degraded,
        results=results
        or [
            CheckResult("hibp", True, verdict is Verdict.LEAKED, None, None),
            CheckResult("weakpass", True, verdict is Verdict.PRECOMPUTED, None, None),
        ],
    )


def client_for(evaluation_obj, config=None):
    config = config or load_config(None, env={})
    app = create_app(config=config, runner=StubRunner(evaluation_obj))
    app.config.update(TESTING=True)
    return app.test_client()


def post(client, payload):
    return client.post("/api/v1/check", json=payload)


def test_default_config_reports_denylist_check_as_disabled():
    # denylist.path defaults to null, so no DenylistChecker is ever wired --
    # checks.denylist.enabled must be reconciled to False, not left at the
    # DEFAULTS value of True, or /api/v1/check would report a placeholder as
    # if it were a real check.
    config = load_config(None, env={})
    assert config.checks["denylist"].enabled is False


def test_denylist_config_enabled_stays_true_when_path_is_set(tmp_path):
    # Goes through the real load_config -> _build path (not a post-hoc
    # object.__setattr__ swap), so the enabled/path reconciliation in _build
    # actually runs against a path that is set from the start.
    word_file = tmp_path / "words.txt"
    word_file.write_text("acme\n", encoding="utf-8")
    config = load_config(None, env={"AMIWEAK_DENYLIST__PATH": str(word_file)})
    assert config.checks["denylist"].enabled is True
    assert config.denylist.path == str(word_file)


def test_safe_password_returns_error_false():
    response = post(client_for(evaluation(Verdict.SAFE)), {"password": "correcthorse"})
    body = response.get_json()
    assert response.status_code == 200
    assert body["error"] is False
    assert body["errorMessage"] == "This password looks fine."
    assert body["verdict"] == "safe"


def test_leaked_password_returns_error_true_with_configured_message():
    body = post(client_for(evaluation(Verdict.LEAKED)), {"password": "password"}).get_json()
    assert body["error"] is True
    assert body["errorMessage"] == "This password has appeared in a known data breach."
    assert body["verdict"] == "leaked"


def test_precomputed_verdict():
    body = post(client_for(evaluation(Verdict.PRECOMPUTED)), {"password": "letmein1"}).get_json()
    assert body["error"] is True
    assert body["verdict"] == "precomputed"


def test_too_short_verdict():
    body = post(client_for(evaluation(Verdict.TOO_SHORT)), {"password": "ab"}).get_json()
    assert body["error"] is True
    assert body["errorMessage"] == "This password is too short."


def test_messages_are_configurable(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('messages:\n  leaked: "Nope, change it."\n', encoding="utf-8")
    client = client_for(evaluation(Verdict.LEAKED), config=load_config(path, env={}))
    assert post(client, {"password": "password"}).get_json()["errorMessage"] == "Nope, change it."


def test_response_includes_per_check_breakdown():
    body = post(client_for(evaluation(Verdict.SAFE)), {"password": "correcthorse"}).get_json()
    assert [c["name"] for c in body["checks"]] == ["hibp", "weakpass"]
    assert set(body["checks"][0]) == {
        "name",
        "enabled",
        "applicable",
        "skipped",
        "hit",
        "count",
        "error",
    }


def test_degraded_flag_is_exposed():
    body = post(
        client_for(evaluation(Verdict.SAFE, degraded=True)), {"password": "correcthorse"}
    ).get_json()
    assert body["degraded"] is True


def test_runner_receives_the_password():
    runner = StubRunner(evaluation(Verdict.SAFE))
    app = create_app(config=load_config(None, env={}), runner=runner)
    app.test_client().post("/api/v1/check", json={"password": "correcthorse"})
    assert runner.calls == ["correcthorse"]


def test_rejects_an_algorithm_no_backend_supports():
    """The false-safe this guards: /check always hashes as SHA-1, so if no
    enabled backend supports SHA-1, the old code planned nothing, marked every
    check inapplicable, and fell through to a confident `safe` for a password
    nothing looked at."""

    class NoSha1Runner(StubRunner):
        def supports(self, algorithm):
            return False

    runner = NoSha1Runner(evaluation(Verdict.SAFE))
    app = create_app(config=load_config(None, env={}), runner=runner)
    response = post(app.test_client(), {"password": "correcthorse"})
    assert response.status_code == 400
    assert response.get_json()["error"] is True
    assert runner.calls == []


def test_normal_check_still_succeeds_once_the_guard_is_in_place():
    response = post(client_for(evaluation(Verdict.SAFE)), {"password": "correcthorse"})
    body = response.get_json()
    assert response.status_code == 200
    assert body["verdict"] == "safe"


@pytest.mark.parametrize("payload", [{}, {"password": None}, {"password": 123}, {"password": ""}])
def test_bad_payload_is_400_in_the_same_envelope(payload):
    response = post(client_for(evaluation(Verdict.SAFE)), payload)
    body = response.get_json()
    assert response.status_code == 400
    assert body["error"] is True
    assert isinstance(body["errorMessage"], str)


def test_non_json_body_is_400():
    client = client_for(evaluation(Verdict.SAFE))
    response = client.post("/api/v1/check", data="password=x")
    assert response.status_code == 400
    assert response.get_json()["error"] is True


def test_empty_body_is_400():
    # Distinct from test_non_json_body_is_400: an empty body takes the
    # early-return path in _load_json (nothing to even attempt decoding),
    # not the decode-failure path.
    client = client_for(evaluation(Verdict.SAFE))
    response = client.post("/api/v1/check", data=b"", content_type="application/json")
    assert response.status_code == 400
    assert response.get_json()["error"] is True


def test_json_array_body_is_400():
    client = client_for(evaluation(Verdict.SAFE))
    assert client.post("/api/v1/check", json=["a"]).status_code == 400


# SSPR (and other legacy clients) send Content-Type: application/json;
# charset=UTF-8 but encode accented text as Windows-1252, so a lone \xe9 / \xe8
# / \x92 makes the body invalid UTF-8. A strict UTF-8 JSON parse 400s the whole
# request even when the only non-ASCII bytes sit in fields we never read.
CP1252_CHECK_BODY = (
    b'{"password":"CACAHUETE6840.fh",'
    b'"policy":{"ChangeMessage":"sera synchronis\xe9 avec les syst\xe8mes, '
    b'si vous disposez d\x92appareils mobiles"}}'
)


def test_check_accepts_a_cp1252_encoded_body():
    client = client_for(evaluation(Verdict.SAFE))
    response = client.post(
        "/api/v1/check", data=CP1252_CHECK_BODY, content_type="application/json; charset=UTF-8"
    )
    assert response.status_code == 200
    assert response.get_json()["verdict"] == "safe"


def test_check_cp1252_body_still_reads_the_ascii_password():
    runner = StubRunner(evaluation(Verdict.SAFE))
    app = create_app(config=load_config(None, env={}), runner=runner)
    app.test_client().post(
        "/api/v1/check", data=CP1252_CHECK_BODY, content_type="application/json; charset=UTF-8"
    )
    assert runner.calls == ["CACAHUETE6840.fh"]


def test_get_is_not_allowed():
    assert client_for(evaluation(Verdict.SAFE)).get("/api/v1/check").status_code == 405


def test_response_is_not_cacheable():
    response = post(client_for(evaluation(Verdict.SAFE)), {"password": "correcthorse"})
    assert response.headers["Cache-Control"] == "no-store"


def test_security_headers_are_present():
    response = post(client_for(evaluation(Verdict.SAFE)), {"password": "correcthorse"})
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_config_endpoint_exposes_messages_and_strength():
    body = client_for(evaluation(Verdict.SAFE)).get("/api/v1/config").get_json()
    assert body["strength"]["min_score"] == 3
    assert body["strength"]["min_length"] == 8
    assert body["messages"]["leaked"]
    assert "checks" not in body
    assert "proxy" not in body


def test_config_exposes_the_denylisted_message():
    body = client_for(evaluation(Verdict.SAFE)).get("/api/v1/config").get_json()
    assert "denylisted" in body["messages"]
    assert body["messages"]["denylisted"]


def test_rate_limit_returns_429(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "policy:\n  rate_limit:\n    requests: 2\n    per_seconds: 60\n", encoding="utf-8"
    )
    client = client_for(evaluation(Verdict.SAFE), config=load_config(path, env={}))
    for _ in range(2):
        assert post(client, {"password": "correcthorse"}).status_code == 200
    response = post(client, {"password": "correcthorse"})
    assert response.status_code == 429
    assert response.get_json()["error"] is True


def test_rate_limit_can_be_disabled(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "policy:\n  rate_limit:\n    enabled: false\n    requests: 1\n", encoding="utf-8"
    )
    client = client_for(evaluation(Verdict.SAFE), config=load_config(path, env={}))
    for _ in range(5):
        assert post(client, {"password": "correcthorse"}).status_code == 200


def test_runner_exception_is_500_with_generic_message():
    class Exploding:
        def evaluate(self, password):
            raise RuntimeError("boom")

    app = create_app(config=load_config(None, env={}), runner=Exploding())
    response = app.test_client().post("/api/v1/check", json={"password": "correcthorse"})
    body = response.get_json()
    assert response.status_code == 500
    assert body["error"] is True
    assert body["errorMessage"] == "Something went wrong while checking this password."


NTLM_A = "aaaaaaaa" + "1" * 24
NTLM_B = "aaaaaaaa" + "2" * 24


def batch_body(**overrides):
    body = {
        "algorithm": "ntlm",
        "items": [{"label": "x", "hash": NTLM_A}, {"label": "y", "hash": NTLM_B}],
    }
    body.update(overrides)
    return body


class FakeBatchRunner:
    def __init__(self, verdicts=None):
        self._verdicts = verdicts or {}
        self.seen = None

    def evaluate(self, password):
        raise AssertionError("the batch endpoint must not call evaluate")

    def prefix_cost(self, items, algorithm):
        return len(items)

    def supports(self, algorithm):
        return True

    def evaluate_batch(self, items, algorithm):
        self.seen = (list(items), algorithm)
        return [
            BatchOutcome(
                entry.label,
                Evaluation(
                    verdict=self._verdicts.get(entry.label, Verdict.SAFE),
                    degraded=False,
                    results=[CheckResult("hibp", True, False, None, None)],
                ),
            )
            for entry in items
        ]


def batch_app(runner=None):
    return create_app(config=load_config(None, env={}), runner=runner or FakeBatchRunner())


def test_batch_echoes_labels_and_verdicts():
    runner = FakeBatchRunner(verdicts={"x": Verdict.LEAKED})
    response = batch_app(runner).test_client().post("/api/v1/check/batch", json=batch_body())
    assert response.status_code == 200
    body = response.get_json()
    assert body["error"] is False
    assert body["algorithm"] == "ntlm"
    assert {r["label"]: r["verdict"] for r in body["results"]} == {"x": "leaked", "y": "safe"}


def test_batch_summary_counts_verdicts():
    runner = FakeBatchRunner(verdicts={"x": Verdict.LEAKED})
    body = batch_app(runner).test_client().post("/api/v1/check/batch", json=batch_body()).get_json()
    assert body["summary"] == {
        "total": 2,
        "leaked": 1,
        "precomputed": 0,
        "denylisted": 0,
        "safe": 1,
        "error": 0,
    }
    assert body["errorMessage"] == "Checked 2 passwords."


def test_batch_summary_has_a_denylisted_key():
    # Any successful batch response must include summary["denylisted"], so a
    # consumer sees a stable shape whether or not the verdict occurred.
    runner = FakeBatchRunner(verdicts={"x": Verdict.DENYLISTED})
    response = batch_app(runner).test_client().post("/api/v1/check/batch", json=batch_body())
    assert response.status_code == 200
    body = response.get_json()
    assert "denylisted" in body["summary"]
    assert body["summary"]["denylisted"] == 1
    assert {r["label"]: r["verdict"] for r in body["results"]}["x"] == "denylisted"


def test_batch_passes_the_parsed_algorithm_to_the_runner():
    runner = FakeBatchRunner()
    batch_app(runner).test_client().post("/api/v1/check/batch", json=batch_body())
    assert runner.seen[1] is Algorithm.NTLM


def test_batch_rejects_an_unknown_algorithm():
    response = (
        batch_app().test_client().post("/api/v1/check/batch", json=batch_body(algorithm="md5"))
    )
    assert response.status_code == 400


def test_batch_rejects_a_digest_of_the_wrong_length():
    body = batch_body(items=[{"label": "x", "hash": "abc"}])
    assert batch_app().test_client().post("/api/v1/check/batch", json=body).status_code == 400


def test_batch_rejects_a_non_hex_digest():
    body = batch_body(items=[{"label": "x", "hash": "z" * 32}])
    assert batch_app().test_client().post("/api/v1/check/batch", json=body).status_code == 400


def test_batch_rejects_an_empty_item_list():
    assert (
        batch_app().test_client().post("/api/v1/check/batch", json=batch_body(items=[])).status_code
        == 400
    )


def test_batch_rejects_a_non_object_item():
    body = batch_body(items=["not-an-object"])
    assert batch_app().test_client().post("/api/v1/check/batch", json=body).status_code == 400


def test_batch_rejects_a_missing_label():
    body = batch_body(items=[{"hash": NTLM_A}])
    assert batch_app().test_client().post("/api/v1/check/batch", json=body).status_code == 400


def test_batch_rejects_an_over_long_label():
    body = batch_body(items=[{"label": "x" * 129, "hash": NTLM_A}])
    assert batch_app().test_client().post("/api/v1/check/batch", json=body).status_code == 400


def test_batch_rejection_response_omits_the_submitted_label_and_hash():
    label = "very-unique-test-label-xyz"
    bad_hash = "z" * 32  # non-hex, so this fails validation
    body = batch_body(items=[{"label": label, "hash": bad_hash}])
    response = batch_app().test_client().post("/api/v1/check/batch", json=body)
    assert response.status_code == 400
    text = response.get_data(as_text=True)
    assert label not in text
    assert bad_hash not in text


def test_batch_accepts_the_maximum_item_count():
    items = [{"label": str(n), "hash": NTLM_A} for n in range(1000)]
    response = batch_app().test_client().post("/api/v1/check/batch", json=batch_body(items=items))
    assert response.status_code == 200


def test_batch_rejects_one_item_over_the_maximum():
    items = [{"label": str(n), "hash": NTLM_A} for n in range(1001)]
    response = batch_app().test_client().post("/api/v1/check/batch", json=batch_body(items=items))
    assert response.status_code == 400


def test_batch_rejects_a_body_that_is_not_an_object():
    assert batch_app().test_client().post("/api/v1/check/batch", json=[]).status_code == 400


def test_batch_accepts_a_cp1252_encoded_body():
    # The accent sits in a label -- a field the endpoint DOES read -- so this
    # also pins that the fallback decode yields the right string, not mojibake.
    runner = FakeBatchRunner()
    body = (
        b'{"algorithm":"ntlm","items":[{"label":"caf\xe9-user","hash":"' + NTLM_A.encode() + b'"}]}'
    )
    response = (
        batch_app(runner)
        .test_client()
        .post("/api/v1/check/batch", data=body, content_type="application/json; charset=UTF-8")
    )
    assert response.status_code == 200
    assert [entry.label for entry in runner.seen[0]] == ["café-user"]


def test_batch_is_rate_limited_by_prefix_cost():
    # The fake charges a fixed cost of 1 per request, deliberately different
    # from len(items) == 2 in batch_body(). With a budget of 2, the handler
    # charging runner.prefix_cost(...) correctly lets both requests through
    # (1 + 1 == 2). If someone "fixes" the handler to charge len(items)
    # instead, the first request alone would exhaust the budget (2) and the
    # second request would come back 429 instead of 200 -- pinning the
    # requirement that the cost must come from prefix_cost, not item count.
    class FixedCostRunner(FakeBatchRunner):
        def prefix_cost(self, items, algorithm):
            return 1

    config = load_config(None, env={"AMIWEAK_BATCH__RATE_LIMIT__PREFIXES": "2"})
    client = create_app(config=config, runner=FixedCostRunner()).test_client()
    assert client.post("/api/v1/check/batch", json=batch_body()).status_code == 200
    assert client.post("/api/v1/check/batch", json=batch_body()).status_code == 200


def test_batch_rate_limit_returns_429_once_the_budget_is_exhausted():
    # Same FixedCostRunner pattern as the prefix-cost test above, so this
    # assertion is about the handler's rate-limiting logic (does it ever
    # actually reject?) rather than about prefix_cost's real implementation.
    class FixedCostRunner(FakeBatchRunner):
        def prefix_cost(self, items, algorithm):
            return 1

    config = load_config(None, env={"AMIWEAK_BATCH__RATE_LIMIT__PREFIXES": "1"})
    client = create_app(config=config, runner=FixedCostRunner()).test_client()
    assert client.post("/api/v1/check/batch", json=batch_body()).status_code == 200
    response = client.post("/api/v1/check/batch", json=batch_body())
    assert response.status_code == 429
    assert response.get_json()["error"] is True


def test_batch_with_a_fully_warm_cache_still_costs_at_least_one_token():
    # prefix_cost of 0 (an entirely cached batch) must not make the request
    # free: TokenBucket.allow short-circuits True for cost <= 0, so an
    # unmetered zero-cost batch could be resubmitted without limit.
    class ZeroCostRunner(FakeBatchRunner):
        def prefix_cost(self, items, algorithm):
            return 0

    config = load_config(None, env={"AMIWEAK_BATCH__RATE_LIMIT__PREFIXES": "1"})
    client = create_app(config=config, runner=ZeroCostRunner()).test_client()
    assert client.post("/api/v1/check/batch", json=batch_body()).status_code == 200
    response = client.post("/api/v1/check/batch", json=batch_body())
    assert response.status_code == 429


def test_batch_can_be_disabled():
    config = load_config(None, env={"AMIWEAK_BATCH__ENABLED": "false"})
    client = create_app(config=config, runner=FakeBatchRunner()).test_client()
    assert client.post("/api/v1/check/batch", json=batch_body()).status_code == 404


def test_batch_rejects_an_algorithm_no_backend_supports():
    """The false-safe this guards: an empty plan used to resolve to `safe`."""

    class NoNtlmRunner(FakeBatchRunner):
        def supports(self, algorithm):
            return algorithm is not Algorithm.NTLM

    response = (
        batch_app(NoNtlmRunner()).test_client().post("/api/v1/check/batch", json=batch_body())
    )
    assert response.status_code == 400
    assert response.get_json()["error"] is True


def test_a_runner_failure_is_a_500_with_the_configured_message():
    class Exploding(FakeBatchRunner):
        def evaluate_batch(self, items, algorithm):
            raise RuntimeError("boom")

    response = batch_app(Exploding()).test_client().post("/api/v1/check/batch", json=batch_body())
    assert response.status_code == 500
    assert response.get_json()["error"] is True


SHA1_DIGEST = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"


class FakeHashRunner:
    def __init__(self, evaluation_obj=None, supported=None):
        self._evaluation = evaluation_obj or evaluation(Verdict.SAFE)
        self._supported = supported
        self.seen = None

    def evaluate(self, password):
        raise AssertionError("the hash endpoint must not call evaluate")

    def supports(self, algorithm):
        return self._supported is None or algorithm in self._supported

    def evaluate_digest(self, digest, algorithm):
        self.seen = (digest, algorithm)
        return self._evaluation


def hash_client(runner=None, config=None):
    config = config or load_config(None, env={})
    return create_app(config=config, runner=runner or FakeHashRunner()).test_client()


def post_hash(client, payload):
    return client.post("/api/v1/check/hash", json=payload)


def test_hash_safe_digest_returns_error_false():
    response = post_hash(hash_client(), {"hash": SHA1_DIGEST})
    body = response.get_json()
    assert response.status_code == 200
    assert body["error"] is False
    assert body["verdict"] == "safe"
    assert body["errorMessage"] == "This password looks fine."


def test_hash_leaked_digest_returns_error_true():
    runner = FakeHashRunner(evaluation(Verdict.LEAKED))
    body = post_hash(hash_client(runner), {"hash": SHA1_DIGEST}).get_json()
    assert body["error"] is True
    assert body["verdict"] == "leaked"
    assert body["errorMessage"] == "This password has appeared in a known data breach."


def test_hash_defaults_to_sha1_and_echoes_it():
    runner = FakeHashRunner()
    body = post_hash(hash_client(runner), {"hash": SHA1_DIGEST}).get_json()
    assert body["algorithm"] == "sha1"
    assert runner.seen == (SHA1_DIGEST, Algorithm.SHA1)


def test_hash_accepts_an_explicit_ntlm_digest():
    runner = FakeHashRunner()
    body = post_hash(hash_client(runner), {"hash": NTLM_A, "algorithm": "ntlm"}).get_json()
    assert body["algorithm"] == "ntlm"
    assert runner.seen == (NTLM_A, Algorithm.NTLM)


def test_hash_normalises_case_before_lookup():
    runner = FakeHashRunner()
    post_hash(hash_client(runner), {"hash": SHA1_DIGEST.upper()})
    assert runner.seen[0] == SHA1_DIGEST


def test_hash_includes_the_per_check_breakdown():
    body = post_hash(hash_client(), {"hash": SHA1_DIGEST}).get_json()
    assert [c["name"] for c in body["checks"]] == ["hibp", "weakpass"]
    assert set(body["checks"][0]) == {
        "name",
        "enabled",
        "applicable",
        "skipped",
        "hit",
        "count",
        "error",
    }


def test_hash_exposes_degraded_and_its_message():
    runner = FakeHashRunner(evaluation(Verdict.SAFE, degraded=True))
    body = post_hash(hash_client(runner), {"hash": SHA1_DIGEST}).get_json()
    assert body["degraded"] is True
    assert body["degradedMessage"]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"hash": None},
        {"hash": 123},
        {"hash": ""},
        {"hash": "abc"},  # too short for sha1
        {"hash": "z" * 40},  # not hex
        {"hash": NTLM_A},  # 32 hex, but sha1 is the default
        {"hash": SHA1_DIGEST, "algorithm": "ntlm"},  # 40 hex against ntlm
        {"hash": SHA1_DIGEST, "algorithm": "md5"},
        {"hash": SHA1_DIGEST, "algorithm": 7},
        {"hash": SHA1_DIGEST, "algorithm": None},
    ],
)
def test_hash_bad_payload_is_400_in_the_same_envelope(payload):
    response = post_hash(hash_client(), payload)
    body = response.get_json()
    assert response.status_code == 400
    assert body["error"] is True
    assert isinstance(body["errorMessage"], str)


def test_hash_rejects_a_body_that_is_not_an_object():
    assert hash_client().post("/api/v1/check/hash", json=[]).status_code == 400
    assert hash_client().post("/api/v1/check/hash", data="hash=x").status_code == 400


def test_hash_get_is_not_allowed():
    assert hash_client().get("/api/v1/check/hash").status_code == 405


def test_hash_accepts_a_cp1252_encoded_body():
    runner = FakeHashRunner()
    body = b'{"hash":"' + SHA1_DIGEST.encode() + b'","note":"caf\xe9"}'
    response = hash_client(runner).post(
        "/api/v1/check/hash", data=body, content_type="application/json; charset=UTF-8"
    )
    assert response.status_code == 200
    assert runner.seen == (SHA1_DIGEST, Algorithm.SHA1)


def test_hash_rejection_does_not_echo_the_submitted_digest():
    bad = "z" * 40
    response = post_hash(hash_client(), {"hash": bad})
    assert response.status_code == 400
    assert bad not in response.get_data(as_text=True)


def test_hash_rejects_an_algorithm_no_backend_supports():
    runner = FakeHashRunner(supported=[Algorithm.SHA1])
    response = post_hash(hash_client(runner), {"hash": NTLM_A, "algorithm": "ntlm"})
    assert response.status_code == 400
    assert runner.seen is None


def test_hash_shares_the_interactive_rate_limit_bucket(tmp_path):
    """/check and /check/hash are the same work; one must not double the budget."""
    path = tmp_path / "config.yaml"
    path.write_text(
        "policy:\n  rate_limit:\n    requests: 2\n    per_seconds: 60\n", encoding="utf-8"
    )

    class BothRunner(FakeHashRunner):
        def evaluate(self, password):
            return self._evaluation

    client = hash_client(BothRunner(), config=load_config(path, env={}))
    assert client.post("/api/v1/check", json={"password": "correcthorse"}).status_code == 200
    assert post_hash(client, {"hash": SHA1_DIGEST}).status_code == 200
    assert post_hash(client, {"hash": SHA1_DIGEST}).status_code == 429


def test_hash_rate_limit_can_be_disabled(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        "policy:\n  rate_limit:\n    enabled: false\n    requests: 1\n", encoding="utf-8"
    )
    client = hash_client(config=load_config(path, env={}))
    for _ in range(5):
        assert post_hash(client, {"hash": SHA1_DIGEST}).status_code == 200


def test_hash_a_malformed_body_costs_no_rate_limit_token(tmp_path):
    """Validation runs before the limiter, so junk cannot exhaust a client's budget."""
    path = tmp_path / "config.yaml"
    path.write_text(
        "policy:\n  rate_limit:\n    requests: 1\n    per_seconds: 60\n", encoding="utf-8"
    )
    client = hash_client(config=load_config(path, env={}))
    for _ in range(5):
        assert post_hash(client, {"hash": "nope"}).status_code == 400
    assert post_hash(client, {"hash": SHA1_DIGEST}).status_code == 200


def test_hash_runner_exception_is_500_with_the_configured_message():
    class Exploding(FakeHashRunner):
        def evaluate_digest(self, digest, algorithm):
            raise RuntimeError("boom")

    response = post_hash(hash_client(Exploding()), {"hash": SHA1_DIGEST})
    body = response.get_json()
    assert response.status_code == 500
    assert body["error"] is True
    assert body["errorMessage"] == "Something went wrong while checking this password."


def test_hash_response_is_not_cacheable():
    response = post_hash(hash_client(), {"hash": SHA1_DIGEST})
    assert response.headers["Cache-Control"] == "no-store"


def test_hash_never_returns_too_short(tmp_path):
    """check_hash applies no length gate of its own: policy.min_length is
    deliberately unenforceable on a digest, since a digest carries no record
    of the length of the password it came from.

    A high min_length is configured so a length gate, if one were added by a
    future regression, would either short-circuit before the runner is ever
    called (caught by `runner.seen`) or would come back as a `too_short`
    verdict (caught by the status/verdict assertions below).
    """
    path = tmp_path / "config.yaml"
    path.write_text("policy:\n  min_length: 64\n", encoding="utf-8")
    runner = FakeHashRunner()
    response = post_hash(
        hash_client(runner, config=load_config(path, env={})), {"hash": sha1_hex("a")}
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["verdict"] != "too_short"
    assert runner.seen is not None


def test_weak_verdict():
    body = post(client_for(evaluation(Verdict.WEAK)), {"password": "aaaaaaaa"}).get_json()
    assert body["error"] is True
    assert body["errorMessage"] == "This password is too easy to guess."
    assert body["verdict"] == "weak"


def real_client():
    config = load_config(None, env={})
    app = create_app(config=config)
    app.config.update(TESTING=True)
    return app.test_client()


@responses.activate
def test_end_to_end_weak_password_via_the_real_worker():
    body = post(real_client(), {"password": "password"}).get_json()
    assert body["verdict"] == "weak"
    assert body["error"] is True


@responses.activate
def test_end_to_end_strong_password_via_the_real_worker():
    strong = "Xk9-f3a7c1b2e4d6-correct-horse-battery-staple"
    digest = sha1_hex(strong)
    responses.get(f"https://api.pwnedpasswords.com/range/{digest[:5].upper()}", body="AAAA:1\n")
    responses.get(f"https://weakpass.com/api/v1/range/{digest[:6]}.txt", body="deadbeef\n")
    body = post(real_client(), {"password": strong}).get_json()
    assert body["verdict"] == "safe"
    assert body["error"] is False


def _config_with_denylist(tmp_path, word="acme", rules=()):
    """A real config wired to a temp word file, with strength scoring disabled.

    Strength is unrelated to what these tests exercise (the denylist gate and
    the denylist digest checker) and its real scorer would add flakiness and a
    node.js dependency for no benefit here.
    """
    word_file = tmp_path / "words.txt"
    word_file.write_text(f"{word}\n", encoding="utf-8")
    config = load_config(None, env={})
    object.__setattr__(
        config,
        "denylist",
        DenylistConfig(
            path=str(word_file),
            min_token_length=4,
            match_plaintext=True,
            rules=rules,
            max_digests=1_000_000,
            cache_path=None,
        ),
    )
    object.__setattr__(config, "strength", StrengthConfig(enabled=False, min_score=3, timeout=2.0))
    # The path -> enabled reconciliation in config._build already ran (against
    # the original null path) before this post-hoc swap set a real path, so it
    # needs to be redone here for the DenylistChecker to actually get wired.
    object.__setattr__(
        config,
        "checks",
        {**config.checks, "denylist": dataclasses.replace(config.checks["denylist"], enabled=True)},
    )
    return config


def mock_upstream_misses(digest):
    """Mock hibp/weakpass as MISSES for `digest`, matching the URL shapes in
    tests/test_no_leak.py::mock_upstreams -- so a denylist hit is the only
    possible source of a non-safe verdict."""
    responses.get(f"https://api.pwnedpasswords.com/range/{digest[:5].upper()}", body="")
    responses.get(f"https://weakpass.com/api/v1/range/{digest[:6]}.txt", body="")


@responses.activate
def test_plaintext_denylist_hit_on_check(tmp_path):
    config = _config_with_denylist(tmp_path, word="acme")
    mock_upstream_misses(sha1_hex("ACME2026!"))
    app = create_app(config=config)
    app.config.update(TESTING=True)
    response = post(app.test_client(), {"password": "ACME2026!"})
    body = response.get_json()
    assert body["verdict"] == "denylisted"
    assert body["error"] is True


@responses.activate
def test_digest_denylist_hit_on_check_hash(tmp_path):
    config = _config_with_denylist(tmp_path, word="acme")
    digest = sha1_hex("acme")
    mock_upstream_misses(digest)
    app = create_app(config=config)
    app.config.update(TESTING=True)
    response = app.test_client().post("/api/v1/check/hash", json={"hash": digest})
    body = response.get_json()
    assert body["verdict"] == "denylisted"
    assert body["error"] is True


@responses.activate
def test_documented_asymmetry(tmp_path):
    """A plaintext ban can catch a mutation the digest set never produced.

    "ACME2026!" is denylisted on /check via substring matching against the
    normalized token "acme", but with an empty rule set the digest set holds
    only sha1("acme") itself -- not sha1("ACME2026!") -- so /check/hash for
    that exact string is safe. This is the documented asymmetry between the
    two endpoints, not a bug.
    """
    config = _config_with_denylist(tmp_path, word="acme", rules=())
    plaintext_digest = sha1_hex("ACME2026!")
    app = create_app(config=config)
    app.config.update(TESTING=True)
    # The plaintext gate rejects on the substring match alone -- no digest is
    # computed for an upstream call, so no mocks are needed for this request.
    plaintext_body = post(app.test_client(), {"password": "ACME2026!"}).get_json()
    assert plaintext_body["verdict"] == "denylisted"

    mock_upstream_misses(plaintext_digest)
    hash_body = (
        app.test_client().post("/api/v1/check/hash", json={"hash": plaintext_digest}).get_json()
    )
    assert hash_body["verdict"] == "safe"
