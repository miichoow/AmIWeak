import pytest

from amiweak.algorithms import Algorithm
from amiweak.config import ENV_RESERVED, ConfigError, load_config

MINIMAL = """
server:
  host: "0.0.0.0"
  port: 9000
"""


def write(tmp_path, text):
    p = tmp_path / "config.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_loads_values_from_yaml(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={})
    assert cfg.server.host == "0.0.0.0"
    assert cfg.server.port == 9000


def test_applies_defaults_for_missing_sections(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={})
    assert cfg.checks["hibp"].enabled is True
    assert cfg.checks["weakpass"].on_error == "fail_open"
    assert cfg.policy.min_length == 8
    assert cfg.http.verify_tls is True


def test_missing_file_uses_all_defaults(tmp_path):
    cfg = load_config(tmp_path / "nope.yaml", env={})
    assert cfg.server.port == 8080


def test_no_path_uses_all_defaults():
    assert load_config(None, env={}).server.port == 8080


def test_env_override_scalar(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_SERVER__PORT": "1234"})
    assert cfg.server.port == 1234


def test_env_override_nested_bool(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_CHECKS__HIBP__ENABLED": "false"})
    assert cfg.checks["hibp"].enabled is False


def test_env_override_message(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_MESSAGES__SAFE": "fine"})
    assert cfg.messages.safe == "fine"


def test_env_override_float(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_HTTP__TIMEOUT": "1.5"})
    assert cfg.http.timeout == 1.5


def test_env_override_sets_proxy(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_PROXY__HTTPS": "http://proxy:3128"})
    assert cfg.proxy.https == "http://proxy:3128"


def test_config_path_env_var_is_not_treated_as_a_key(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_CONFIG": "/somewhere.yaml"})
    assert cfg.server.port == 9000


def test_worker_count_env_var_is_not_treated_as_a_key(tmp_path):
    # gunicorn.conf.py reads AMIWEAK_WORKERS to size the pool. It lives under the
    # prefix but names no configuration key, so without the exemption every
    # worker gunicorn forked would fail to start.
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_WORKERS": "8"})
    assert cfg.server.port == 9000


@pytest.mark.parametrize("name", sorted(ENV_RESERVED))
def test_every_reserved_env_var_is_exempt_from_key_matching(tmp_path, name):
    assert load_config(write(tmp_path, MINIMAL), env={name: "x"}).server.port == 9000


def test_unknown_key_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="server.prot"):
        load_config(write(tmp_path, "server:\n  prot: 80\n"), env={})


def test_unknown_env_key_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="AMIWEAK_SERVER__PROT"):
        load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_SERVER__PROT": "80"})


def test_bad_port_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="server.port"):
        load_config(write(tmp_path, "server:\n  port: 99999\n"), env={})


def test_non_positive_timeout_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="http.timeout"):
        load_config(write(tmp_path, "http:\n  timeout: 0\n"), env={})


def test_check_timeout_inherits_http_timeout_when_unset(tmp_path):
    cfg = load_config(write(tmp_path, "http:\n  timeout: 12.5\n"), env={})
    assert [c.timeout for c in cfg.checks.values()] == [12.5, 12.5, 12.5]


def test_check_timeout_inherits_the_http_default_when_neither_is_set():
    cfg = load_config(None, env={})
    assert cfg.http.timeout == 5.0
    assert cfg.checks["hibp"].timeout == 5.0


def test_explicit_check_timeout_overrides_http_timeout(tmp_path):
    text = "http:\n  timeout: 12.5\nchecks:\n  hibp:\n    timeout: 1.5\n"
    cfg = load_config(write(tmp_path, text), env={})
    assert cfg.checks["hibp"].timeout == 1.5
    # Only the backend that asked for it: the others still inherit.
    assert cfg.checks["weakpass"].timeout == 12.5


def test_check_timeout_from_the_environment_is_a_number_not_a_string(tmp_path):
    # The default is None, which carries no type for _coerce_like to copy, so
    # without NUMERIC_WHEN_UNSET this would arrive as the string "1.5".
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_CHECKS__HIBP__TIMEOUT": "1.5"})
    assert cfg.checks["hibp"].timeout == 1.5


def test_non_numeric_check_timeout_from_the_environment_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="AMIWEAK_CHECKS__HIBP__TIMEOUT"):
        load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_CHECKS__HIBP__TIMEOUT": "soon"})


def test_non_positive_check_timeout_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="checks.hibp.timeout"):
        load_config(write(tmp_path, "checks:\n  hibp:\n    timeout: 0\n"), env={})


def test_bad_on_error_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="on_error"):
        load_config(write(tmp_path, "checks:\n  hibp:\n    on_error: maybe\n"), env={})


def test_bad_log_level_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="logging.level"):
        load_config(write(tmp_path, "logging:\n  level: CHATTY\n"), env={})


def test_empty_message_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="messages.safe"):
        load_config(write(tmp_path, 'messages:\n  safe: ""\n'), env={})


def test_out_of_range_min_score_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="strength.min_score"):
        load_config(write(tmp_path, "strength:\n  min_score: 9\n"), env={})


def test_malformed_yaml_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="parse"):
        load_config(write(tmp_path, "server: [unclosed\n"), env={})


def test_non_mapping_document_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="mapping"):
        load_config(write(tmp_path, "- a\n- b\n"), env={})


def test_empty_file_is_all_defaults(tmp_path):
    assert load_config(write(tmp_path, ""), env={}).server.port == 8080


def test_env_override_with_bad_type_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="AMIWEAK_SERVER__PORT"):
        load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_SERVER__PORT": "abc"})


def test_env_override_with_bad_bool_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="AMIWEAK_CHECKS__HIBP__ENABLED"):
        load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_CHECKS__HIBP__ENABLED": "maybe"})


def test_env_override_with_bad_float_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="AMIWEAK_HTTP__TIMEOUT"):
        load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_HTTP__TIMEOUT": "abc"})


def test_env_key_with_a_bad_intermediate_segment_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="AMIWEAK_CHECKS__NOPE__ENABLED"):
        load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_CHECKS__NOPE__ENABLED": "true"})


def test_a_bool_where_an_int_is_expected_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="policy.min_length"):
        load_config(write(tmp_path, "policy:\n  min_length: true\n"), env={})


def test_negative_min_length_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="must not be negative"):
        load_config(write(tmp_path, "policy:\n  min_length: -1\n"), env={})


def test_loading_does_not_mutate_the_module_defaults(tmp_path):
    """A shallow copy here let one env override rewrite DEFAULTS process-wide."""
    from amiweak.config import DEFAULTS

    load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_CHECKS__HIBP__ENABLED": "false"})
    assert DEFAULTS["checks"]["hibp"]["enabled"] is True
    assert load_config(None, env={}).checks["hibp"].enabled is True


def test_a_file_override_does_not_leak_into_the_next_load(tmp_path):
    load_config(write(tmp_path, "policy:\n  min_length: 20\n"), env={})
    assert load_config(None, env={}).policy.min_length == 8


def test_shipped_config_file_is_valid():
    cfg = load_config("config.yaml", env={})
    assert cfg.messages.leaked


def test_batch_and_cache_defaults():
    config = load_config(None, env={})
    assert config.batch.enabled is True
    assert config.batch.max_items == 1000
    assert config.batch.max_concurrency == 8
    assert config.batch.deadline == 120.0
    assert config.batch.max_label_length == 128
    assert config.batch.rate_limit.prefixes == 5000
    assert config.batch.rate_limit.per_seconds == 3600
    assert config.cache.enabled is True
    assert config.cache.max_entries == 256
    assert config.cache.ttl_seconds == 3600.0


def test_checks_default_to_both_algorithms():
    config = load_config(None, env={})
    assert config.checks["hibp"].algorithms == (Algorithm.SHA1, Algorithm.NTLM)
    assert config.checks["weakpass"].algorithms == (Algorithm.SHA1, Algorithm.NTLM)


def test_algorithms_can_be_narrowed_from_a_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("checks:\n  hibp:\n    algorithms: [sha1]\n", encoding="utf-8")
    config = load_config(path, env={})
    assert config.checks["hibp"].algorithms == (Algorithm.SHA1,)


def test_algorithms_can_be_set_from_the_environment():
    config = load_config(None, env={"AMIWEAK_CHECKS__HIBP__ALGORITHMS": "sha1"})
    assert config.checks["hibp"].algorithms == (Algorithm.SHA1,)


def test_algorithms_from_the_environment_split_on_commas():
    config = load_config(None, env={"AMIWEAK_CHECKS__HIBP__ALGORITHMS": "ntlm, sha1"})
    assert config.checks["hibp"].algorithms == (Algorithm.NTLM, Algorithm.SHA1)


def test_unknown_algorithm_is_a_startup_error():
    with pytest.raises(ConfigError, match="algorithms"):
        load_config(None, env={"AMIWEAK_CHECKS__HIBP__ALGORITHMS": "md5"})


def test_empty_algorithm_list_is_a_startup_error(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("checks:\n  hibp:\n    algorithms: []\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="algorithms"):
        load_config(path, env={})


def test_batch_complete_message_placeholders_are_validated(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('messages:\n  batch_complete: "Checked {totl} passwords."\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="batch_complete"):
        load_config(path, env={})


def test_batch_complete_message_rejects_malformed_braces(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text('messages:\n  batch_complete: "Checked {total passwords."\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="batch_complete"):
        load_config(path, env={})


def test_batch_complete_message_accepts_both_placeholders(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(
        'messages:\n  batch_complete: "{total} checked, {failed} failed."\n', encoding="utf-8"
    )
    config = load_config(path, env={})
    assert config.messages.batch_complete.format(total=3, failed=1) == "3 checked, 1 failed."


def test_batch_max_concurrency_must_be_positive():
    with pytest.raises(ConfigError, match="max_concurrency"):
        load_config(None, env={"AMIWEAK_BATCH__MAX_CONCURRENCY": "0"})


def test_strength_timeout_defaults_to_two_seconds():
    config = load_config(None, env={})
    assert config.strength.timeout == 2.0


def test_strength_timeout_is_configurable(tmp_path):
    config = load_config(write(tmp_path, "strength:\n  timeout: 0.5\n"), env={})
    assert config.strength.timeout == 0.5


def test_strength_timeout_must_be_positive(tmp_path):
    with pytest.raises(ConfigError, match="strength.timeout"):
        load_config(write(tmp_path, "strength:\n  timeout: 0\n"), env={})


def test_denylist_defaults_are_off(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={})
    assert cfg.denylist.path is None
    assert cfg.denylist.min_token_length == 4
    assert cfg.denylist.match_plaintext is True
    assert cfg.denylist.rules == ("rules/corporate.rule",)
    assert cfg.denylist.max_digests == 1_000_000
    assert cfg.denylist.cache_path is None
    assert cfg.checks["denylist"].algorithms == (Algorithm.SHA1,)
    assert cfg.messages.denylisted


def test_denylist_values_load_from_yaml(tmp_path):
    text = (
        MINIMAL
        + """
denylist:
  path: "words.txt"
  min_token_length: 5
  match_plaintext: false
  rules: []
  max_digests: 50
  cache_path: "/var/cache/words.bin"
"""
    )
    cfg = load_config(write(tmp_path, text), env={})
    assert cfg.denylist.path == "words.txt"
    assert cfg.denylist.min_token_length == 5
    assert cfg.denylist.match_plaintext is False
    assert cfg.denylist.rules == ()
    assert cfg.denylist.max_digests == 50
    assert cfg.denylist.cache_path == "/var/cache/words.bin"


def test_denylist_min_token_length_must_be_positive(tmp_path):
    text = MINIMAL + "\ndenylist:\n  min_token_length: 0\n"
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text), env={})


def test_denylist_path_env_override(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_DENYLIST__PATH": "w.txt"})
    assert cfg.denylist.path == "w.txt"


def test_denylist_rules_env_override_is_comma_split(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_DENYLIST__RULES": "a.rule,b.rule"})
    assert cfg.denylist.rules == ("a.rule", "b.rule")


def test_docs_are_enabled_by_default():
    config = load_config(None, env={})
    assert config.docs.enabled is True


def test_docs_can_be_disabled_from_yaml(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("docs:\n  enabled: false\n", encoding="utf-8")
    config = load_config(path, env={})
    assert config.docs.enabled is False


def test_docs_can_be_disabled_from_the_environment():
    config = load_config(None, env={"AMIWEAK_DOCS__ENABLED": "false"})
    assert config.docs.enabled is False


def test_docs_enabled_must_be_a_boolean(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("docs:\n  enabled: maybe\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path, env={})


def test_state_defaults_to_per_process() -> None:
    config = load_config(None, env={})
    assert config.state.path is None
    assert config.state.busy_timeout == 5.0


def test_state_path_from_env() -> None:
    config = load_config(None, env={"AMIWEAK_STATE__PATH": "shared.db"})
    assert config.state.path == "shared.db"


def test_state_busy_timeout_must_be_positive(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "config.yaml"
    path.write_text("state:\n  busy_timeout: 0\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="state.busy_timeout"):
        load_config(path, env={})


def test_unknown_state_key_is_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "config.yaml"
    path.write_text("state:\n  pathh: x\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown configuration key"):
        load_config(path, env={})


def test_theme_defaults_to_the_shipped_design(tmp_path):
    assert load_config(write(tmp_path, MINIMAL), env={}).ui.theme == "original"


def test_theme_can_be_selected_from_yaml(tmp_path):
    cfg = load_config(write(tmp_path, "ui:\n  theme: terminal\n"), env={})
    assert cfg.ui.theme == "terminal"


def test_theme_can_be_selected_from_the_environment(tmp_path):
    cfg = load_config(write(tmp_path, MINIMAL), env={"AMIWEAK_UI__THEME": "bento"})
    assert cfg.ui.theme == "bento"


def test_unknown_theme_is_rejected_at_startup(tmp_path):
    with pytest.raises(ConfigError, match="ui.theme"):
        load_config(write(tmp_path, "ui:\n  theme: neon\n"), env={})
