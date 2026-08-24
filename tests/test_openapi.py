import pytest

from amiweak.config import ConfigError
from amiweak.openapi import DEFAULT_SPEC_PATH, load_spec


def test_loads_the_shipped_specification():
    spec = load_spec(DEFAULT_SPEC_PATH)
    assert spec["openapi"].startswith("3.")
    assert "info" in spec
    assert "paths" in spec


def test_a_missing_file_is_a_startup_error(tmp_path):
    with pytest.raises(ConfigError) as exc:
        load_spec(tmp_path / "nope.yaml")
    assert "not found" in str(exc.value)


def test_an_unreadable_path_is_a_startup_error_not_a_missing_file_error(tmp_path):
    # Opening a directory fails with an OSError that is not FileNotFoundError
    # -- distinct from the "not found" path, still a clean ConfigError.
    with pytest.raises(ConfigError, match="could not be read"):
        load_spec(tmp_path)


def test_malformed_yaml_is_a_startup_error(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("openapi: 3.1.0\n  bad indent: [\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_spec(path)


def test_a_document_that_is_not_a_mapping_is_a_startup_error(tmp_path):
    path = tmp_path / "list.yaml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_spec(path)


def test_a_document_missing_required_top_level_keys_is_a_startup_error(tmp_path):
    path = tmp_path / "thin.yaml"
    path.write_text("openapi: 3.1.0\n", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_spec(path)
    assert "info" in str(exc.value) or "paths" in str(exc.value)


def _refs(node):
    """Every $ref string anywhere in the document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _refs(item)


def test_every_ref_resolves_to_a_defined_component():
    spec = load_spec(DEFAULT_SPEC_PATH)
    schemas = spec["components"]["schemas"]
    for ref in _refs(spec):
        assert ref.startswith("#/components/schemas/"), ref
        assert ref.rsplit("/", 1)[-1] in schemas, ref


def test_the_server_url_is_relative():
    # An absolute URL would hardcode one deployment's hostname and would send
    # the console's try-it-out requests somewhere other than the origin that
    # served the page.
    spec = load_spec(DEFAULT_SPEC_PATH)
    for server in spec["servers"]:
        assert server["url"].startswith("/"), server


def test_the_verdict_enum_matches_the_code():
    from amiweak.checks.runner import Verdict

    spec = load_spec(DEFAULT_SPEC_PATH)
    documented = set(spec["components"]["schemas"]["Verdict"]["enum"])
    assert documented == {str(v) for v in Verdict}


def test_the_algorithm_enum_matches_the_code():
    from amiweak.algorithms import Algorithm

    spec = load_spec(DEFAULT_SPEC_PATH)
    documented = set(spec["components"]["schemas"]["Algorithm"]["enum"])
    assert documented == {str(a) for a in Algorithm}
