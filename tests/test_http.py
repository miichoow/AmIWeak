from amiweak.config import HttpConfig, ProxyConfig
from amiweak.http import build_session

HTTP = HttpConfig(timeout=3.0, verify_tls=True, user_agent="AmIWeak/test")


def test_session_sets_user_agent_and_verifies_tls():
    session = build_session(HTTP, ProxyConfig(http=None, https=None, no_proxy=None))
    assert session.headers["User-Agent"] == "AmIWeak/test"
    assert session.verify is True


def test_tls_verification_can_not_be_silently_lost():
    session = build_session(
        HttpConfig(timeout=3.0, verify_tls=False, user_agent="AmIWeak/test"),
        ProxyConfig(http=None, https=None, no_proxy=None),
    )
    assert session.verify is False


def test_session_applies_configured_proxies():
    session = build_session(
        HTTP,
        ProxyConfig(http="http://p:3128", https="http://p:3128", no_proxy="localhost"),
    )
    assert session.proxies["https"] == "http://p:3128"
    assert session.proxies["http"] == "http://p:3128"
    assert session.proxies["no_proxy"] == "localhost"


def test_ca_bundle_replaces_the_trust_store_without_disabling_verification(tmp_path):
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    session = build_session(
        HttpConfig(timeout=3.0, verify_tls=True, user_agent="AmIWeak/test", ca_bundle=str(bundle)),
        ProxyConfig(http=None, https=None, no_proxy=None),
    )
    assert session.verify == str(bundle)


def test_ca_bundle_is_ignored_when_verification_is_off(tmp_path):
    session = build_session(
        HttpConfig(timeout=3.0, verify_tls=False, user_agent="AmIWeak/test", ca_bundle="x.pem"),
        ProxyConfig(http=None, https=None, no_proxy=None),
    )
    assert session.verify is False


def test_unset_proxies_are_absent():
    session = build_session(HTTP, ProxyConfig(http=None, https=None, no_proxy=None))
    assert session.proxies == {}


def test_https_adapter_is_mounted_with_retries():
    session = build_session(HTTP, ProxyConfig(http=None, https=None, no_proxy=None))
    adapter = session.get_adapter("https://api.pwnedpasswords.com/range/ABCDE")
    assert adapter.max_retries.total == 1
