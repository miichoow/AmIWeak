"""The outbound HTTP session shared by every checker.

One session per process gives connection pooling across checks, and centralising
it means proxy and TLS settings cannot drift apart between backends.
"""

from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from amiweak.config import HttpConfig, ProxyConfig


def build_session(http: HttpConfig, proxy: ProxyConfig) -> requests.Session:
    """Build a `requests.Session` configured for the upstream range APIs."""
    session = requests.Session()
    # `requests` lets ambient env vars (REQUESTS_CA_BUNDLE, HTTP_PROXY, ...)
    # silently override session.verify/proxies whenever a call omits verify=
    # explicitly. That defeats the whole point of centralising proxy/TLS
    # config here, so this session ignores the environment entirely.
    session.trust_env = False
    session.headers.update(
        {
            "User-Agent": http.user_agent,
            "Accept-Encoding": "gzip",
            "Accept": "text/plain",
        }
    )
    # A network that terminates TLS presents its own certificate, which certifi
    # has never heard of. Point ca_bundle at that CA's PEM rather than reaching
    # for verify_tls: false — the check still works, and it stays verified.
    if not http.verify_tls:
        session.verify = False
    elif http.ca_bundle:
        session.verify = http.ca_bundle
    else:
        session.verify = True

    proxies = {
        key: value
        for key, value in (
            ("http", proxy.http),
            ("https", proxy.https),
            ("no_proxy", proxy.no_proxy),
        )
        if value is not None
    }
    if proxies:
        session.proxies.update(proxies)

    retry = Retry(
        total=1,
        backoff_factor=0.2,
        status_forcelist=(502, 503, 504),
        allowed_methods=frozenset({"GET"}),
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session
