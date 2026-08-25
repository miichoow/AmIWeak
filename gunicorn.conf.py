"""Gunicorn settings.

Note the access log format: it uses %(U)s, the path *without* the query string.
The API takes its password by POST so nothing sensitive should reach a URL in the
first place, and dropping the query string means a mistake elsewhere still can't
write one to disk.
"""

import os

_host = os.environ.get("AMIWEAK_SERVER__HOST", "0.0.0.0")
_port = os.environ.get("AMIWEAK_SERVER__PORT", "8080")

bind = f"{_host}:{_port}"
workers = int(os.environ.get("AMIWEAK_WORKERS", "4"))
worker_class = "gthread"
threads = 4
timeout = 30
graceful_timeout = 30

accesslog = "-"
errorlog = "-"
access_log_format = '%(h)s "%(m)s %(U)s" %(s)s %(b)s %(D)s'

# TLS is off unless both are set — e.g. AMIWEAK_CERTFILE=cert.pem AMIWEAK_KEYFILE=key.pem
certfile = os.environ.get("AMIWEAK_CERTFILE") or None
keyfile = os.environ.get("AMIWEAK_KEYFILE") or None
