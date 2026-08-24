"""Development server (Windows, or anywhere gunicorn is not available).

    python run.py --config config.yaml --port 8080
    python run.py --cert cert.pem --key key.pem --port 8443

This is Werkzeug's single-process server. Use gunicorn in production.
"""

from __future__ import annotations

import argparse
import os
import sys

from amiweak.app import DEFAULT_CONFIG_PATH, create_app
from amiweak.config import ConfigError, load_config


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the AmIWeak development server.")
    parser.add_argument(
        "--config",
        default=os.environ.get("AMIWEAK_CONFIG", DEFAULT_CONFIG_PATH),
        help="path to config.yaml (default: ./config.yaml)",
    )
    parser.add_argument("--host", default=None, help="override the configured host")
    parser.add_argument("--port", type=int, default=None, help="override the configured port")
    parser.add_argument("--cert", default=None, help="TLS certificate file (requires --key)")
    parser.add_argument("--key", default=None, help="TLS private key file (requires --cert)")
    args = parser.parse_args()

    if bool(args.cert) != bool(args.key):
        print("error: --cert and --key must be given together", file=sys.stderr)
        return 2

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    host = args.host or config.server.host
    port = args.port or config.server.port
    ssl_context = (args.cert, args.key) if args.cert and args.key else None
    scheme = "https" if ssl_context else "http"

    print(f"AmIWeak on {scheme}://{host}:{port} — development server, do not use in production.")
    create_app(config=config).run(host=host, port=port, debug=False, ssl_context=ssl_context)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
