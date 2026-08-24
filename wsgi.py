"""Gunicorn entrypoint (Linux).

gunicorn -c gunicorn.conf.py wsgi:app
"""

from amiweak.app import create_app

app = create_app()
