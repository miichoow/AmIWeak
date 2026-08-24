"""Logging that cannot spill a password.

Nothing in this codebase logs a password or a hash to begin with. This module is
the second line, so that a future `logger.debug(request.json)` — or a library
that decides to log a URL — still cannot produce a readable secret.

Redaction is installed as a *log record factory* rather than only as a filter.
A filter added to a logger runs only for records emitted on that exact logger:
`logging.getLogger().addFilter(f)` does nothing for `amiweak.routes.api`,
because `callHandlers` walks ancestors' handlers but not their filters. Handler
filters work, but only for handlers that exist when we run — and pytest, systemd,
and gunicorn all attach their own later. The record factory runs at construction,
before anything can see the record, so no wiring can route around it.

`RedactingFilter` remains for handlers configured outside this module.
"""

from __future__ import annotations

import logging
import re
import traceback

from amiweak.config import LoggingConfig

REDACTED = "[REDACTED]"

# key=value and "key": "value", for the usual names a password travels under.
# `hash` covers the batch endpoint's request body (`{"label": ..., "hash": ...}`);
# `label` is deliberately not here -- it is an arbitrary string, not a
# hash-shaped or predictable-length value, so a keyed regex cannot usefully
# redact it.
_KEYED = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|hash)\b[\"']?\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&}]+)"
)

# A bare hash. 40 hex characters is a SHA-1 digest; 32 is an NTLM digest.
# Matching both means this also redacts MD5 sums and UUIDs that happen to
# appear in a log line -- an acceptable false-positive rate for a redaction
# safety net, where over-redaction is the safe failure mode.
_HEX_DIGEST = re.compile(r"(?i)\b[0-9a-f]{32}\b|\b[0-9a-f]{40}\b")

_TARGET_LOGGERS = ("werkzeug", "gunicorn.error", "gunicorn.access")


def redact(text: str) -> str:
    """Return `text` with password values and hash-shaped hex runs replaced."""
    text = _KEYED.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    return _HEX_DIGEST.sub(REDACTED, text)


def safe_traceback(exc: BaseException) -> str:
    """Format an exception as its type plus stack frames, dropping its message.

    The message is the one part of a traceback that can carry a caller's value —
    `RuntimeError(f"bad password {password}")` is all it takes. Frames carry
    file, line, and source text, which are what you actually need to debug and
    which cannot hold a secret.
    """
    frames = "".join(traceback.format_tb(exc.__traceback__)).rstrip()
    return f"{type(exc).__name__}\n{frames}" if frames else type(exc).__name__


def scrub(record: logging.LogRecord) -> logging.LogRecord:
    """Rewrite a record in place when it holds anything password-shaped."""
    try:
        message = record.getMessage()
    except Exception:  # noqa: BLE001 - a broken format string must not break logging
        message = None

    if message is not None:
        cleaned = redact(message)
        if cleaned != message:
            record.msg = cleaned
            # Clear args so the formatter cannot re-interpolate the originals.
            record.args = None

    # Tracebacks are formatted later, by the handler. Pre-render a message-free
    # version now; Formatter reuses exc_text when it is already set.
    if record.exc_info and record.exc_info[1] is not None:
        record.exc_text = redact(safe_traceback(record.exc_info[1]))
        record.exc_info = None

    return record


class RedactingFilter(logging.Filter):
    """Scrubs a record. Safe to install on any handler or logger."""

    def filter(self, record: logging.LogRecord) -> bool:
        scrub(record)
        return True


def install_record_factory() -> None:
    """Wrap the global log record factory so every record is scrubbed at birth."""
    base = logging.getLogRecordFactory()
    if getattr(base, "_amiweak_redacting", False):
        return

    def factory(*args: object, **kwargs: object) -> logging.LogRecord:
        return scrub(base(*args, **kwargs))

    factory._amiweak_redacting = True  # type: ignore[attr-defined]
    logging.setLogRecordFactory(factory)


def configure_logging(config: LoggingConfig) -> None:
    """Set the log level and make redaction unavoidable."""
    install_record_factory()

    logging.basicConfig(
        level=config.level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    redacting = RedactingFilter()

    root = logging.getLogger()
    root.setLevel(config.level)
    for handler in root.handlers:
        handler.addFilter(redacting)

    for name in _TARGET_LOGGERS:
        logger = logging.getLogger(name)
        for handler in logger.handlers:
            handler.addFilter(redacting)

    if not config.access_log:
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
