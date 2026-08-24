import logging

from amiweak.config import LoggingConfig
from amiweak.logging_setup import (
    RedactingFilter,
    configure_logging,
    install_record_factory,
    safe_traceback,
)

HASH = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
NTLM_HASH = "aad3b435b51404eeaad3b435b51404ee"


def filtered(message, *args):
    record = logging.LogRecord("t", logging.INFO, __file__, 1, message, args, None)
    RedactingFilter().filter(record)
    return record.getMessage()


def test_redacts_password_key_in_json_like_text():
    assert "hunter2" not in filtered('{"password": "hunter2"}')


def test_redacts_password_key_in_query_like_text():
    out = filtered("GET /x?password=hunter2&a=1")
    assert "hunter2" not in out
    assert "a=1" in out


def test_redacts_pwd_and_secret_aliases():
    out = filtered("pwd=hunter2 secret=hunter2 passwd=hunter2")
    assert "hunter2" not in out


def test_redacts_bare_sha1_hashes():
    out = filtered(f"looking up {HASH}")
    assert HASH not in out
    assert "[REDACTED]" in out


def test_redacts_bare_ntlm_length_hashes():
    out = filtered(f"looking up {NTLM_HASH}")
    assert NTLM_HASH not in out
    assert "[REDACTED]" in out


def test_redacts_hash_key_in_json_like_text():
    assert NTLM_HASH not in filtered(f'{{"hash": "{NTLM_HASH}"}}')


def test_leaves_ordinary_messages_alone():
    assert filtered("check completed in 0.2s") == "check completed in 0.2s"


def test_keeps_the_key_so_the_line_stays_readable():
    assert "password" in filtered('{"password": "hunter2"}')


def test_redacts_interpolated_arguments():
    assert "hunter2" not in filtered("body=%s", '{"password": "hunter2"}')


def test_survives_a_record_with_broken_formatting():
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "%d", ("x",), None)
    assert RedactingFilter().filter(record) is True


def _raise(message):
    try:
        raise RuntimeError(message)
    except RuntimeError as exc:
        return (type(exc), exc, exc.__traceback__)


def test_safe_traceback_drops_the_exception_message():
    _, exc, _ = _raise("boom hunter2")
    rendered = safe_traceback(exc)
    assert "hunter2" not in rendered
    assert "RuntimeError" in rendered


def test_safe_traceback_keeps_the_frames():
    _, exc, _ = _raise("boom")
    assert "test_logging_setup.py" in safe_traceback(exc)


def test_exception_message_is_dropped_from_a_record():
    record = logging.LogRecord(
        "t", logging.ERROR, __file__, 1, "failed", None, _raise("boom hunter2")
    )
    RedactingFilter().filter(record)
    assert "hunter2" not in (record.exc_text or "")
    assert record.exc_info is None


def test_formatted_output_carries_no_exception_message():
    record = logging.LogRecord(
        "t", logging.ERROR, __file__, 1, "failed", None, _raise("boom hunter2")
    )
    RedactingFilter().filter(record)
    assert "hunter2" not in logging.Formatter("%(message)s").format(record)


def test_record_factory_scrubs_records_from_any_logger(caplog):
    # A logger-level filter on root would never see this record; the factory does.
    install_record_factory()
    caplog.set_level(logging.DEBUG)
    logging.getLogger("amiweak.somewhere.deep").info('{"password": "hunter2"}')
    assert "hunter2" not in "\n".join(r.getMessage() for r in caplog.records)


def test_record_factory_is_installed_only_once():
    install_record_factory()
    first = logging.getLogRecordFactory()
    install_record_factory()
    assert logging.getLogRecordFactory() is first


def test_configure_logging_sets_the_level():
    configure_logging(LoggingConfig(level="WARNING", access_log=True))
    assert logging.getLogger().level == logging.WARNING
    configure_logging(LoggingConfig(level="INFO", access_log=True))


def test_access_log_can_be_silenced():
    configure_logging(LoggingConfig(level="INFO", access_log=False))
    assert logging.getLogger("werkzeug").level == logging.ERROR
    logging.getLogger("werkzeug").setLevel(logging.NOTSET)


def test_a_handler_on_a_target_logger_is_also_filtered():
    target = logging.getLogger("werkzeug")
    handler = logging.StreamHandler()
    target.addHandler(handler)
    try:
        configure_logging(LoggingConfig(level="INFO", access_log=True))
        assert any(isinstance(f, RedactingFilter) for f in handler.filters)
    finally:
        target.removeHandler(handler)
