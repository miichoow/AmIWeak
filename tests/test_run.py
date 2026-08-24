"""`run.py`'s CLI: TLS flag validation and how they reach `Flask.run`."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from flask import Flask

import run
from amiweak.config import load_config


@pytest.fixture(autouse=True)
def _capture_flask_run(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Stand in for Flask.run so tests never actually bind a socket."""
    calls: list[dict[str, Any]] = []

    def fake_run(self: Flask, **kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(Flask, "run", fake_run)
    return calls


@pytest.fixture(autouse=True)
def _config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("server:\n  host: 127.0.0.1\n  port: 8080\n", encoding="utf-8")
    monkeypatch.setenv("AMIWEAK_CONFIG", str(config_path))
    load_config(str(config_path))  # fails fast here if the fixture's YAML is wrong


def _argv(*args: str) -> list[str]:
    return ["run.py", *args]


def test_no_cert_or_key_runs_without_tls(
    monkeypatch: pytest.MonkeyPatch, _capture_flask_run: list[dict[str, Any]]
) -> None:
    monkeypatch.setattr(sys, "argv", _argv())
    assert run.main() == 0
    assert _capture_flask_run[-1]["ssl_context"] is None


def test_cert_and_key_together_enable_tls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, _capture_flask_run: list[dict[str, Any]]
) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    monkeypatch.setattr(sys, "argv", _argv("--cert", str(cert), "--key", str(key)))
    assert run.main() == 0
    assert _capture_flask_run[-1]["ssl_context"] == (str(cert), str(key))


def test_cert_without_key_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    _capture_flask_run: list[dict[str, Any]],
) -> None:
    monkeypatch.setattr(sys, "argv", _argv("--cert", str(tmp_path / "cert.pem")))
    assert run.main() == 2
    assert "--cert and --key must be given together" in capsys.readouterr().err
    assert _capture_flask_run == []


def test_unreadable_config_is_reported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    _capture_flask_run: list[dict[str, Any]],
) -> None:
    broken = tmp_path / "broken.yaml"
    broken.write_text("server: [unclosed\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", _argv("--config", str(broken)))
    assert run.main() == 2
    assert "configuration error:" in capsys.readouterr().err
    assert _capture_flask_run == []


def test_key_without_cert_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    _capture_flask_run: list[dict[str, Any]],
) -> None:
    monkeypatch.setattr(sys, "argv", _argv("--key", str(tmp_path / "key.pem")))
    assert run.main() == 2
    assert "--cert and --key must be given together" in capsys.readouterr().err
    assert _capture_flask_run == []
