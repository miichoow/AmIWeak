"""Loading the OpenAPI document.

The spec is read and parsed once, at startup, rather than per request. A
malformed or missing document is a `ConfigError` -- the same fatal signal a
malformed `config.yaml` gives -- because a documentation surface that only fails
on first use is a surface nobody notices is broken.
"""

from __future__ import annotations

import os
from typing import Any

import yaml

from amiweak.config import ConfigError

#: Path relative to the repository root, resolved against the process working
#: directory exactly as `config.yaml` is.
DEFAULT_SPEC_PATH = "openapi.yaml"

#: Every document must carry these. An OpenAPI file without them is not one.
REQUIRED_KEYS = ("openapi", "info", "paths")


def load_spec(path: str | os.PathLike[str] = DEFAULT_SPEC_PATH) -> dict[str, Any]:
    """Read and parse the OpenAPI document, or raise `ConfigError`."""
    try:
        with open(path, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except FileNotFoundError:
        raise ConfigError(f"{path}: OpenAPI specification not found") from None
    except OSError as exc:
        reason = exc.strerror or exc.__class__.__name__
        raise ConfigError(f"{path}: could not be read ({reason})") from None
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: malformed YAML ({exc})") from None

    if not isinstance(document, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")

    missing = [key for key in REQUIRED_KEYS if key not in document]
    if missing:
        raise ConfigError(f"{path}: missing required key(s) {', '.join(missing)}")

    return document
