"""Configuration loading: a YAML file, then AMIWEAK_* environment overrides.

Every scalar in the shipped `config.yaml` can be overridden by an environment
variable named after its path, uppercased, with `__` between levels:

    AMIWEAK_SERVER__PORT=9000
    AMIWEAK_CHECKS__HIBP__ENABLED=false
    AMIWEAK_MESSAGES__LEAKED="Change this password."

Unknown keys are rejected rather than ignored. A typo'd `enabld: false` that
silently left a check running would be worse than a startup failure.
"""

from __future__ import annotations

import copy
import dataclasses
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import yaml

from amiweak.algorithms import Algorithm, parse_algorithm

ENV_PREFIX = "AMIWEAK_"
ENV_SEPARATOR = "__"

# Environment variables that live under the prefix but are not configuration keys.
# AMIWEAK_WORKERS is read by gunicorn.conf.py, in the master process, before this
# module ever runs; without the exemption every worker it forks would then die
# here on the very variable that decided how many of them to fork.
ENV_RESERVED = {"AMIWEAK_CONFIG", "AMIWEAK_OPENAPI", "AMIWEAK_WORKERS"}

LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}

# Page designs. "original" is templates/index.html with static/css/app.css;
# every other name is templates/themes/<name>.html with a matching stylesheet.
# Adding a theme means adding both files and a name here.
THEMES = {"original", "vault", "terminal", "editorial", "bento"}
ON_ERROR_POLICIES = {"fail_open", "fail_closed"}


class ConfigError(Exception):
    """Raised when configuration is malformed or invalid."""


BATCH_MESSAGE_FIELDS = frozenset({"total", "failed"})


DEFAULTS: dict[str, Any] = {
    "server": {"host": "127.0.0.1", "port": 8080},
    "proxy": {"http": None, "https": None, "no_proxy": None},
    "http": {
        "timeout": 5.0,
        "verify_tls": True,
        "ca_bundle": None,
        "user_agent": "AmIWeak/1.0",
    },
    # `timeout: None` means "inherit http.timeout". A number here overrides it
    # for that backend alone.
    "checks": {
        "hibp": {
            "enabled": True,
            "timeout": None,
            "on_error": "fail_open",
            "algorithms": ["sha1", "ntlm"],
        },
        "weakpass": {
            "enabled": True,
            "timeout": None,
            "on_error": "fail_open",
            "algorithms": ["sha1", "ntlm"],
        },
        "denylist": {
            "enabled": True,
            "timeout": None,
            "on_error": "fail_open",
            "algorithms": ["sha1"],
        },
    },
    "batch": {
        "enabled": True,
        "max_items": 1000,
        "max_concurrency": 8,
        "deadline": 120.0,
        "max_label_length": 128,
        "rate_limit": {"enabled": True, "prefixes": 5000, "per_seconds": 3600},
    },
    "cache": {"enabled": True, "max_entries": 256, "ttl_seconds": 3600.0},
    "state": {"path": None, "busy_timeout": 5.0},
    "denylist": {
        "path": None,
        "min_token_length": 4,
        "match_plaintext": True,
        "rules": ["rules/corporate.rule"],
        "max_digests": 1_000_000,
        "cache_path": None,
    },
    "policy": {
        "overall_deadline": 8.0,
        "min_length": 8,
        "rate_limit": {"enabled": True, "requests": 30, "per_seconds": 60},
    },
    "strength": {"enabled": True, "min_score": 3, "timeout": 2.0},
    "docs": {"enabled": True},
    "ui": {"theme": "original"},
    "messages": {
        "safe": "This password looks fine.",
        "leaked": "This password has appeared in a known data breach.",
        "precomputed": "This password is in a public password-cracking list.",
        "weak": "This password is too easy to guess.",
        "too_short": "This password is too short.",
        "degraded": "One of the checks could not be reached, so this result is incomplete.",
        "error": "Something went wrong while checking this password.",
        "batch_complete": "Checked {total} passwords.",
        "denylisted": "This password contains something specific to your organisation.",
    },
    "logging": {"level": "INFO", "access_log": True},
}


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int


@dataclass(frozen=True)
class ProxyConfig:
    http: str | None
    https: str | None
    no_proxy: str | None


@dataclass(frozen=True)
class HttpConfig:
    timeout: float
    verify_tls: bool
    user_agent: str
    ca_bundle: str | None = None


@dataclass(frozen=True)
class CheckConfig:
    enabled: bool
    timeout: float
    on_error: str
    algorithms: tuple[Algorithm, ...] = (Algorithm.SHA1,)


@dataclass(frozen=True)
class RateLimitConfig:
    enabled: bool
    requests: int
    per_seconds: int


@dataclass(frozen=True)
class BatchRateLimitConfig:
    enabled: bool
    prefixes: int
    per_seconds: int


@dataclass(frozen=True)
class BatchConfig:
    enabled: bool
    max_items: int
    max_concurrency: int
    deadline: float
    max_label_length: int
    rate_limit: BatchRateLimitConfig


@dataclass(frozen=True)
class CacheConfig:
    enabled: bool
    max_entries: int
    ttl_seconds: float


@dataclass(frozen=True)
class StateConfig:
    path: str | None
    busy_timeout: float


@dataclass(frozen=True)
class PolicyConfig:
    overall_deadline: float
    min_length: int
    rate_limit: RateLimitConfig


@dataclass(frozen=True)
class StrengthConfig:
    enabled: bool
    min_score: int
    timeout: float


@dataclass(frozen=True)
class DocsConfig:
    enabled: bool


@dataclass(frozen=True)
class UiConfig:
    theme: str


@dataclass(frozen=True)
class DenylistConfig:
    path: str | None
    min_token_length: int
    match_plaintext: bool
    rules: tuple[str, ...]
    max_digests: int
    cache_path: str | None


@dataclass(frozen=True)
class MessagesConfig:
    safe: str
    leaked: str
    precomputed: str
    weak: str
    too_short: str
    degraded: str
    error: str
    batch_complete: str
    denylisted: str


@dataclass(frozen=True)
class LoggingConfig:
    level: str
    access_log: bool


@dataclass(frozen=True)
class Config:
    server: ServerConfig
    proxy: ProxyConfig
    http: HttpConfig
    checks: dict[str, CheckConfig]
    policy: PolicyConfig
    strength: StrengthConfig
    docs: DocsConfig
    ui: UiConfig
    messages: MessagesConfig
    logging: LoggingConfig
    batch: BatchConfig
    cache: CacheConfig
    denylist: DenylistConfig
    state: StateConfig


def _merge(defaults: dict[str, Any], override: Any, path: str = "") -> dict[str, Any]:
    """Overlay `override` onto `defaults`, rejecting keys the defaults do not define.

    The copy has to be deep. A shallow one leaves nested dicts shared with
    DEFAULTS, and `_apply_env` writes into them — so a single
    `AMIWEAK_CHECKS__HIBP__ENABLED=false` would silently rewrite the defaults for
    the rest of the process.
    """
    if override is None:
        return copy.deepcopy(defaults)
    if not isinstance(override, dict):
        raise ConfigError(f"{path or 'config'}: expected a mapping")
    merged: dict[str, Any] = copy.deepcopy(defaults)
    for key, value in override.items():
        node = f"{path}.{key}" if path else str(key)
        if key not in defaults:
            raise ConfigError(f"{node}: unknown configuration key")
        if isinstance(defaults[key], dict):
            merged[key] = _merge(defaults[key], value, node)
        else:
            merged[key] = value
    return merged


def _as_bool(raw: str, source: str) -> bool:
    lowered = raw.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{source}: expected a boolean, got {raw!r}")


def _as_int(raw: str, source: str) -> int:
    try:
        return int(raw.strip())
    except ValueError:
        raise ConfigError(f"{source}: expected an integer, got {raw!r}") from None


def _as_float(raw: str, source: str) -> float:
    try:
        return float(raw.strip())
    except ValueError:
        raise ConfigError(f"{source}: expected a number, got {raw!r}") from None


#: Leaf names whose default is `None` but which take a number when set.
#: `_coerce_like` reads the type of the value it replaces, and `None` carries no
#: type, so a nullable numeric key has to declare itself or an environment
#: override would arrive as a string and fail validation.
NUMERIC_WHEN_UNSET = frozenset({"timeout"})


def _coerce_like(current: Any, raw: str, source: str, leaf: str = "") -> Any:
    """Coerce an environment string to the type of the value it replaces."""
    if current is None and leaf in NUMERIC_WHEN_UNSET:
        return _as_float(raw, source)
    if isinstance(current, list):
        # A list-valued key is set as a comma-separated string:
        #   AMIWEAK_CHECKS__HIBP__ALGORITHMS="sha1,ntlm"
        return [part.strip() for part in raw.split(",") if part.strip()]
    if isinstance(current, bool):
        return _as_bool(raw, source)
    if isinstance(current, int):
        return _as_int(raw, source)
    if isinstance(current, float):
        return _as_float(raw, source)
    return None if raw == "" else raw


def _apply_env(data: dict[str, Any], env: Mapping[str, str]) -> None:
    for raw_key, raw_value in sorted(env.items()):
        if not raw_key.startswith(ENV_PREFIX) or raw_key in ENV_RESERVED:
            continue
        parts = raw_key[len(ENV_PREFIX) :].lower().split(ENV_SEPARATOR)
        node: Any = data
        for part in parts[:-1]:
            if not isinstance(node, dict) or part not in node:
                raise ConfigError(f"{raw_key}: does not match any configuration key")
            node = node[part]
        leaf = parts[-1]
        if not isinstance(node, dict) or leaf not in node:
            raise ConfigError(f"{raw_key}: does not match any configuration key")
        node[leaf] = _coerce_like(node[leaf], raw_value, raw_key, leaf)


def _require(value: Any, kind: type | tuple[type, ...], path: str) -> Any:
    if isinstance(value, bool) and kind is not bool:
        raise ConfigError(f"{path}: expected {getattr(kind, '__name__', kind)}")
    if not isinstance(value, kind):
        raise ConfigError(f"{path}: expected {getattr(kind, '__name__', kind)}")
    return value


def _positive_number(value: Any, path: str) -> float:
    number = _require(value, (int, float), path)
    if number <= 0:
        raise ConfigError(f"{path}: must be greater than zero")
    return float(number)


def _positive_int(value: Any, path: str) -> int:
    number = _require(value, int, path)
    if number <= 0:
        raise ConfigError(f"{path}: must be greater than zero")
    return int(number)


def _optional_str(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return str(_require(value, str, path))


def _non_empty_str(value: Any, path: str) -> str:
    text = str(_require(value, str, path))
    if not text.strip():
        raise ConfigError(f"{path}: must not be empty")
    return text


def _algorithms(value: Any, path: str) -> tuple[Algorithm, ...]:
    """Parse a list of algorithm names, rejecting unknown ones at startup."""
    raw = _require(value, list, path)
    if not raw:
        raise ConfigError(f"{path}: must list at least one algorithm")
    parsed = []
    for entry in raw:
        try:
            parsed.append(parse_algorithm(entry))
        except ValueError as exc:
            raise ConfigError(f"{path}: {exc}") from None
    return tuple(parsed)


def _validate_batch_message(text: str, path: str) -> str:
    """Reject any placeholder that `str.format` will not be given a value for."""
    import string

    try:
        fields = {name for _, name, _, _ in string.Formatter().parse(text) if name is not None}
    except ValueError as exc:
        raise ConfigError(f"{path}: malformed placeholder ({exc})") from None
    unknown = fields - BATCH_MESSAGE_FIELDS
    if unknown:
        raise ConfigError(f"{path}: unknown placeholders {sorted(unknown)}")
    return text


def _build(data: dict[str, Any]) -> Config:
    server_port = _require(data["server"]["port"], int, "server.port")
    if not 1 <= server_port <= 65535:
        raise ConfigError("server.port: must be between 1 and 65535")

    # Resolved before the checks so each one can fall back to it.
    http_timeout = _positive_number(data["http"]["timeout"], "http.timeout")

    checks: dict[str, CheckConfig] = {}
    for name, raw in data["checks"].items():
        prefix = f"checks.{name}"
        on_error = _non_empty_str(raw["on_error"], f"{prefix}.on_error")
        if on_error not in ON_ERROR_POLICIES:
            raise ConfigError(f"{prefix}.on_error: must be one of {sorted(ON_ERROR_POLICIES)}")
        checks[name] = CheckConfig(
            enabled=bool(_require(raw["enabled"], bool, f"{prefix}.enabled")),
            # None means inherit; a number here is this backend's own timeout.
            timeout=(
                http_timeout
                if raw["timeout"] is None
                else _positive_number(raw["timeout"], f"{prefix}.timeout")
            ),
            on_error=on_error,
            algorithms=_algorithms(raw["algorithms"], f"{prefix}.algorithms"),
        )

    min_length = _require(data["policy"]["min_length"], int, "policy.min_length")
    if min_length < 0:
        raise ConfigError("policy.min_length: must not be negative")

    min_score = _require(data["strength"]["min_score"], int, "strength.min_score")
    if not 0 <= min_score <= 4:
        raise ConfigError("strength.min_score: must be between 0 and 4")
    strength_timeout = _positive_number(data["strength"]["timeout"], "strength.timeout")

    theme = _non_empty_str(data["ui"]["theme"], "ui.theme")
    if theme not in THEMES:
        raise ConfigError(f"ui.theme: must be one of {sorted(THEMES)}")

    level = _non_empty_str(data["logging"]["level"], "logging.level").upper()
    if level not in LOG_LEVELS:
        raise ConfigError(f"logging.level: must be one of {sorted(LOG_LEVELS)}")

    dl = data["denylist"]
    denylist = DenylistConfig(
        path=_optional_str(dl["path"], "denylist.path"),
        min_token_length=_positive_int(dl["min_token_length"], "denylist.min_token_length"),
        match_plaintext=bool(_require(dl["match_plaintext"], bool, "denylist.match_plaintext")),
        rules=tuple(
            _non_empty_str(r, "denylist.rules")
            for r in _require(dl["rules"], list, "denylist.rules")
        ),
        max_digests=_positive_int(dl["max_digests"], "denylist.max_digests"),
        cache_path=_optional_str(dl["cache_path"], "denylist.cache_path"),
    )

    # `path` is the single master switch for the denylist feature: with no path
    # configured, Denylist.load returns None and no DenylistChecker is ever
    # wired, so reporting `enabled: true` in /healthz and check responses would
    # be a lie. Reconcile here, once, rather than at every reporting site.
    if denylist.path is None and "denylist" in checks:
        checks["denylist"] = dataclasses.replace(checks["denylist"], enabled=False)

    return Config(
        server=ServerConfig(
            host=_non_empty_str(data["server"]["host"], "server.host"),
            port=server_port,
        ),
        proxy=ProxyConfig(
            http=_optional_str(data["proxy"]["http"], "proxy.http"),
            https=_optional_str(data["proxy"]["https"], "proxy.https"),
            no_proxy=_optional_str(data["proxy"]["no_proxy"], "proxy.no_proxy"),
        ),
        http=HttpConfig(
            timeout=http_timeout,
            verify_tls=bool(_require(data["http"]["verify_tls"], bool, "http.verify_tls")),
            user_agent=_non_empty_str(data["http"]["user_agent"], "http.user_agent"),
            ca_bundle=_optional_str(data["http"]["ca_bundle"], "http.ca_bundle"),
        ),
        checks=checks,
        policy=PolicyConfig(
            overall_deadline=_positive_number(
                data["policy"]["overall_deadline"], "policy.overall_deadline"
            ),
            min_length=min_length,
            rate_limit=RateLimitConfig(
                enabled=bool(
                    _require(
                        data["policy"]["rate_limit"]["enabled"],
                        bool,
                        "policy.rate_limit.enabled",
                    )
                ),
                requests=_positive_int(
                    data["policy"]["rate_limit"]["requests"], "policy.rate_limit.requests"
                ),
                per_seconds=_positive_int(
                    data["policy"]["rate_limit"]["per_seconds"],
                    "policy.rate_limit.per_seconds",
                ),
            ),
        ),
        strength=StrengthConfig(
            enabled=bool(_require(data["strength"]["enabled"], bool, "strength.enabled")),
            min_score=min_score,
            timeout=strength_timeout,
        ),
        docs=DocsConfig(
            enabled=bool(_require(data["docs"]["enabled"], bool, "docs.enabled")),
        ),
        ui=UiConfig(theme=theme),
        messages=MessagesConfig(
            **{
                key: (
                    _validate_batch_message(
                        _non_empty_str(value, f"messages.{key}"), f"messages.{key}"
                    )
                    if key == "batch_complete"
                    else _non_empty_str(value, f"messages.{key}")
                )
                for key, value in data["messages"].items()
            }
        ),
        logging=LoggingConfig(
            level=level,
            access_log=bool(_require(data["logging"]["access_log"], bool, "logging.access_log")),
        ),
        batch=BatchConfig(
            enabled=bool(_require(data["batch"]["enabled"], bool, "batch.enabled")),
            max_items=_positive_int(data["batch"]["max_items"], "batch.max_items"),
            max_concurrency=_positive_int(
                data["batch"]["max_concurrency"], "batch.max_concurrency"
            ),
            deadline=_positive_number(data["batch"]["deadline"], "batch.deadline"),
            max_label_length=_positive_int(
                data["batch"]["max_label_length"], "batch.max_label_length"
            ),
            rate_limit=BatchRateLimitConfig(
                enabled=bool(
                    _require(
                        data["batch"]["rate_limit"]["enabled"], bool, "batch.rate_limit.enabled"
                    )
                ),
                prefixes=_positive_int(
                    data["batch"]["rate_limit"]["prefixes"], "batch.rate_limit.prefixes"
                ),
                per_seconds=_positive_int(
                    data["batch"]["rate_limit"]["per_seconds"], "batch.rate_limit.per_seconds"
                ),
            ),
        ),
        cache=CacheConfig(
            enabled=bool(_require(data["cache"]["enabled"], bool, "cache.enabled")),
            max_entries=_positive_int(data["cache"]["max_entries"], "cache.max_entries"),
            ttl_seconds=_positive_number(data["cache"]["ttl_seconds"], "cache.ttl_seconds"),
        ),
        denylist=denylist,
        state=StateConfig(
            path=_optional_str(data["state"]["path"], "state.path"),
            busy_timeout=_positive_number(data["state"]["busy_timeout"], "state.busy_timeout"),
        ),
    )


def load_config(
    path: str | os.PathLike[str] | None = None,
    env: Mapping[str, str] | None = None,
) -> Config:
    """Load configuration from `path`, then apply `AMIWEAK_*` overrides from `env`.

    A `path` of None, or a path that does not exist, yields the built-in defaults.
    """
    env = os.environ if env is None else env
    raw: Any = None
    if path is not None and os.path.isfile(path):
        with open(path, encoding="utf-8") as handle:
            try:
                raw = yaml.safe_load(handle)
            except yaml.YAMLError as exc:
                reason = exc.__class__.__name__
                raise ConfigError(f"{path}: could not parse YAML ({reason})") from None
    data = _merge(DEFAULTS, raw)
    _apply_env(data, env)
    return _build(data)
