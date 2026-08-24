"""Where cross-cutting counters and rate-limit buckets live.

Two implementations satisfy one protocol. `MemoryStore` holds everything in
process dicts and is what a single-process deployment wants. `SqliteStore`
holds the same data in a WAL-mode database several gunicorn workers open at
once, so the numbers and the allowances are shared rather than duplicated per
worker.

Nothing user-supplied becomes a key here. Counter labels are fixed verdict and
backend names; bucket keys are client addresses. `tests/test_no_leak.py`
enforces that rather than trusting it.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Protocol

from filelock import FileLock, Timeout

from amiweak.config import StateConfig

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StoreSnapshot:
    """Everything /metrics and /healthz read, in one round trip."""

    counters: dict[str, dict[str, int]] = field(default_factory=dict)
    latency: dict[str, dict[str, float]] = field(default_factory=dict)
    health: dict[str, dict[str, str | None]] = field(default_factory=dict)


class StateStore(Protocol):
    def incr(self, name: str, label: str, amount: int) -> None: ...
    def observe(self, name: str, seconds: float) -> None: ...
    def set_health(self, name: str, last_ok: str | None, last_error: str | None) -> None: ...
    def spend(
        self, key: str, cost: float, capacity: float, refill_rate: float, now: float
    ) -> bool: ...
    def evict_buckets(self, namespace: str, cutoff: float) -> None: ...
    def snapshot(self) -> StoreSnapshot: ...
    def close(self) -> None: ...


class MemoryStore:
    """Per-process state. Exactly the behaviour this application had before."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, dict[str, int]] = defaultdict(dict)
        self._latency: dict[str, dict[str, float]] = {}
        self._health: dict[str, dict[str, str | None]] = {}
        self._buckets: dict[str, tuple[float, float]] = {}

    def incr(self, name: str, label: str, amount: int) -> None:
        with self._lock:
            bucket = self._counters[name]
            bucket[label] = bucket.get(label, 0) + amount

    def observe(self, name: str, seconds: float) -> None:
        with self._lock:
            entry = self._latency.setdefault(name, {"count": 0.0, "sum": 0.0, "max": 0.0})
            entry["count"] += 1
            entry["sum"] += seconds
            entry["max"] = max(entry["max"], seconds)

    def set_health(self, name: str, last_ok: str | None, last_error: str | None) -> None:
        with self._lock:
            self._health[name] = {"last_ok": last_ok, "last_error": last_error}

    def spend(self, key: str, cost: float, capacity: float, refill_rate: float, now: float) -> bool:
        with self._lock:
            tokens, last_seen = self._buckets.get(key, (capacity, now))
            tokens = min(capacity, tokens + (now - last_seen) * refill_rate)
            if tokens < cost:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - cost, now)
            return True

    def evict_buckets(self, namespace: str, cutoff: float) -> None:
        with self._lock:
            if len(self._buckets) < 1024:
                return
            prefix = f"{namespace}:"
            stale = [
                k
                for k, (_, seen) in self._buckets.items()
                if k.startswith(prefix) and seen < cutoff
            ]
            for key in stale:
                del self._buckets[key]

    def snapshot(self) -> StoreSnapshot:
        with self._lock:
            return StoreSnapshot(
                counters={name: dict(v) for name, v in self._counters.items()},
                latency={name: dict(v) for name, v in self._latency.items()},
                health={name: dict(v) for name, v in self._health.items()},
            )

    def close(self) -> None:
        """Nothing to release. Present so callers need not care which store they hold."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS counters (
    name  TEXT NOT NULL,
    label TEXT NOT NULL,
    value INTEGER NOT NULL,
    PRIMARY KEY (name, label)
);
CREATE TABLE IF NOT EXISTS latency (
    name  TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    sum   REAL NOT NULL,
    max   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS health (
    name       TEXT PRIMARY KEY,
    last_ok    TEXT,
    last_error TEXT
);
CREATE TABLE IF NOT EXISTS buckets (
    key       TEXT PRIMARY KEY,
    tokens    REAL NOT NULL,
    last_seen REAL NOT NULL
);
"""

SCHEMA_LOCK_TIMEOUT = 10.0


class SqliteStore:
    """State shared by every worker opening the same file.

    WAL mode so readers never block the writer: a /metrics scrape must not
    contend with a request spending a token. `synchronous=NORMAL` because
    losing the last few counter increments to a power cut is not a real cost,
    and fsync-per-increment would be.

    One connection per thread, since sqlite3 connections are not thread-safe
    and the shipped deployment is gthread. SQLite's own locking coordinates
    between them and between processes; that is the part we are not writing.
    """

    def __init__(self, path: str, busy_timeout: float) -> None:
        self._path = path
        self._busy_timeout = busy_timeout
        self._local = threading.local()
        self._create_schema()

    def _create_schema(self) -> None:
        """Guarded by a file lock so simultaneously booting workers cannot race."""
        parent = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(parent, exist_ok=True)
        lock = FileLock(f"{self._path}.lock", timeout=SCHEMA_LOCK_TIMEOUT)
        try:
            with lock:
                conn = self._connect()
                with conn:
                    conn.executescript(SCHEMA)
        except Timeout:
            raise RuntimeError(
                f"state: timed out acquiring the schema lock {self._path}.lock"
            ) from None

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._path,
            timeout=self._busy_timeout,
            isolation_level=None,  # explicit transactions only
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(f"PRAGMA busy_timeout={int(self._busy_timeout * 1000)}")
        return conn

    @property
    def _conn(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    def incr(self, name: str, label: str, amount: int) -> None:
        self._conn.execute(
            "INSERT INTO counters (name, label, value) VALUES (?, ?, ?) "
            "ON CONFLICT (name, label) DO UPDATE SET value = value + excluded.value",
            (name, label, amount),
        )

    def observe(self, name: str, seconds: float) -> None:
        self._conn.execute(
            "INSERT INTO latency (name, count, sum, max) VALUES (?, 1, ?, ?) "
            "ON CONFLICT (name) DO UPDATE SET "
            "  count = count + 1, "
            "  sum   = sum + excluded.sum, "
            "  max   = MAX(max, excluded.max)",
            (name, seconds, seconds),
        )

    def set_health(self, name: str, last_ok: str | None, last_error: str | None) -> None:
        self._conn.execute(
            "INSERT INTO health (name, last_ok, last_error) VALUES (?, ?, ?) "
            "ON CONFLICT (name) DO UPDATE SET "
            "  last_ok = excluded.last_ok, last_error = excluded.last_error",
            (name, last_ok, last_error),
        )

    def spend(self, key: str, cost: float, capacity: float, refill_rate: float, now: float) -> bool:
        """Read-modify-write under the writer lock.

        BEGIN IMMEDIATE takes the write lock at statement one rather than at
        the first write, so two workers cannot both read the last token and
        both conclude they may spend it.
        """
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT tokens, last_seen FROM buckets WHERE key = ?", (key,)
            ).fetchone()
            tokens, last_seen = row if row is not None else (capacity, now)
            tokens = min(capacity, tokens + (now - last_seen) * refill_rate)
            allowed = tokens >= cost
            if allowed:
                tokens -= cost
            conn.execute(
                "INSERT INTO buckets (key, tokens, last_seen) VALUES (?, ?, ?) "
                "ON CONFLICT (key) DO UPDATE SET tokens = excluded.tokens, "
                "  last_seen = excluded.last_seen",
                (key, tokens, now),
            )
            conn.execute("COMMIT")
            return allowed
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def evict_buckets(self, namespace: str, cutoff: float) -> None:
        """Delete stale buckets belonging to `namespace` only.

        The LIKE pattern is built from `namespace`, never from user input --
        callers only ever pass one of a small set of fixed literals such as
        `"policy"` or `"batch"`, none of which contain `%` or `_`. Written
        with a LIKE match (rather than a substr/instr check) because it can
        use the `key` primary key index; documented here since nothing
        escapes the pattern.
        """
        self._conn.execute(
            "DELETE FROM buckets WHERE key LIKE ? AND last_seen < ?",
            (f"{namespace}:%", cutoff),
        )

    def snapshot(self) -> StoreSnapshot:
        conn = self._conn
        counters: dict[str, dict[str, int]] = defaultdict(dict)
        for name, label, value in conn.execute("SELECT name, label, value FROM counters"):
            counters[name][label] = value
        latency = {
            name: {"count": float(count), "sum": total, "max": peak}
            for name, count, total, peak in conn.execute(
                "SELECT name, count, sum, max FROM latency"
            )
        }
        health: dict[str, dict[str, str | None]] = {
            name: {"last_ok": last_ok, "last_error": last_error}
            for name, last_ok, last_error in conn.execute(
                "SELECT name, last_ok, last_error FROM health"
            )
        }
        return StoreSnapshot(counters=dict(counters), latency=latency, health=health)

    def close(self) -> None:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


STORE_ERRORS = "store_errors_total"


class ResilientStore:
    """A store that degrades to per-process state instead of failing a request.

    A metric is not worth a 500, and neither is a rate-limit decision. When the
    primary raises, the operation is retried against an in-process fallback and
    the failure is counted. The degraded state is exactly the behaviour this
    application had before the primary existed.

    Log messages here name the operation, never its arguments. A bucket key is
    a client address and a counter label is a fixed name, but the rule is that
    nothing reaches a log line that did not have to.
    """

    def __init__(self, primary: StateStore, fallback: StateStore) -> None:
        self._primary = primary
        self._fallback = fallback

    def _note(self, operation: str, exc: BaseException) -> None:
        self._fallback.incr(STORE_ERRORS, "", 1)
        logger.warning(
            "state store %s failed (%s); using per-process state",
            operation,
            type(exc).__name__,
        )

    def incr(self, name: str, label: str, amount: int) -> None:
        try:
            self._primary.incr(name, label, amount)
        except (sqlite3.Error, OSError) as exc:
            self._note("incr", exc)
            self._fallback.incr(name, label, amount)

    def observe(self, name: str, seconds: float) -> None:
        try:
            self._primary.observe(name, seconds)
        except (sqlite3.Error, OSError) as exc:
            self._note("observe", exc)
            self._fallback.observe(name, seconds)

    def set_health(self, name: str, last_ok: str | None, last_error: str | None) -> None:
        try:
            self._primary.set_health(name, last_ok, last_error)
        except (sqlite3.Error, OSError) as exc:
            self._note("set_health", exc)
            self._fallback.set_health(name, last_ok, last_error)

    def spend(self, key: str, cost: float, capacity: float, refill_rate: float, now: float) -> bool:
        try:
            return self._primary.spend(key, cost, capacity, refill_rate, now)
        except (sqlite3.Error, OSError) as exc:
            self._note("spend", exc)
            return self._fallback.spend(key, cost, capacity, refill_rate, now)

    def evict_buckets(self, namespace: str, cutoff: float) -> None:
        try:
            self._primary.evict_buckets(namespace, cutoff)
        except (sqlite3.Error, OSError) as exc:
            self._note("evict_buckets", exc)
            self._fallback.evict_buckets(namespace, cutoff)

    def snapshot(self) -> StoreSnapshot:
        """Merge both views, so counters recorded while degraded still appear."""
        try:
            primary = self._primary.snapshot()
        except (sqlite3.Error, OSError) as exc:
            self._note("snapshot", exc)
            primary = StoreSnapshot()
        fallback = self._fallback.snapshot()

        counters: dict[str, dict[str, int]] = {
            name: dict(labels) for name, labels in primary.counters.items()
        }
        for name, labels in fallback.counters.items():
            target = counters.setdefault(name, {})
            for label, value in labels.items():
                target[label] = target.get(label, 0) + value

        latency = {name: dict(v) for name, v in primary.latency.items()}
        for name, entry in fallback.latency.items():
            existing = latency.setdefault(name, {"count": 0.0, "sum": 0.0, "max": 0.0})
            existing["count"] += entry["count"]
            existing["sum"] += entry["sum"]
            existing["max"] = max(existing["max"], entry["max"])

        # A primary entry for a backend means the store has since recorded
        # something for it -- possibly after recovering from an earlier
        # blip -- so it is preferred over whatever the fallback holds.
        # Fallback only wins when the primary has never recorded that
        # backend at all, e.g. every write for it happened during an
        # outage.
        health = {name: dict(v) for name, v in primary.health.items()}
        for name, state in fallback.health.items():
            if name not in health:
                health[name] = dict(state)

        return StoreSnapshot(counters=counters, latency=latency, health=health)

    def close(self) -> None:
        for store in (self._primary, self._fallback):
            try:
                store.close()
            except (sqlite3.Error, OSError) as exc:
                logger.warning("state store close failed (%s)", type(exc).__name__)


def build_store(config: StateConfig) -> StateStore:
    """Pick an implementation.

    `path: null` is the default and yields exactly the behaviour this
    application had before a store existed. That matters for upgrades, and it
    matters for `run.py`, which is a single process — there is nothing to share
    there, so a database file would be pure overhead.
    """
    if config.path is None:
        return MemoryStore()
    return ResilientStore(
        SqliteStore(config.path, busy_timeout=config.busy_timeout),
        MemoryStore(),
    )
