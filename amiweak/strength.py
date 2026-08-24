"""A persistent Node child process running the vendored zxcvbn-ts bundles.

Running the exact browser bundles under Node, instead of a Python
reimplementation, is what keeps the server and the page agreeing on a
password's score by construction rather than by coincidence.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from queue import Empty, Queue

from amiweak.checks.base import ERROR_INTERNAL, ERROR_TIMEOUT

_WORKER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "strength_worker.js")

#: Once a spawn attempt fails (e.g. `node` is not on PATH), wait this long
#: before trying again, so a sustained outage does not fork a process on
#: every single request.
_RESPAWN_BACKOFF_SECONDS = 5.0


@dataclass(frozen=True)
class ScoreResult:
    """Exactly one of `score` and `error` is set, same convention as `RangeFetch`."""

    score: int | None
    error: str | None


class StrengthScorer:
    """One `node strength_worker.js` child, one round trip in flight at a time.

    The child is started lazily on the first call to `score()`, not in
    `__init__` -- constructing an app that never ends up calling
    `/api/v1/check` (most of the test suite, `/healthz`, `/metrics`, the
    static page) must not fork a process nobody is going to use.

    Reads happen on a background thread feeding a queue, which is the
    portable way to get a read timeout on a pipe on both Windows and Linux --
    `select()` on a pipe does not work on Windows.
    """

    def __init__(
        self, timeout: float, node_path: str = "node", worker_script: str = _WORKER_SCRIPT
    ) -> None:
        self._timeout = timeout
        self._node_path = node_path
        self._worker_script = worker_script
        self._lock = threading.Lock()
        self._process: subprocess.Popen[str] | None = None
        self._out_queue: Queue[str] = Queue()
        self._stderr_lines: deque[str] = deque(maxlen=50)
        self._last_spawn_failure: float | None = None

    def score(self, password: str) -> ScoreResult:
        with self._lock:
            if not self._ensure_running():
                return ScoreResult(None, ERROR_INTERNAL)
            process = self._process
            assert process is not None and process.stdin is not None
            try:
                process.stdin.write(json.dumps({"password": password}) + "\n")
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                self._kill()
                return ScoreResult(None, ERROR_INTERNAL)

            try:
                line = self._out_queue.get(timeout=self._timeout)
            except Empty:
                # Presumed stuck: kill it so a fresh process is spawned next
                # time, and so the reader thread's blocking read unblocks.
                # Also start the same backoff a spawn failure gets: a worker
                # that is merely too slow to answer (cold start, load, a
                # slow filesystem) would otherwise be killed and respawned
                # on every single call, paying the cold-start cost and
                # timing out again -- forever, with no damping.
                self._kill()
                self._last_spawn_failure = time.monotonic()
                return ScoreResult(None, ERROR_TIMEOUT)

        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return ScoreResult(None, ERROR_INTERNAL)
        if "score" in payload:
            return ScoreResult(int(payload["score"]), None)
        return ScoreResult(None, ERROR_INTERNAL)

    def _ensure_running(self) -> bool:
        if self._process is not None and self._process.poll() is None:
            return True
        now = time.monotonic()
        if (
            self._last_spawn_failure is not None
            and now - self._last_spawn_failure < _RESPAWN_BACKOFF_SECONDS
        ):
            return False
        try:
            process = subprocess.Popen(
                [self._node_path, self._worker_script],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError:
            self._last_spawn_failure = now
            return False
        self._process = process
        # Fresh queue: a stale response left behind by a killed process must
        # never be handed to the next caller as if it were theirs.
        self._out_queue = Queue()
        threading.Thread(
            target=self._read_stdout, args=(process, self._out_queue), daemon=True
        ).start()
        threading.Thread(target=self._read_stderr, args=(process,), daemon=True).start()
        return True

    def _read_stdout(self, process: subprocess.Popen[str], queue: Queue[str]) -> None:
        assert process.stdout is not None
        for line in process.stdout:
            queue.put(line)

    def _read_stderr(self, process: subprocess.Popen[str]) -> None:
        assert process.stderr is not None
        for line in process.stderr:
            self._stderr_lines.append(line.rstrip("\n"))

    def _kill(self) -> None:
        if self._process is not None:
            self._process.kill()
            self._process.wait()
            self._process = None

    def debug_stderr(self) -> list[str]:
        """The worker's last few stderr lines, for the no-leak test and crash diagnostics."""
        return list(self._stderr_lines)

    def close(self) -> None:
        with self._lock:
            self._kill()
