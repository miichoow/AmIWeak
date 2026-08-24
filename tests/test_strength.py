import os
import time

from amiweak.strength import ScoreResult, StrengthScorer


def test_scores_a_known_weak_password():
    scorer = StrengthScorer(timeout=5.0)
    try:
        assert scorer.score("password") == ScoreResult(0, None)
    finally:
        scorer.close()


def test_scores_a_known_strong_password():
    scorer = StrengthScorer(timeout=5.0)
    try:
        assert scorer.score("Xk9-f3a7c1b2e4d6") == ScoreResult(4, None)
    finally:
        scorer.close()


def test_the_process_is_not_spawned_until_the_first_call():
    scorer = StrengthScorer(timeout=5.0)
    try:
        assert scorer._process is None
        scorer.score("password")
        assert scorer._process is not None
    finally:
        scorer.close()


def test_the_process_is_reused_across_calls():
    scorer = StrengthScorer(timeout=5.0)
    try:
        scorer.score("password")
        first = scorer._process
        scorer.score("password")
        assert scorer._process is first
    finally:
        scorer.close()


def test_close_terminates_the_process():
    scorer = StrengthScorer(timeout=5.0)
    scorer.score("password")
    process = scorer._process
    scorer.close()
    assert process.poll() is not None


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
HANG_WORKER = os.path.join(FIXTURES, "hang_worker.js")


def test_a_hanging_worker_times_out_quickly():
    scorer = StrengthScorer(timeout=0.3, worker_script=HANG_WORKER)
    try:
        started = time.monotonic()
        result = scorer.score("password")
        elapsed = time.monotonic() - started
        assert result == ScoreResult(None, "timeout")
        assert elapsed < 1.0
    finally:
        scorer.close()


def test_a_timed_out_worker_is_killed_so_it_can_be_respawned():
    scorer = StrengthScorer(timeout=0.3, worker_script=HANG_WORKER)
    try:
        scorer.score("password")
        assert scorer._process is None or scorer._process.poll() is not None
    finally:
        scorer.close()


def test_a_dead_process_is_respawned_on_the_next_call():
    scorer = StrengthScorer(timeout=5.0)
    try:
        scorer.score("password")
        scorer._process.kill()
        scorer._process.wait()
        assert scorer.score("password") == ScoreResult(0, None)
    finally:
        scorer.close()


def test_spawn_failure_returns_an_error():
    scorer = StrengthScorer(timeout=1.0, node_path="this-binary-does-not-exist-anywhere")
    try:
        assert scorer.score("password") == ScoreResult(None, "internal")
    finally:
        scorer.close()


def test_spawn_failure_backs_off_instead_of_retrying_every_call(monkeypatch):
    import amiweak.strength as strength_module

    calls = []
    real_popen = strength_module.subprocess.Popen

    def counting_popen(*args, **kwargs):
        calls.append(1)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(strength_module.subprocess, "Popen", counting_popen)
    scorer = StrengthScorer(timeout=1.0, node_path="this-binary-does-not-exist-anywhere")
    try:
        scorer.score("password")
        scorer.score("password")
        assert len(calls) == 1
    finally:
        scorer.close()


def test_a_timeout_backs_off_instead_of_respawning_every_call(monkeypatch):
    import amiweak.strength as strength_module

    calls = []
    real_popen = strength_module.subprocess.Popen

    def counting_popen(*args, **kwargs):
        calls.append(1)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(strength_module.subprocess, "Popen", counting_popen)
    scorer = StrengthScorer(timeout=0.3, worker_script=HANG_WORKER)
    try:
        first = scorer.score("password")
        assert first == ScoreResult(None, "timeout")
        second = scorer.score("password")
        assert second == ScoreResult(None, "internal")
        assert len(calls) == 1
    finally:
        scorer.close()


def test_debug_stderr_starts_empty():
    scorer = StrengthScorer(timeout=5.0)
    try:
        assert scorer.debug_stderr() == []
    finally:
        scorer.close()


BAD_JSON_WORKER = os.path.join(FIXTURES, "bad_json_worker.js")
NO_SCORE_WORKER = os.path.join(FIXTURES, "no_score_worker.js")
STDERR_WORKER = os.path.join(FIXTURES, "stderr_worker.js")


def test_a_broken_pipe_on_write_is_an_internal_error(monkeypatch):
    scorer = StrengthScorer(timeout=5.0)
    try:
        scorer.score("password")  # spawns the process
        process = scorer._process

        def raise_broken_pipe(*args, **kwargs):
            raise BrokenPipeError()

        monkeypatch.setattr(process.stdin, "write", raise_broken_pipe)
        result = scorer.score("password")
        assert result == ScoreResult(None, "internal")
        assert scorer._process is None
    finally:
        scorer.close()


def test_a_non_json_response_is_an_internal_error():
    scorer = StrengthScorer(timeout=5.0, worker_script=BAD_JSON_WORKER)
    try:
        assert scorer.score("password") == ScoreResult(None, "internal")
    finally:
        scorer.close()


def test_a_response_with_no_score_key_is_an_internal_error():
    scorer = StrengthScorer(timeout=5.0, worker_script=NO_SCORE_WORKER)
    try:
        assert scorer.score("password") == ScoreResult(None, "internal")
    finally:
        scorer.close()


def test_worker_stderr_output_is_captured():
    scorer = StrengthScorer(timeout=5.0, worker_script=STDERR_WORKER)
    try:
        scorer.score("password")
        for _ in range(50):
            if scorer.debug_stderr():
                break
            time.sleep(0.05)
        assert "worker starting" in scorer.debug_stderr()
    finally:
        scorer.close()
