"""Dynamic verification tests (small, fast measurements)."""

from __future__ import annotations

import pytest

from debian_redos.analyzers.heuristics import analyze
from debian_redos.dynamic import verifier
from debian_redos.dynamic.verifier import (
    VerificationSettings,
    _confirm,
    _run_plan,
    verify_candidate,
)
from debian_redos.models import DynamicStatus, Trial
from debian_redos.workers.runner import WorkerPool, WorkerSession, detect_engine, php_delimited

from helpers import make_candidate


def _settings(config):
    settings = VerificationSettings.from_config(config)
    # Keep the last step well above the 5 ms absolute-time gate in _confirm:
    # on a fast runner an 18-character attack string finishes in 2-3 ms, so
    # the confirmation becomes a coin flip.  At 24 characters the same pattern
    # takes hundreds of milliseconds on every CPython from 3.9 to 3.13.
    settings.exponential_sizes = [16, 18, 20, 22, 24]
    settings.polynomial_sizes = [32, 64, 128]
    settings.timeout_s = 1.5
    settings.budget_s = 5.0
    settings.stability_reruns = 0
    return settings


@pytest.mark.slow
def test_python_engine_confirms_nested_quantifier(config):
    candidate = make_candidate(pattern=r"^(a+)+$", input_control="user_network")
    analysis = verify_candidate(candidate, candidate.static,
                                WorkerPool(config), _settings(config))
    assert analysis.status == DynamicStatus.CONFIRMED.value
    assert analysis.growth_class == "exponential"
    assert analysis.engine == "python-re"
    assert analysis.max_elapsed_ms and analysis.max_elapsed_ms >= 5.0
    assert len([t for t in analysis.trials if t.status == "completed"]) >= 2


@pytest.mark.slow
def test_python_engine_does_not_confirm_linear(config):
    candidate = make_candidate(pattern=r"^[a-z]+$", input_control="user_network")
    analysis = verify_candidate(candidate, candidate.static,
                                WorkerPool(config), _settings(config))
    # no attack plans -> skipped, never "confirmed"
    assert analysis.status in (DynamicStatus.SKIPPED.value,
                               DynamicStatus.NOT_CONFIRMED.value)


def test_unresolved_pattern_is_skipped(config):
    analysis = analyze(None)
    candidate = make_candidate(pattern=None)
    candidate.static = analysis
    result = verify_candidate(candidate, analysis, WorkerPool(config),
                              _settings(config))
    assert result.status == DynamicStatus.SKIPPED.value


def test_single_timeout_is_never_enough():
    settings = VerificationSettings()
    timeout = Trial(input_length=40, elapsed_ms=2000.0, status="timeout")
    confirmed, reason = _confirm("timeout", [], [timeout], [], 0.0, settings,
                                 verifier._RunOutcome())
    assert confirmed is False
    assert "single timeout" in reason


def test_timeout_after_slow_point_is_confirmed():
    settings = VerificationSettings()
    timeout = Trial(input_length=40, elapsed_ms=2000.0, status="timeout")
    confirmed, _ = _confirm("timeout", [(30, 120.0)], [timeout], [5.0], 120.0,
                            settings, verifier._RunOutcome())
    assert confirmed is True


def test_exponential_requires_absolute_time():
    settings = VerificationSettings()
    confirmed, reason = _confirm("exponential", [(10, 0.1), (20, 1.0)], [], [3.3],
                                 1.0, settings, verifier._RunOutcome())
    assert confirmed is False
    assert "too small" in reason


@pytest.mark.slow
def test_worker_session_protocol():
    engine = detect_engine("python")
    assert engine is not None
    session = WorkerSession(engine, timeout=3.0, memory_mb=256)
    session.start()
    try:
        response = session.request({"pattern": "a+b", "text": "aaab"})
        assert response["status"] == "completed"
        assert response["elapsed_ms"] >= 0
        response = session.request({"pattern": "a+b", "text": "ccc"})
        assert response["status"] == "completed"
    finally:
        session.close()


def test_php_delimited_chooses_safe_delimiter():
    assert php_delimited("a/b") == "\x01a/b\x01"
    assert php_delimited("a", "i").endswith("i")


def test_robust_tail_ignores_one_noisy_point():
    # A clean quadratic curve whose last measurement was throttled.
    assert verifier._robust_tail([2.16, 1.71, 1.92, 2.00, 1.02]) == pytest.approx(1.92)
    # A genuinely linear curve stays linear even with a small bump.
    assert verifier._robust_tail([1.0, 1.0, 1.0, 1.2]) == pytest.approx(1.0)
    # Exponential growth is preserved.
    assert verifier._robust_tail([9.39, 10.68, 11.49, 13.06, 17.22]) == pytest.approx(13.06)


def test_duplicate_size_takes_fastest_measurement():
    trial = lambda n, ms, s="completed": Trial(input_length=n, elapsed_ms=ms,
                                               status=s)
    points = verifier._aggregate_trials([
        trial(32, 0.5), trial(32, 0.2),
        trial(64, 9.0), trial(64, 4.0),
        trial(128, 40.0),
        trial(160, 1.0, "timeout"),
    ])
    assert points == [(32, 0.2), (64, 4.0), (128, 40.0)]
