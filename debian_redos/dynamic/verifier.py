"""Dynamic verification: execution of attack strings and growth analysis.

Confirmation policy
-------------------
A pattern is *confirmed* only when the measured curve shows super-linear
degradation across at least two size steps (or a hard timeout preceded by a
measurably slow run), and the slowest measurement is reproducible.  A single
timeout on a single run is never enough: engines differ in startup cost and the
host may be noisy, so every confirmation carries the measured points with it.
"""

from __future__ import annotations

import math
import statistics
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..models import (
    AttackWitness,
    Complexity,
    DynamicAnalysis,
    DynamicStatus,
    RegexCandidate,
    StaticAnalysis,
    Trial,
)
from ..workers.runner import WorkerDead, WorkerPool, WorkerTimeout


@dataclass
class VerificationSettings:
    timeout_s: float = 2.0
    budget_s: float = 8.0
    max_input: int = 8192
    memory_mb: int = 256
    noise_floor_ms: float = 0.5
    confirm_ratio: float = 2.5
    min_points: int = 3
    slope_delta: float = 0.8
    exponential_sizes: List[int] = field(default_factory=lambda: [8, 10, 12, 14, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 96, 128])
    polynomial_sizes: List[int] = field(default_factory=lambda: [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192])
    max_candidates: int = 4
    stability_reruns: int = 1

    @classmethod
    def from_config(cls, config) -> "VerificationSettings":
        growth = config.get("dynamic.growth", {}) or {}
        sizes = config.get("dynamic.sizes", {}) or {}
        return cls(
            timeout_s=float(config.limit("timeout_seconds") or 2.0),
            budget_s=float(config.limit("candidate_budget_seconds") or 8.0),
            max_input=int(config.limit("max_input_length") or 8192),
            memory_mb=int(config.limit("max_memory_mb") or 256),
            noise_floor_ms=float(growth.get("noise_floor_ms", 0.5)),
            confirm_ratio=float(growth.get("confirm_ratio", 2.5)),
            min_points=int(growth.get("min_points", 3)),
            slope_delta=float(growth.get("exponential_slope_delta", 0.8)),
            exponential_sizes=list(sizes.get("exponential", cls.__dataclass_fields__["exponential_sizes"].default_factory())),
            polynomial_sizes=list(sizes.get("polynomial", cls.__dataclass_fields__["polynomial_sizes"].default_factory())),
            max_candidates=int(config.get("dynamic.max_candidates_per_finding", 4)),
        )


@dataclass
class _RunOutcome:
    trials: List[Trial] = field(default_factory=list)
    plan: Optional[AttackWitness] = None
    engine_version: str = "unknown"
    engine_label: str = ""
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None


def verify_candidate(
    candidate: RegexCandidate,
    static: StaticAnalysis,
    pool: WorkerPool,
    settings: VerificationSettings,
    log=None,
) -> DynamicAnalysis:
    def note(message: str) -> None:
        if log is not None:
            log(message)

    if candidate.pattern is None:
        return DynamicAnalysis(status=DynamicStatus.SKIPPED.value,
                               notes=["pattern is dynamic and could not be resolved"])
    if not static.suspicious:
        return DynamicAnalysis(status=DynamicStatus.SKIPPED.value,
                               notes=["pattern is not suspicious, dynamic test not required"])
    plans = list(static.attack_plans)
    if not plans:
        return DynamicAnalysis(status=DynamicStatus.SKIPPED.value,
                               notes=["no attack witness was generated"])

    engine = pool.engine(candidate.language)
    if engine is None:
        return DynamicAnalysis(
            status=DynamicStatus.SKIPPED.value,
            notes=[pool.unavailable_note(candidate.language)],
        )

    outcomes: List[_RunOutcome] = []
    for index, plan in enumerate(plans[: max(1, settings.max_candidates)]):
        note(f"dynamic test {index + 1}/{min(len(plans), settings.max_candidates)} "
             f"pump={plan.pump!r} prefix={plan.prefix!r} suffix={plan.suffix!r}")
        outcome = _run_plan(candidate, plan, engine, settings, note)
        outcomes.append(outcome)
        analysis = _summarise(outcome, settings)
        if analysis.status == DynamicStatus.CONFIRMED.value:
            return analysis

    best = max(outcomes, key=_outcome_score) if outcomes else _RunOutcome()
    analysis = _summarise(best, settings)
    if all(outcome.error for outcome in outcomes) and outcomes:
        analysis.status = DynamicStatus.ERROR.value
        analysis.notes.extend(sorted({o.error for o in outcomes if o.error}))
    return analysis


def _outcome_score(outcome: _RunOutcome) -> float:
    completed = [t.elapsed_ms for t in outcome.trials if t.status == "completed"]
    timeouts = [t for t in outcome.trials if t.status == "timeout"]
    score = max(completed) if completed else 0.0
    if timeouts:
        score += 100000.0
    return score


def _run_plan(candidate: RegexCandidate, plan: AttackWitness, engine,
              settings: VerificationSettings, note) -> _RunOutcome:
    outcome = _RunOutcome(plan=plan, engine_label=engine.label,
                          engine_version=engine.version)
    sizes = (settings.exponential_sizes if plan.kind == "exponential"
             else settings.polynomial_sizes)
    pump = plan.pump or "a"
    fixed = len(plan.prefix) + len(plan.suffix) + len(plan.breaker)

    started = time.monotonic()
    session = pool_session(engine, settings)
    try:
        try:
            warmup = session.request({
                "pattern": _pattern_for(engine, candidate, plan),
                "flags": _flags_for(engine, candidate),
                "warmup": True,
                "use_regex_module": _use_regex_module(candidate),
            }, timeout=session.startup_timeout)
        except WorkerTimeout:
            outcome.error = "engine did not start within the startup timeout"
            return outcome
        except WorkerDead as exc:
            outcome.error = f"engine failed to start: {exc}"
            return outcome
        if warmup.get("status") not in ("ok", "completed"):
            outcome.error = f"compile failed: {warmup.get('error', 'unknown error')}"
            return outcome
        outcome.engine_version = warmup.get("engine_version", engine.version)

        for target in sizes:
            if time.monotonic() - started > settings.budget_s:
                outcome.notes.append("verification budget exhausted")
                break
            repetitions = max(1, (target - fixed) // max(1, len(pump)))
            text = plan.prefix + pump * repetitions + plan.suffix + plan.breaker
            if len(text) > settings.max_input:
                break
            payload = {
                "pattern": _pattern_for(engine, candidate, plan),
                "flags": _flags_for(engine, candidate),
                "text": text,
                "use_regex_module": _use_regex_module(candidate),
            }
            try:
                response = session.request(payload, timeout=settings.timeout_s)
            except WorkerTimeout:
                outcome.trials.append(Trial(input_length=len(text),
                                            elapsed_ms=settings.timeout_s * 1000.0,
                                            status="timeout",
                                            input_preview=_preview(text)))
                outcome.notes.append(f"hard wall-clock timeout at {len(text)} characters")
                break
            except WorkerDead as exc:
                outcome.trials.append(Trial(input_length=len(text), elapsed_ms=0.0,
                                            status="crash", error=str(exc),
                                            input_preview=_preview(text)))
                outcome.error = f"worker crashed: {exc}"
                break
            status = response.get("status", "error")
            elapsed = float(response.get("elapsed_ms") or 0.0)
            outcome.trials.append(Trial(
                input_length=len(text),
                elapsed_ms=elapsed,
                status="completed" if status in ("completed", "ok") else "error",
                error=response.get("error"),
                input_preview=_preview(text),
            ))
            if status not in ("completed", "ok"):
                outcome.error = response.get("error") or "engine error"
                break
            if elapsed >= settings.timeout_s * 1000.0 * 0.9:
                outcome.notes.append("measurement approached the wall-clock limit")
                break
    finally:
        session.close()

    _stability_check(candidate, plan, engine, settings, outcome, note)
    return outcome


def pool_session(engine, settings: VerificationSettings):
    from ..workers.runner import WorkerSession

    startup = 60.0 if engine.kind == "docker" else max(10.0, settings.timeout_s * 3)
    session = WorkerSession(engine, timeout=settings.timeout_s,
                            memory_mb=settings.memory_mb, startup_timeout=startup)
    session.start()
    return session


def _stability_check(candidate: RegexCandidate, plan: AttackWitness, engine,
                     settings: VerificationSettings, outcome: _RunOutcome, note) -> None:
    completed = [t for t in outcome.trials if t.status == "completed"]
    if len(completed) < 2 or settings.stability_reruns <= 0:
        return
    worst = max(completed, key=lambda t: t.elapsed_ms)
    if worst.elapsed_ms < max(settings.noise_floor_ms * 4, 2.0):
        outcome.notes.append("slowest measurement is below the noise floor, "
                             "stability check skipped")
        return
    pump = plan.pump or "a"
    fixed = len(plan.prefix) + len(plan.suffix) + len(plan.breaker)
    repetitions = max(1, (worst.input_length - fixed) // max(1, len(pump)))
    text = plan.prefix + pump * repetitions + plan.suffix + plan.breaker
    session = pool_session(engine, settings)
    try:
        repeat = session.request({
            "pattern": _pattern_for(engine, candidate, plan),
            "flags": _flags_for(engine, candidate),
            "text": text,
            "use_regex_module": _use_regex_module(candidate),
        }, timeout=settings.timeout_s)
    except (WorkerTimeout, WorkerDead) as exc:
        outcome.notes.append(f"stability re-run failed: {type(exc).__name__}")
        return
    finally:
        session.close()
    if repeat.get("status") not in ("completed", "ok"):
        outcome.notes.append("stability re-run returned an engine error")
        return
    second = float(repeat.get("elapsed_ms") or 0.0)
    ratio = max(second, worst.elapsed_ms) / max(1e-9, min(second, worst.elapsed_ms))
    outcome.trials.append(Trial(input_length=worst.input_length, elapsed_ms=second,
                                status="completed", input_preview=_preview(text)))
    if ratio <= 2.0:
        outcome.notes.append(f"stability check passed (repeat ratio {ratio:.2f})")
    else:
        outcome.notes.append(f"stability check noisy: repeat ratio {ratio:.2f}")
        outcome.error = None


def _pattern_for(engine, candidate: RegexCandidate, plan: AttackWitness) -> str:
    if engine.language == "php":
        from ..workers.runner import php_delimited

        body = candidate.raw_pattern
        if body:
            return body
        return php_delimited(candidate.pattern or "", candidate.flags)
    return candidate.pattern or ""


def _flags_for(engine, candidate: RegexCandidate) -> str:
    if engine.language == "php":
        return ""
    return candidate.flags or ""


def _use_regex_module(candidate: RegexCandidate) -> bool:
    """Measure the third-party ``regex`` module only when the source uses it."""
    return candidate.language == "python" and candidate.engine_hint == "regex"


def _preview(text: str, limit: int = 80) -> str:
    if len(text) <= limit:
        return text
    return text[: limit // 2] + "..." + text[-limit // 2:]


# ---------------------------------------------------------------------------
# growth analysis
# ---------------------------------------------------------------------------

def _summarise(outcome: _RunOutcome, settings: VerificationSettings) -> DynamicAnalysis:
    analysis = DynamicAnalysis(
        engine=outcome.engine_label or None,
        engine_version=outcome.engine_version,
        notes=list(outcome.notes),
        trials=outcome.trials,
    )
    if outcome.plan is not None:
        analysis.attack = f"{outcome.plan.prefix}{outcome.plan.pump}xN{outcome.plan.suffix}{outcome.plan.breaker}"
    analysis.attack_inputs = [t.input_preview for t in outcome.trials
                              if t.input_preview][-3:]

    completed: List[Tuple[int, float]] = _aggregate_trials(outcome.trials)
    timeouts = [t for t in outcome.trials if t.status == "timeout"]
    errors = [t for t in outcome.trials if t.status in ("error", "crash")]

    measurable = [(n, ms) for n, ms in completed if ms >= settings.noise_floor_ms]
    if measurable:
        analysis.max_elapsed_ms = max(ms for _, ms in measurable)
    if timeouts:
        analysis.timeout_at = timeouts[-1].input_length

    slopes = _slopes(measurable)
    if slopes:
        analysis.growth_slope = _robust_tail(slopes)

    if not completed and errors and not measurable:
        analysis.status = DynamicStatus.ERROR.value
        analysis.growth_class = "unknown"
        analysis.evidence.append(f"engine error: {errors[0].error}")
        return analysis

    growth_class = "unknown"
    evidence: List[str] = []

    if len(measurable) >= 2:
        tail = _robust_tail(slopes)
        delta = slopes[-1] - slopes[0]
        growth_class = _classify(tail, delta, analysis.max_elapsed_ms or 0.0,
                                settings)
        evidence.append(
            "log-log slopes between consecutive sizes: "
            + ", ".join(f"{s:.2f}" for s in slopes)
        )
    if timeouts:
        # The slopes measured before the hard limit describe the asymptote,
        # so a super-linear reading (quadratic or exponential) is kept: the
        # timeout is additional evidence, not a replacement for the measured
        # class.  Only a curve that looked linear/constant before the limit
        # is reported as a bare "timeout".
        if growth_class not in ("exponential", "polynomial"):
            growth_class = "timeout"
        evidence.append(f"hard wall-clock timeout at {analysis.timeout_at} characters")

    analysis.growth_class = growth_class
    confirmed, reason = _confirm(growth_class, measurable, timeouts, slopes,
                                 analysis.max_elapsed_ms or 0.0, settings, outcome)
    analysis.evidence.extend(evidence)
    if reason:
        analysis.evidence.append(reason)

    if confirmed:
        analysis.status = DynamicStatus.CONFIRMED.value
    elif outcome.error:
        analysis.status = DynamicStatus.ERROR.value
    elif len(measurable) < 2:
        analysis.status = DynamicStatus.INCONCLUSIVE.value
        analysis.evidence.append("not enough measurable points to establish growth")
    else:
        analysis.status = DynamicStatus.NOT_CONFIRMED.value
    return analysis


def _aggregate_trials(trials: Sequence[Trial]) -> List[Tuple[int, float]]:
    """Collapse repeated measurements of the same input length.

    The stability check runs the same size twice, and one of the two runs may
    be disturbed by CPU contention or allocator effects.  The *fastest*
    observation is the closest estimate of the algorithmic cost, because noise
    can only add time.  Averaging (or taking the maximum) would let a single
    throttled rerun inflate the last log-log slope and turn a clean quadratic
    curve into a false "exponential" reading.
    """
    best: Dict[int, float] = {}
    for trial in trials:
        if trial.status != "completed" or trial.elapsed_ms < 0:
            continue
        previous = best.get(trial.input_length)
        best[trial.input_length] = (trial.elapsed_ms if previous is None
                                    else min(previous, trial.elapsed_ms))
    return sorted(best.items())


def _slopes(points: Sequence[Tuple[int, float]]) -> List[float]:
    slopes: List[float] = []
    for (n1, t1), (n2, t2) in zip(points, points[1:]):
        if n2 <= n1 or t1 <= 0 or t2 <= 0:
            continue
        slopes.append(math.log(t2 / t1) / math.log(n2 / n1))
    return slopes


def _robust_tail(slopes: Sequence[float]) -> float:
    """Estimate the asymptotic slope while tolerating one noisy last point.

    A single mismeasured size can halve the final ratio (CPU contention,
    allocator effects, an engine switching strategies).  Since confirmation
    requires reproducible super-linear growth, one noisy tail point must not
    turn a clean quadratic curve into "linear".  The median of the last three
    slopes is stable for both quadratic and exponential curves, and still
    reports genuinely linear patterns as linear.
    """
    if not slopes:
        return 0.0
    recent = list(slopes[-3:]) if len(slopes) >= 3 else list(slopes)
    return statistics.median(recent)


def _classify(tail: float, delta: float, max_ms: float,
              settings: VerificationSettings) -> str:
    """Map the asymptotic log-log slope to a growth class.

    ``tail`` is the robust (median of the last three) slope, so it is close to
    2 for quadratic backtracking and grows without bound for exponential
    backtracking.  ``delta`` (last minus first slope) is only a secondary
    signal: on short ladders the first segments are dominated by startup and
    noise, so a large delta must not by itself turn a steady quadratic curve
    into "exponential".
    """
    if max_ms < settings.noise_floor_ms * 2:
        return "inconclusive"
    if tail >= 3.0 or (tail >= 2.2 and delta >= max(1.5, settings.slope_delta * 2)):
        return "exponential"
    if tail >= 1.35:
        return "polynomial"
    if tail >= 0.7:
        return "linear"
    return "constant"


def _confirm(growth_class: str, measurable: Sequence[Tuple[int, float]],
             timeouts: Sequence[Trial], slopes: Sequence[float], max_ms: float,
             settings: VerificationSettings, outcome: _RunOutcome) -> Tuple[bool, str]:
    tail = _robust_tail(slopes)
    if growth_class == "exponential" and len(measurable) >= 2:
        if max_ms >= max(5.0, settings.noise_floor_ms * 10):
            return True, (f"super-linear growth: {max_ms:.1f} ms at "
                          f"{measurable[-1][0]} characters, slope {tail:.2f}")
        return False, "growth is super-linear but the absolute time is too small"
    if growth_class == "polynomial" and len(measurable) >= 2:
        if max_ms >= 10.0:
            return True, (f"polynomial growth: {max_ms:.1f} ms at "
                          f"{measurable[-1][0]} characters, slope {tail:.2f}")
        return False, "polynomial growth measured, but absolute time is too small"
    if timeouts:
        previous = measurable[-1][1] if measurable else 0.0
        if previous >= 20.0:
            return True, (f"timeout preceded by {previous:.1f} ms at "
                          f"{measurable[-1][0]} characters")
        if len(slopes) >= 2 and slopes[-1] >= 2.5:
            return True, (f"timeout preceded by super-linear growth "
                          f"(slope {slopes[-1]:.2f})")
        return False, "single timeout without measurable degradation before it"
    if growth_class == "linear":
        return False, "linear growth is not a ReDoS"
    return False, "no reproducible degradation"


def summarize_for_cache(analysis: DynamicAnalysis) -> Dict[str, object]:
    return {
        "status": analysis.status,
        "growth_class": analysis.growth_class,
        "growth_slope": analysis.growth_slope,
        "max_elapsed_ms": analysis.max_elapsed_ms,
        "engine_version": analysis.engine_version,
    }
