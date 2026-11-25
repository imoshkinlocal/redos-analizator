"""Factories shared by the tests."""

from __future__ import annotations

from debian_redos.analyzers import heuristics
from debian_redos.models import (
    DynamicAnalysis,
    DynamicStatus,
    InputControl,
    RegexCandidate,
    StaticAnalysis,
    Trial,
)


def make_candidate(pattern=r"^(a+)+$", *, language="python", file="app.py",
                   line=10, function="handler", input_control="unknown",
                   flags="", static: StaticAnalysis = None) -> RegexCandidate:
    candidate = RegexCandidate(
        package="pkg",
        version="1.0",
        language=language,
        file=file,
        line=line,
        function=function,
        pattern=pattern,
        dialect=language,
        flags=flags,
        input_control=input_control,
        input_evidence=f"source: {input_control}",
        extractor="test",
    )
    candidate.static = static if static is not None else heuristics.analyze(
        pattern, language, flags)
    return candidate


def confirmed_dynamic(*, engine="python-re", max_ms=250.0,
                      growth="exponential") -> DynamicAnalysis:
    return DynamicAnalysis(
        status=DynamicStatus.CONFIRMED.value,
        engine=engine,
        engine_version="test",
        growth_class=growth,
        growth_slope=5.1,
        max_elapsed_ms=max_ms,
        attack="a xN !",
        trials=[Trial(input_length=12, elapsed_ms=1.0),
                Trial(input_length=20, elapsed_ms=max_ms)],
        evidence=["super-linear growth"],
    )


def skipped_dynamic() -> DynamicAnalysis:
    return DynamicAnalysis(status=DynamicStatus.SKIPPED.value,
                           notes=["dynamic stage disabled"])
