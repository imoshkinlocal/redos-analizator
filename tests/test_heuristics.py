"""Calibration tests for the structural detector.

The expected verdicts below were cross-checked against real Python ``re``
measurements during development; they are the regression baseline for the
static stage.
"""

from __future__ import annotations

import pytest

from debian_redos.analyzers.heuristics import analyze
from debian_redos.models import Complexity, StaticStatus


@pytest.mark.parametrize("pattern,dialect,status,complexity", [
    (r"^(a+)+$", "python", StaticStatus.VULNERABLE, Complexity.EXPONENTIAL),
    (r"^(a|aa)+$", "python", StaticStatus.VULNERABLE, Complexity.EXPONENTIAL),
    (r"^(\d+)*$", "python", StaticStatus.VULNERABLE, Complexity.EXPONENTIAL),
    (r"(.*a){12}", "python", StaticStatus.SUSPICIOUS, Complexity.EXPONENTIAL),
    (r"(a*)*b", "python", StaticStatus.VULNERABLE, Complexity.EXPONENTIAL),
    (r"(?:a+)+$", "python", StaticStatus.VULNERABLE, Complexity.EXPONENTIAL),
    (r"a*a*$", "python", StaticStatus.SUSPICIOUS, Complexity.POLYNOMIAL),
    (r"(ab|a)+$", "python", StaticStatus.SAFE, Complexity.LINEAR),
    (r"^(a|b)+$", "python", StaticStatus.SAFE, Complexity.LINEAR),
    (r"^[a-z]+$", "python", StaticStatus.SAFE, Complexity.LINEAR),
    (r"\d+\.\d+", "python", StaticStatus.SAFE, Complexity.LINEAR),
    (r"^(a+)\1+$", "python", StaticStatus.SUSPICIOUS, Complexity.UNKNOWN),
])
def test_calibration_matrix(pattern, dialect, status, complexity):
    analysis = analyze(pattern, dialect)
    assert analysis.status == status.value
    assert analysis.complexity == complexity.value


def test_dialect_does_not_change_structural_result():
    python = analyze(r"^(a|aa)+$", "python")
    ruby = analyze(r"\A(a|aa)+\z", "ruby")
    php = analyze(r"^(a|aa)+$", "php")
    for analysis in (python, ruby, php):
        assert analysis.complexity == "exponential"
        assert analysis.status == "vulnerable"


def test_evidence_and_attack_witness():
    analysis = analyze(r"^(a+)+$")
    rules = {item.rule for item in analysis.evidence}
    assert "nested_quantifier" in rules
    assert "ambiguous_repetition" in rules
    assert analysis.attack_plans
    plan = analysis.attack_plans[0]
    assert plan.pump
    assert plan.kind == "exponential"
    assert plan.prefix == "" and plan.suffix == ""
    assert plan.to_dict()["breaker"]


def test_polynomial_witness():
    analysis = analyze(r"a*a*$")
    assert analysis.attack_plans
    assert analysis.attack_plans[0].kind == "polynomial"
    assert analysis.attack_plans[0].pump == "a"


def test_unresolved_pattern():
    analysis = analyze(None)
    assert analysis.status == StaticStatus.DYNAMIC_PATTERN_UNRESOLVED.value
    assert analysis.suspicious is True


def test_too_long_pattern_is_unsupported():
    analysis = analyze("a" * 20, max_pattern_length=10)
    assert analysis.status == StaticStatus.UNSUPPORTED.value


def test_parse_error_is_unsupported():
    analysis = analyze("(a")
    assert analysis.status == StaticStatus.UNSUPPORTED.value
    assert "parse error" in " ".join(analysis.notes)


def test_possessive_and_atomic_are_not_flagged():
    assert analyze(r"(?>a+)+$").complexity != "exponential"
    assert analyze(r"(a++)+$").complexity != "exponential"


def test_confidence_and_notes_are_serialisable():
    analysis = analyze(r"(.*a){12}")
    payload = analysis.to_dict()
    assert payload["evidence"]
    restored = type(analysis).from_dict(payload)
    assert restored.complexity == analysis.complexity
    assert restored.evidence[0].rule == analysis.evidence[0].rule
    if analysis.attack_plans:
        assert restored.attack_plans[0].pump == analysis.attack_plans[0].pump
