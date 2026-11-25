"""Correlation policy tests."""

from __future__ import annotations

import json

from debian_redos.core.correlate import CorrelateOptions, CveMap, correlate
from debian_redos.models import DynamicStatus, Verdict

from helpers import confirmed_dynamic, make_candidate, skipped_dynamic


def _run(candidates, **kwargs):
    options = CorrelateOptions(**kwargs)
    return correlate(candidates, package="pkg", version="1.0",
                     run_id="run-1", options=options)


def test_confirmed_attacker_controlled_is_exploitable():
    candidate = make_candidate(input_control="user_network")
    candidate.dynamic = confirmed_dynamic()
    findings = _run([candidate])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.verdict == Verdict.EXPLOITABLE.value
    assert finding.severity == "critical"
    assert finding.priority == "critical"
    assert finding.engine == "python-re"
    assert finding.dynamic.confirmed


def test_confirmed_non_attacker_input_is_downgraded():
    candidate = make_candidate(input_control="file")
    candidate.dynamic = confirmed_dynamic()
    finding = _run([candidate])[0]
    assert finding.verdict == Verdict.CONFIRMED.value
    assert finding.severity == "medium"


def test_static_only_exponential_with_unknown_input_needs_review():
    candidate = make_candidate(input_control="unknown")
    candidate.dynamic = skipped_dynamic()
    finding = _run([candidate])[0]
    assert finding.verdict == Verdict.NEEDS_REVIEW.value
    assert finding.severity == "medium"


def test_static_only_exponential_with_network_input_is_potential():
    candidate = make_candidate(input_control="user_network")
    candidate.dynamic = skipped_dynamic()
    finding = _run([candidate])[0]
    assert finding.verdict == Verdict.POTENTIAL.value
    assert finding.severity == "medium"


def test_polynomial_potential_is_low():
    candidate = make_candidate(pattern="a*a*$", input_control="user_network")
    candidate.dynamic = skipped_dynamic()
    finding = _run([candidate])[0]
    assert finding.static.complexity == "polynomial"
    assert finding.verdict == Verdict.POTENTIAL.value
    assert finding.severity == "low"


def test_safe_patterns_are_filtered_by_default():
    candidate = make_candidate(pattern="^[a-z]+$")
    assert _run([candidate]) == []
    reported = _run([candidate], report_safe=True)
    assert len(reported) == 1 and reported[0].verdict == "informational"


def test_dynamic_error_becomes_needs_review():
    candidate = make_candidate(input_control="user_network")
    from debian_redos.models import DynamicAnalysis
    candidate.dynamic = DynamicAnalysis(status=DynamicStatus.ERROR.value,
                                        notes=["worker crashed"])
    finding = _run([candidate])[0]
    assert finding.verdict == Verdict.NEEDS_REVIEW.value


def test_same_file_and_pattern_is_deduplicated():
    first = make_candidate(line=10, input_control="user_network")
    first.dynamic = confirmed_dynamic()
    second = make_candidate(line=20, input_control="file", function="other")
    second.static = first.static
    second.dynamic = confirmed_dynamic()
    findings = _run([first, second])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.duplicates == 1
    assert finding.input_control == "user_network"
    assert finding.line == 10
    assert "also at" in " ".join(finding.notes)


def test_different_files_are_not_deduplicated():
    first = make_candidate(file="a.py")
    first.dynamic = confirmed_dynamic()
    second = make_candidate(file="b.py")
    second.dynamic = confirmed_dynamic()
    assert len(_run([first, second])) == 2


def test_unresolved_pattern_is_needs_review():
    candidate = make_candidate(pattern=None, input_control="unknown")
    candidate.static = __import__("debian_redos.analyzers.heuristics",
                                  fromlist=["analyze"]).analyze(None)
    finding = _run([candidate])[0]
    assert finding.verdict == Verdict.NEEDS_REVIEW.value


def test_missing_dynamic_is_normalised():
    candidate = make_candidate(input_control="unknown")
    assert candidate.dynamic is None
    finding = _run([candidate])[0]
    assert finding.dynamic is not None
    assert finding.dynamic.status == DynamicStatus.SKIPPED.value
    restored = type(finding).from_dict(finding.to_dict())
    assert restored.dynamic is not None
    assert restored.dynamic.status == DynamicStatus.SKIPPED.value


def test_min_severity_filters(tmp_path):
    candidate = make_candidate(input_control="file")
    candidate.dynamic = confirmed_dynamic()
    assert _run([candidate], min_severity="high") == []
    assert _run([candidate], min_severity="medium")


def test_cve_map_lookup(tmp_path):
    path = tmp_path / "cve.json"
    path.write_text(json.dumps({
        "patterns": {"sha256:deadbeef": {"cve": "CVE-2021-0001",
                                          "source": "tracker"}},
        "locations": {"pkg:app.py:10": {"cve": "CVE-2021-0002",
                                         "source": "location"}},
        "packages": {"other": [{"cve": "CVE-2021-0003", "file": "other.py",
                                "source": "package"}]},
    }))
    cve_map = CveMap.load(str(path))
    candidate = make_candidate(line=10)
    candidate.dynamic = confirmed_dynamic()
    finding = _run([candidate], cve_map=cve_map)[0]
    assert finding.cve == "CVE-2021-0002"
    assert finding.cve_source == "location"

    candidate2 = make_candidate(pattern="^(b+)+$", line=99)
    candidate2.pattern_hash = "sha256:deadbeef"
    candidate2.dynamic = confirmed_dynamic()
    finding2 = _run([candidate2], cve_map=cve_map)[0]
    assert finding2.cve == "CVE-2021-0001"

    candidate3 = make_candidate(pattern="^(c+)+$", file="other.py", line=5)
    candidate3.package = "other"
    candidate3.dynamic = confirmed_dynamic()
    finding3 = correlate([candidate3], package="other", version="1.0",
                         run_id="run-1", options=CorrelateOptions(cve_map=cve_map))[0]
    assert finding3.cve == "CVE-2021-0003"


def test_cve_map_missing_file_raises():
    import pytest
    with pytest.raises(OSError):
        CveMap.load("/nonexistent/cve.json")
