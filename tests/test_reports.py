"""Report writer tests."""

from __future__ import annotations

import json

from debian_redos.core.correlate import CorrelateOptions, correlate
from debian_redos.models import PackageInfo, ScanResult, ScanStats
from debian_redos.reports import read_jsonl_findings, write_reports
from debian_redos.reports.html_report import build_html
from debian_redos.reports.sarif import build as build_sarif

from helpers import confirmed_dynamic, make_candidate


def _result():
    network = make_candidate(file="app.py", line=10, input_control="user_network")
    network.dynamic = confirmed_dynamic()
    local = make_candidate(pattern="^(b+)+$", file="cli.py", line=3,
                           input_control="user_local")
    local.dynamic = confirmed_dynamic()
    findings = correlate([network, local], package="pkg", version="1.0",
                         run_id="run-1", options=CorrelateOptions())
    return ScanResult(
        run_id="run-1",
        started_at="2024-01-01T00:00:00Z",
        finished_at="2024-01-01T00:00:01Z",
        mode="full",
        packages=[PackageInfo(name="pkg", version="1.0", directory="/tmp/pkg")],
        findings=findings,
        stats=ScanStats(packages=1, files=2, files_scanned=2, candidates=2,
                        confirmed=2, exploitable=2, duration_seconds=1.25),
        notes=["note one"],
    )


def test_write_all_reports(tmp_path):
    result = _result()
    paths = write_reports(result, str(tmp_path))
    assert set(paths) == {"json", "jsonl", "sarif", "html", "summary", "manifest"}
    for name, path in paths.items():
        assert path and __import__("os").path.isfile(path), name

    payload = json.loads(open(paths["json"]).read())
    assert payload["tool"]["name"] == "debian-redos"
    assert payload["run_id"] == "run-1"
    assert len(payload["findings"]) == 2
    assert payload["stats"]["confirmed"] == 2

    lines = open(paths["jsonl"]).read().strip().splitlines()
    assert len(lines) == 3
    header = json.loads(lines[0])
    assert header["kind"] == "scan"
    assert [f.id for f in read_jsonl_findings(paths["jsonl"])] == [
        f.id for f in result.findings]

    sarif = json.loads(open(paths["sarif"]).read())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 2
    assert sarif["runs"][0]["tool"]["driver"]["rules"]
    assert sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"]["uri"].startswith("pkg/")

    summary = open(paths["summary"]).read()
    assert "Debian ReDoS scan summary" in summary
    assert "exploitable" in summary

    html = open(paths["html"]).read()
    assert "<!DOCTYPE html>" in html
    assert "^(a+)+$" in html
    assert "filter by package" in html


def test_html_escapes_findings(tmp_path):
    result = _result()
    result.findings[0].pattern = "<script>alert(1)</script>"
    html = build_html(result)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_sarif_levels_and_rules():
    result = _result()
    sarif = build_sarif(result)
    rules = {rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "redos/exponential/exploitable" in rules
    levels = {item["level"] for item in sarif["runs"][0]["results"]}
    assert levels == {"error"}
    result.findings[0].severity = "low"
    result.findings[0].verdict = "potential"
    sarif = build_sarif(result)
    assert "note" in {item["level"] for item in sarif["runs"][0]["results"]}


def test_empty_result_is_valid(tmp_path):
    result = _result()
    result.findings = []
    paths = write_reports(result, str(tmp_path), formats=["json", "html", "sarif"])
    assert json.loads(open(paths["json"]).read())["findings"] == []
    assert "No findings" in open(paths["html"]).read()
    assert json.loads(open(paths["sarif"]).read())["runs"][0]["results"] == []


def test_unknown_format_raises(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        write_reports(_result(), str(tmp_path), formats=["xml"])
