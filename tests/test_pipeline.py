"""End-to-end pipeline tests (static stage)."""

from __future__ import annotations

import json
import os

from debian_redos.core.database import Database
from debian_redos.core.pipeline import Scanner, ScanOptions


def test_full_static_scan(fixture_package, config, tmp_path):
    db_path = str(tmp_path / "cache.sqlite3")
    reports = str(tmp_path / "reports")
    messages = []
    scanner = Scanner(config, db_path=db_path, log=messages.append)
    try:
        result = scanner.scan(ScanOptions(
            paths=[fixture_package],
            mode="full",
            jobs=2,
            dynamic=False,
            write_reports=True,
            output_dir=reports,
            formats=["json", "summary"],
        ))
    finally:
        scanner.close()

    assert result.run_id.startswith("run-")
    assert result.stats.packages == 1
    assert result.stats.files == 3
    assert result.stats.files_scanned == 3
    assert result.stats.candidates >= 5
    assert result.stats.static_suspicious >= 3
    patterns = {f.pattern for f in result.findings}
    assert "^(a+)+$" in patterns
    assert "^(b+)+$" in patterns
    assert r"\A(a|aa)+\z" in patterns
    assert "^[a-z]+$" not in patterns
    assert all(f.dynamic.status == "skipped" for f in result.findings)
    assert os.path.isfile(os.path.join(reports, "redos-report.json"))
    assert os.path.isfile(os.path.join(reports, "redos-summary.txt"))
    assert any("extracting" in message for message in messages)

    db = Database(db_path)
    try:
        stored = db.query_findings(run_id=result.run_id)
        assert len(stored) == len(result.findings)
        assert stored[0].static.evidence
        stats = db.stats()
        assert stats["scan_runs"] == 1
        assert stats["analysis_cache"] > 0
        assert stats["packages"] == 1
    finally:
        db.close()


def test_incremental_scan_reuses_findings(fixture_package, config, tmp_path):
    db_path = str(tmp_path / "cache.sqlite3")
    scanner = Scanner(config, db_path=db_path)
    try:
        first = scanner.scan(ScanOptions(paths=[fixture_package], mode="full",
                                         dynamic=False, write_reports=False))
        second = scanner.scan(ScanOptions(paths=[fixture_package],
                                          mode="incremental", dynamic=False,
                                          write_reports=False))
    finally:
        scanner.close()
    assert second.stats.files_skipped_cached == 3
    assert second.stats.files_scanned == 0
    assert {f.id for f in second.findings} == {f.id for f in first.findings}
    assert second.stats.confirmed == first.stats.confirmed
    assert second.stats.duration_seconds < first.stats.duration_seconds + 1.0


def test_incremental_with_changed_file_reextracts_only_that_file(
        fixture_package, config, tmp_path):
    import shutil

    tree = tmp_path / "pkg"
    shutil.copytree(fixture_package, tree)
    db_path = str(tmp_path / "cache.sqlite3")
    scanner = Scanner(config, db_path=db_path)
    try:
        scanner.scan(ScanOptions(paths=[str(tree)], mode="full", dynamic=False,
                                 write_reports=False))
        (tree / "app.py").write_text(
            "import re\nfrom flask import request\n"
            "re.match(r'^(x+)+$', request.args.get('q', ''))\n")
        result = scanner.scan(ScanOptions(paths=[str(tree)], mode="incremental",
                                          dynamic=False, write_reports=False))
    finally:
        scanner.close()
    assert result.stats.files_skipped_cached == 2
    assert result.stats.files_scanned == 1
    patterns = {f.pattern for f in result.findings}
    assert "^(x+)+$" in patterns
    # the old vulnerable findings from app.py must be gone, other files stay
    assert "^(b+)+$" not in patterns
    assert r"\A(a|aa)+\z" in patterns


def test_scan_without_supported_files(tmp_path, config):
    empty = tmp_path / "empty"
    empty.mkdir()
    (empty / "README.txt").write_text("nothing to see")
    scanner = Scanner(config, db_path=str(tmp_path / "cache.sqlite3"))
    try:
        result = scanner.scan(ScanOptions(paths=[str(empty)], dynamic=False,
                                          write_reports=False))
    finally:
        scanner.close()
    assert result.stats.files == 0
    assert result.findings == []
    assert result.stats.packages == 1


def test_scan_dsc_without_unpacking(tmp_path, config):
    dsc = tmp_path / "demo_1.0.dsc"
    dsc.write_text("Format: 3.0 (quilt)\nSource: demo\nVersion: 1.0\n")
    scanner = Scanner(config, db_path=str(tmp_path / "cache.sqlite3"))
    try:
        result = scanner.scan(ScanOptions(paths=[str(dsc)], dynamic=False,
                                          write_reports=False))
    finally:
        scanner.close()
    assert result.stats.files == 0
    assert any("source tree not available" in note for note in result.notes)


def test_json_report_is_serialisable(fixture_package, config, tmp_path):
    scanner = Scanner(config, db_path=str(tmp_path / "cache.sqlite3"))
    try:
        result = scanner.scan(ScanOptions(paths=[fixture_package],
                                          dynamic=False, write_reports=False))
    finally:
        scanner.close()
    payload = result.to_dict()
    assert payload["run_id"] == result.run_id
    assert isinstance(payload["findings"], list)
    restored = type(result).from_dict(payload)
    assert restored.findings[0].static.complexity
