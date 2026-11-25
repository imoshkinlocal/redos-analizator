"""SQLite persistence and cache tests."""

from __future__ import annotations

import json

from debian_redos.core import database as db_module
from debian_redos.core.correlate import CorrelateOptions, correlate
from debian_redos.models import ScanStats

from helpers import confirmed_dynamic, make_candidate


def _finding(run_id: str, *, file="app.py", line=10, input_control="user_network"):
    candidate = make_candidate(file=file, line=line, input_control=input_control)
    candidate.dynamic = confirmed_dynamic()
    findings = correlate([candidate], package="pkg", version="1.0",
                         run_id=run_id,
                         options=CorrelateOptions())
    assert findings
    return findings[0]


def test_run_lifecycle_and_findings_roundtrip(tmp_path):
    db = db_module.Database(str(tmp_path / "cache.sqlite3"))
    try:
        run_id = db.start_run("full", "sha256:config", labels={"x": 1})
        finding = _finding(run_id)
        db.save_findings([finding])
        db.finish_run(run_id, ScanStats(files=3), notes=["hello"])

        stored = db.query_findings(run_id=run_id)
        assert len(stored) == 1
        loaded = stored[0]
        assert loaded.id == finding.id
        # deep model reconstruction: nested objects must not stay dicts
        assert loaded.static.evidence[0].rule
        assert loaded.dynamic.trials[0].input_length == 12
        assert loaded.dynamic.confirmed is True

        meta = db.run_meta(run_id)
        assert meta["mode"] == "full"
        assert meta["config_hash"] == "sha256:config"
        assert meta["notes"] == ["hello"]
        assert meta["stats_json"]["files"] == 3
    finally:
        db.close()


def test_two_runs_keep_separate_findings(tmp_path):
    db = db_module.Database(str(tmp_path / "cache.sqlite3"))
    try:
        first = db.start_run("full", "cfg")
        db.save_findings([_finding(first)])
        db.finish_run(first, ScanStats())
        second = db.start_run("incremental", "cfg")
        db.save_findings([_finding(second)])
        db.finish_run(second, ScanStats())
        assert len(db.query_findings(run_id=first)) == 1
        assert len(db.query_findings(run_id=second)) == 1
        assert db.previous_run()["id"] == second
    finally:
        db.close()


def test_finding_without_literal_pattern_roundtrips(tmp_path):
    """Dynamic candidates may have no literal pattern; ``to_dict`` drops the
    None field, so ``from_dict`` must still be able to rebuild the model."""
    db = db_module.Database(str(tmp_path / "cache.sqlite3"))
    try:
        run_id = db.start_run("full", "cfg")
        finding = _finding(run_id)
        finding.pattern = None
        finding.pattern_hash = None
        db.save_findings([finding])
        db.finish_run(run_id, ScanStats())
        loaded = db.query_findings(run_id=run_id)[0]
        assert loaded.pattern is None
        assert loaded.id == finding.id
    finally:
        db.close()


def test_file_cache_and_reuse(tmp_path):
    from debian_redos.models import SourceFile

    db = db_module.Database(str(tmp_path / "cache.sqlite3"))
    try:
        source = SourceFile(package="pkg", version="1.0", path="a.py",
                            abspath="/tmp/a.py", language="python",
                            sha256="abc", size=10, lines=1)
        db.save_files([source])
        assert db.file_is_unchanged("pkg", "1.0", "a.py", "abc") is True
        assert db.file_is_unchanged("pkg", "1.0", "a.py", "def") is False
        assert db.file_is_unchanged("pkg", "2.0", "a.py", "abc") is False

        run_id = db.start_run("full", "cfg")
        db.save_findings([_finding(run_id)])
        db.finish_run(run_id, ScanStats())
        reused = db.findings_for_files("pkg", "1.0", ["app.py"], run_id=run_id)
        assert len(reused) == 1
        assert db.findings_for_files("pkg", "1.0", ["nope.py"], run_id=run_id) == []
    finally:
        db.close()


def test_analysis_and_dynamic_caches(tmp_path):
    db = db_module.Database(str(tmp_path / "cache.sqlite3"))
    try:
        assert db.cache_get("analysis_cache", "k") is None
        db.cache_put("analysis_cache", "k", {"status": "safe"})
        assert db.cache_get("analysis_cache", "k") == {"status": "safe"}
        db.cache_put("dynamic_cache", "d", {"status": "confirmed"}, engine="python-re")
        assert db.cache_get("dynamic_cache", "d") == {"status": "confirmed"}
        db.clear_cache()
        assert db.cache_get("analysis_cache", "k") is None
        assert db.cache_get("dynamic_cache", "d") is None
    finally:
        db.close()


def test_query_filters_and_stats(tmp_path):
    db = db_module.Database(str(tmp_path / "cache.sqlite3"))
    try:
        run_id = db.start_run("full", "cfg")
        db.save_packages([__import__("debian_redos.models", fromlist=["PackageInfo"]).PackageInfo(
            name="pkg", version="1.0", directory="/tmp")])
        db.save_findings([_finding(run_id, file="a.py", line=1),
                          _finding(run_id, file="b.py", line=2,
                                   input_control="file")])
        db.finish_run(run_id, ScanStats())
        assert len(db.query_findings(run_id=run_id)) == 2
        assert len(db.query_findings(run_id=run_id, min_severity="critical")) >= 1
        assert len(db.query_findings(run_id=run_id, verdict="exploitable")) == 1
        assert len(db.query_findings(run_id=run_id, package="pkg")) == 2
        packages = db.load_packages()
        assert packages[0].name == "pkg"
        stats = db.stats()
        assert stats["findings"] == 2
        assert stats["scan_runs"] == 1
    finally:
        db.close()


def test_prune_removes_old_runs(tmp_path):
    db = db_module.Database(str(tmp_path / "cache.sqlite3"))
    try:
        ids = []
        for index in range(4):
            run_id = db.start_run("full", "cfg")
            db.save_findings([_finding(run_id)])
            db.finish_run(run_id, ScanStats())
            ids.append(run_id)
            import time
            time.sleep(1.01)  # started_at has second resolution
        removed = db.prune(keep_runs=1)
        assert removed == 3
        remaining = db.connection.execute("SELECT id FROM scan_runs").fetchall()
        assert [row["id"] for row in remaining] == [ids[-1]]
    finally:
        db.close()


def test_cache_table_validation(tmp_path):
    db = db_module.Database(str(tmp_path / "cache.sqlite3"))
    try:
        try:
            db.cache_get("findings", "k")
        except ValueError as exc:
            assert "unknown cache table" in str(exc)
        else:
            raise AssertionError("expected ValueError")
    finally:
        db.close()
