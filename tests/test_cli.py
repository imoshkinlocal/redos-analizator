"""CLI end-to-end tests."""

from __future__ import annotations

import json
import os

from debian_redos.cli import main


def test_analyze_pattern_json(capsys):
    code = main(["analyze-pattern", "^(a+)+$", "--language", "python", "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["static"]["complexity"] == "exponential"
    assert payload["static"]["attack_plans"]


def test_analyze_pattern_human(capsys):
    code = main(["analyze-pattern", "^[a-z]+$"])
    assert code == 0
    out = capsys.readouterr().out
    assert "complexity: linear" in out
    assert "status:    safe" in out


def test_extract_json(fixture_package, capsys):
    code = main(["extract", fixture_package, "--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    patterns = {item["pattern"] for item in payload}
    assert "^(a+)+$" in patterns
    assert all(item["package"] == "redos-fixture" for item in payload)


def test_scan_then_report_and_db(fixture_package, config_path, tmp_path, capsys):
    db = str(tmp_path / "cache.sqlite3")
    reports = str(tmp_path / "reports")
    code = main([
        "scan", fixture_package, "--config", config_path, "--static",
        "--db", db, "--output-dir", reports, "--format", "json",
        "--fail-on", "medium", "--quiet",
    ])
    assert code == 1  # medium needs_review/potential findings are present
    assert os.path.isfile(os.path.join(reports, "redos-report.json"))
    capsys.readouterr()

    code = main(["db", "stats", "--config", config_path, "--db", db])
    assert code == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["scan_runs"] == 1
    assert stats["findings"] >= 3

    code = main(["report", "--config", config_path, "--db", db,
                 "--output-dir", str(tmp_path / "reports2"),
                 "--format", "sarif", "--quiet"])
    assert code == 0
    assert os.path.isfile(str(tmp_path / "reports2" / "redos.sarif"))
    capsys.readouterr()

    code = main(["db", "runs", "--db", db])
    assert code == 0
    assert "finished" in capsys.readouterr().out


def test_scan_default_exit_code_is_zero_for_medium(fixture_package, config_path,
                                                  tmp_path, capsys):
    code = main([
        "scan", fixture_package, "--config", config_path, "--static",
        "--db", str(tmp_path / "cache.sqlite3"), "--no-reports", "--quiet",
    ])
    assert code == 0
    capsys.readouterr()


def test_scan_static_flag_disables_dynamic(fixture_package, config_path,
                                           tmp_path, capsys):
    code = main([
        "scan", fixture_package, "--config", config_path, "--static",
        "--db", str(tmp_path / "cache.sqlite3"), "--no-reports",
    ])
    assert code == 0
    out = capsys.readouterr().out
    assert "dynamic stage disabled" in out
    assert "dynamic tests            0" in out


def test_php_cli_candidate_keeps_delimiters():
    from debian_redos.cli import _candidate

    wrapped = _candidate("/^(a+)+$/i", "php", "i")
    assert wrapped.raw_pattern == "/^(a+)+$/i"
    plain = _candidate("^(a+)+$", "php", "i")
    assert plain.raw_pattern != "^(a+)+$"
    assert plain.raw_pattern.endswith("i")


def test_doctor(capsys):
    code = main(["doctor"])
    assert code == 0
    out = capsys.readouterr().out
    assert "debian-redos" in out
    assert "python" in out
    assert "languages / engines" in out


def test_db_clear_cache(fixture_package, config_path, tmp_path, capsys):
    db = str(tmp_path / "cache.sqlite3")
    main(["scan", fixture_package, "--config", config_path, "--static",
          "--db", db, "--no-reports", "--quiet"])
    capsys.readouterr()
    code = main(["db", "clear-cache", "--db", db])
    assert code == 0
    assert "cleared" in capsys.readouterr().out
    code = main(["db", "stats", "--db", db])
    stats = json.loads(capsys.readouterr().out)
    assert stats["analysis_cache"] == 0
    assert stats["dynamic_cache"] == 0


def test_scan_without_paths_uses_cwd(fixture_package, config_path, tmp_path,
                                     monkeypatch, capsys):
    monkeypatch.chdir(fixture_package)
    code = main(["scan", "--config", config_path, "--static",
                 "--db", str(tmp_path / "cache.sqlite3"), "--no-reports",
                 "--quiet"])
    assert code == 0
