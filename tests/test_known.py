"""Known-database matching, CLI and report integration tests."""

from __future__ import annotations

import json
import os

import pytest

from debian_redos.analyzers import heuristics
from debian_redos.cli import main
from debian_redos.config import load_config
from debian_redos.core.correlate import CorrelateOptions, correlate
from debian_redos.core.known import (
    KnownDatabase,
    KnownOptions,
    canonical_of,
    shape_of,
)
from debian_redos.core.pipeline import Scanner, ScanOptions
from debian_redos.models import (
    Finding,
    KnownMatch,
    PackageInfo,
    ScanResult,
    ScanStats,
)
from debian_redos.reports import write_reports
from debian_redos.reports.html_report import build_html
from debian_redos.reports.sarif import build as build_sarif

from helpers import confirmed_dynamic, make_candidate, skipped_dynamic

PORT_VULNERABLE = r"\A[\x09\x0a\x0c\x0d ]*\d*[\x09\x0a\x0c\x0d ]*\z"
PORT_FIXED = r"\A[\x09\x0a\x0c\x0d ]*+\d*[\x09\x0a\x0c\x0d ]*\z"


def _database(tmp_path, entries, name="known.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"schema_version": "1.0", "entries": entries}))
    return KnownDatabase.load(str(path))


def _entry(identifier="CVE-TEST-0001", pattern=r"^(a+)+$", *,
           language="python", cve=None, patterns=None, packages=None):
    if patterns is None:
        patterns = [{"pattern": pattern}]
    data = {
        "id": identifier,
        "cve": cve if cve is not None else identifier,
        "title": f"test advisory {identifier}",
        "language": language,
        "severity": "high",
        "packages": packages or [],
        "patterns": patterns,
    }
    return data


def _match(db, pattern, *, language="python", flags="", package="",
           options=None):
    static = heuristics.analyze(pattern, language, flags)
    return db.match(pattern, language, flags, package=package,
                    static=static, options=options or KnownOptions())


# ---------------------------------------------------------------------------
# database loading / fingerprints
# ---------------------------------------------------------------------------

def test_bundled_database_loads():
    db = KnownDatabase.bundled()
    stats = db.stats()
    assert stats["entries"] == 5
    assert stats["vulnerable_patterns"] == 6
    assert "CVE-2023-28755" in stats["cves"]
    assert "CVE-2023-28756" in stats["cves"]
    assert "CVE-2023-36617" in stats["cves"]
    assert stats["by_language"] == {"ruby": 5}


def test_bundled_vulnerable_patterns_match_their_entry_exactly():
    db = KnownDatabase.bundled()
    for entry in db.entries:
        for pattern in entry.patterns:
            if pattern.status != "vulnerable":
                continue
            dialect = pattern.dialect or entry.language
            matches = _match(db, pattern.pattern, language=dialect,
                             flags=pattern.flags,
                             package=entry.packages[0] if entry.packages else "")
            assert any(match.id == entry.id and "exact" in match.match_types
                       for match in matches), (entry.id, pattern.pattern[:60])


def test_bundled_fixed_patterns_do_not_match_exactly_or_canonically():
    db = KnownDatabase.bundled()
    for entry in db.entries:
        for pattern in entry.patterns:
            if pattern.status != "fixed":
                continue
            dialect = pattern.dialect or entry.language
            matches = _match(db, pattern.pattern, language=dialect,
                             flags=pattern.flags,
                             package=entry.packages[0] if entry.packages else "")
            for match in matches:
                assert not ({"exact", "canonical"} & set(match.match_types)), (
                    entry.id, pattern.pattern[:60], match.id, match.match_types)


def test_known_options_and_database_loading(config_path, tmp_path):
    from debian_redos.config import load_config
    from debian_redos.core.known import load_database, resolve_database_path

    config = load_config(config_path, overrides={"known": {
        "min_score": 0.5, "match_core": False, "match_packages": False,
        "max_matches": 2, "auto_assign_cve": True,
        "auto_assign_min_score": 0.9,
    }})
    options = KnownOptions.from_config(config)
    assert options.min_score == 0.5
    assert options.match_core is False
    assert options.match_packages is False
    assert options.max_matches == 2
    assert options.auto_assign_cve is True
    assert options.auto_assign_min_score == 0.9

    bundled = load_database(load_config(config_path))
    assert bundled is not None and len(bundled.entries) == 5
    assert load_database(load_config(config_path,
                                     overrides={"known": {"enabled": False}})) is None

    custom_path = tmp_path / "custom.json"
    custom_path.write_text(json.dumps({"entries": [_entry("CVE-CUSTOM")]}))
    custom_config = load_config(config_path,
                                overrides={"known": {"db": str(custom_path)}})
    assert resolve_database_path(custom_config) == str(custom_path)
    custom = load_database(custom_config)
    assert custom is not None and [entry.id for entry in custom.entries] == ["CVE-CUSTOM"]


def test_invalid_database_is_rejected(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{}")
    with pytest.raises(ValueError):
        KnownDatabase.load(str(path))

    path.write_text(json.dumps({"entries": [{"id": "X", "patterns": [
        {"pattern": "a", "status": "maybe"}]}]}))
    with pytest.raises(ValueError):
        KnownDatabase.load(str(path))

    path.write_text(json.dumps({"entries": [
        {"id": "X", "patterns": []}, {"id": "X", "patterns": []}]}))
    with pytest.raises(ValueError):
        KnownDatabase.load(str(path))


def test_merge_overrides_by_id(tmp_path):
    first = _database(tmp_path, [_entry("A", cve="CVE-A")], "a.json")
    second = _database(tmp_path, [_entry("A", cve="CVE-B"),
                                  _entry("B", cve="CVE-B")], "b.json")
    merged = first.merge(second)
    assert {entry.id for entry in merged.entries} == {"A", "B"}
    assert next(entry.cve for entry in merged.entries if entry.id == "A") == "CVE-B"


def test_shape_and_canonical_fingerprints():
    from debian_redos.analyzers.regex_ast import parse

    first = parse(r"^(a+)+:(b+)+$", "python")
    second = parse(r"^(x+)+-(y+)+$", "python")
    assert shape_of(first.ast) == shape_of(second.ast)
    assert canonical_of(first.ast) != canonical_of(second.ast)

    capturing = parse(r"\A(a|aa)+\z", "python")
    noncapturing = parse(r"\A(?:a|aa)+\z", "python")
    assert canonical_of(capturing.ast) == canonical_of(noncapturing.ast)
    assert shape_of(capturing.ast) == shape_of(noncapturing.ast)


# ---------------------------------------------------------------------------
# matching levels
# ---------------------------------------------------------------------------

def test_exact_match_against_bundled_database():
    db = KnownDatabase.bundled()
    matches = _match(db, PORT_VULNERABLE, language="ruby")
    assert matches
    assert matches[0].id == "CVE-2023-36617"
    assert matches[0].kind == "exact"
    assert matches[0].score == 1.0
    assert matches[0].confidence == "high"
    assert matches[0].auto_assigned is False


def test_fixed_variant_is_not_flagged():
    db = KnownDatabase.bundled()
    matches = _match(db, PORT_FIXED, language="ruby")
    assert matches == []


def test_canonical_match_ignores_group_spelling(tmp_path):
    db = _database(tmp_path, [_entry(pattern=r"\A(a|aa)+\z")])
    matches = _match(db, r"\A(?:a|aa)+\z")
    assert matches and matches[0].kind == "canonical"
    assert "canonical" in matches[0].match_types
    assert matches[0].score >= 0.95


def test_canonical_match_across_named_group_syntax(tmp_path):
    db = _database(tmp_path, [_entry(pattern=r"(?P<word>a|aa)+")])
    matches = _match(db, r"(?<token>a|aa)+")
    assert matches and "canonical" in matches[0].match_types


def test_language_agnostic_entry_uses_finding_dialect(tmp_path):
    db = _database(tmp_path, [_entry(
        "CVE-ANY", pattern=r"\A(a|aa)+\z", language="any")])
    matches = _match(db, r"\A(a|aa)+\z", language="ruby")
    assert matches and matches[0].kind == "exact"


def test_shape_match_ignores_literal_characters(tmp_path):
    db = _database(tmp_path, [_entry(pattern=r"^(a+)+:(b+)+$")])
    matches = _match(db, r"^(x+)+-(y+)+$")
    assert matches and matches[0].kind == "shape"
    assert "shape" in matches[0].match_types
    assert "exact" not in matches[0].match_types


def test_core_match_ignores_the_envelope(tmp_path):
    db = _database(tmp_path, [_entry(pattern=r"^X(a+)+Y$")])
    matches = _match(db, r"\Afoo(a+)+bar\z")
    assert matches and matches[0].kind == "core"
    assert matches[0].match_types == ["core"]
    assert "exact" not in matches[0].match_types
    assert "shape" not in matches[0].match_types


def test_fuzzy_match_for_small_edits(tmp_path):
    db = _database(tmp_path, [_entry(pattern=r"^([a-z]+)+\d$")])
    matches = _match(db, r"^([a-z]+)+\d\d$",
                     options=KnownOptions(match_core=False))
    assert matches and matches[0].kind == "fuzzy"
    assert "fuzzy" in matches[0].match_types
    assert 0.78 <= matches[0].score < 0.95


def test_unrelated_pattern_has_no_match(tmp_path):
    db = _database(tmp_path, [_entry(pattern=r"^(a+)+$")])
    assert _match(db, r"^[a-z]+$") == []


def test_package_only_advisory_is_low_confidence(tmp_path):
    db = _database(tmp_path, [_entry(
        "CVE-PKG-1", cve="CVE-PKG-1", patterns=[],
        language="ruby", packages=["ruby"])])
    matches = _match(db, r"^[a-z]+$", language="ruby", package="ruby3.1")
    assert len(matches) == 1
    match = matches[0]
    assert match.kind == "package"
    assert match.pattern_matched is False
    assert match.score < 0.5
    assert match.confidence == "low"

    # a patternless dynamic finding can still be linked at package level
    patternless = db.match(None, "ruby", package="ruby3.1")
    assert len(patternless) == 1
    assert patternless[0].kind == "package"
    assert db.match(None, "ruby", package="ruby3.1",
                    options=KnownOptions(match_packages=False)) == []

    # a package-only match must never assign a CVE automatically
    candidate = make_candidate(pattern=r"^(a+)+$", language="ruby",
                               input_control="user_network")
    candidate.package = "ruby3.1"
    candidate.version = "3.1.2"
    candidate.dynamic = skipped_dynamic()
    finding = correlate(
        [candidate], package="ruby3.1", version="3.1.2", run_id="run-1",
        options=CorrelateOptions(
            known_db=db,
            known_options=KnownOptions(auto_assign_cve=True),
        ),
    )[0]
    assert finding.known[0].pattern_matched is False
    assert finding.cve is None


def test_package_name_does_not_match_when_patterns_are_present(tmp_path):
    db = _database(tmp_path, [_entry(
        "CVE-PKG-2", pattern=r"^(z+)+$", language="ruby", packages=["ruby"])])
    assert _match(db, r"^[a-z]+$", language="ruby", package="ruby3.1") == []


# ---------------------------------------------------------------------------
# CVE assignment policy
# ---------------------------------------------------------------------------

def test_auto_assign_cve_is_opt_in(tmp_path):
    db = _database(tmp_path, [_entry("CVE-ONE", cve="CVE-ONE")])
    candidate = make_candidate(pattern=r"^(a+)+$")
    candidate.dynamic = skipped_dynamic()
    finding = correlate([candidate], package="pkg", version="1.0",
                        run_id="run-1",
                        options=CorrelateOptions(known_db=db))[0]
    assert finding.known and finding.known[0].cve == "CVE-ONE"
    assert finding.cve is None


def test_auto_assign_cve_uses_exact_match(tmp_path):
    db = _database(tmp_path, [_entry("CVE-ONE", cve="CVE-ONE")])
    candidate = make_candidate(pattern=r"^(a+)+$")
    candidate.dynamic = skipped_dynamic()
    finding = correlate(
        [candidate], package="pkg", version="1.0", run_id="run-1",
        options=CorrelateOptions(
            known_db=db,
            known_options=KnownOptions(auto_assign_cve=True,
                                       auto_assign_min_score=0.95),
        ),
    )[0]
    assert finding.cve == "CVE-ONE"
    assert finding.cve_source == "known:CVE-ONE"
    assert finding.known[0].auto_assigned is True


def test_auto_assign_does_not_override_existing_cve(tmp_path):
    db = _database(tmp_path, [_entry("CVE-ONE", cve="CVE-ONE")])
    candidate = make_candidate(pattern=r"^(a+)+$")
    candidate.dynamic = skipped_dynamic()
    finding = correlate([candidate], package="pkg", version="1.0",
                        run_id="run-1",
                        options=CorrelateOptions(known_db=db))[0]
    finding.cve = "CVE-EXISTING"
    db.annotate(finding, KnownOptions(auto_assign_cve=True))
    assert finding.cve == "CVE-EXISTING"
    assert finding.known[0].auto_assigned is False


def test_shape_match_is_not_auto_assignable(tmp_path):
    db = _database(tmp_path, [_entry("CVE-SHAPE", pattern=r"^(a+)+:(b+)+$")])
    candidate = make_candidate(pattern=r"^(x+)+-(y+)+$")
    candidate.dynamic = skipped_dynamic()
    finding = correlate(
        [candidate], package="pkg", version="1.0", run_id="run-1",
        options=CorrelateOptions(
            known_db=db,
            known_options=KnownOptions(auto_assign_cve=True),
        ),
    )[0]
    assert finding.known[0].kind == "shape"
    assert finding.cve is None


def test_cve_map_wins_over_auto_assignment(tmp_path):
    from debian_redos.core.correlate import CveMap

    db = _database(tmp_path, [_entry("CVE-KNOWN", cve="CVE-KNOWN")])
    cve_path = tmp_path / "cve.json"
    cve_path.write_text(json.dumps({
        "locations": {"pkg:app.py:10": {"cve": "CVE-MAP", "source": "tracker"}}}))
    candidate = make_candidate(pattern=r"^(a+)+$", line=10)
    candidate.dynamic = skipped_dynamic()
    finding = correlate(
        [candidate], package="pkg", version="1.0", run_id="run-1",
        options=CorrelateOptions(
            cve_map=CveMap.load(str(cve_path)),
            known_db=db,
            known_options=KnownOptions(auto_assign_cve=True),
        ),
    )[0]
    assert finding.cve == "CVE-MAP"
    assert finding.known[0].cve == "CVE-KNOWN"


# ---------------------------------------------------------------------------
# model / persistence round-trip
# ---------------------------------------------------------------------------

def test_known_match_round_trips_through_model(tmp_path):
    db = _database(tmp_path, [_entry("CVE-ONE", cve="CVE-ONE")])
    candidate = make_candidate(pattern=r"^(a+)+$")
    candidate.dynamic = skipped_dynamic()
    finding = correlate([candidate], package="pkg", version="1.0",
                        run_id="run-1",
                        options=CorrelateOptions(known_db=db))[0]
    restored = Finding.from_dict(finding.to_dict())
    assert isinstance(restored.known[0], KnownMatch)
    assert restored.known[0].id == "CVE-ONE"
    assert restored.known[0].match_types == ["exact"]
    assert restored.known[0].references == []


# ---------------------------------------------------------------------------
# pipeline / reports
# ---------------------------------------------------------------------------

def test_pipeline_attaches_known_matches(fixture_package, config_path, tmp_path):
    known_path = tmp_path / "known.json"
    known_path.write_text(json.dumps({"entries": [_entry(
        "CVE-FIXTURE", cve="CVE-FIXTURE", pattern=r"^(a+)+$")]}))
    config = load_config(config_path, overrides={
        "known": {"db": str(known_path), "auto_assign_cve": False},
    })
    scanner = Scanner(config, db_path=str(tmp_path / "cache.sqlite3"))
    try:
        result = scanner.scan(ScanOptions(paths=[fixture_package], dynamic=False,
                                          write_reports=False))
    finally:
        scanner.close()
    assert result.stats.known_matched >= 1
    finding = next(item for item in result.findings
                   if item.pattern == r"^(a+)+$")
    assert finding.known[0].id == "CVE-FIXTURE"
    assert finding.known[0].kind == "exact"
    assert finding.cve is None


def test_incremental_scan_reannotates_reused_findings(fixture_package,
                                                       config_path, tmp_path):
    first_db = tmp_path / "first.json"
    second_db = tmp_path / "second.json"
    first_db.write_text(json.dumps({"entries": [_entry(
        "CVE-FIRST", cve="CVE-FIRST", pattern=r"^(a+)+$")]}))
    second_db.write_text(json.dumps({"entries": [_entry(
        "CVE-SECOND", cve="CVE-SECOND", pattern=r"^(a+)+$")]}))
    common = {"mode": "full"}
    db_path = str(tmp_path / "cache.sqlite3")

    first_config = load_config(config_path, overrides={"known": {"db": str(first_db)}})
    scanner = Scanner(first_config, db_path=db_path)
    try:
        scanner.scan(ScanOptions(paths=[fixture_package], dynamic=False,
                                 write_reports=False, **common))
    finally:
        scanner.close()

    second_config = load_config(config_path, overrides={"known": {"db": str(second_db)}})
    scanner = Scanner(second_config, db_path=db_path)
    try:
        result = scanner.scan(ScanOptions(paths=[fixture_package],
                                          mode="incremental", dynamic=False,
                                          write_reports=False))
    finally:
        scanner.close()
    assert result.stats.files_skipped_cached == 3
    finding = next(item for item in result.findings
                   if item.pattern == r"^(a+)+$")
    assert finding.known[0].id == "CVE-SECOND"


def _known_result(tmp_path):
    db = _database(tmp_path, [_entry("CVE-REPORT", cve="CVE-REPORT")])
    candidate = make_candidate(pattern=r"^(a+)+$", input_control="user_network")
    candidate.dynamic = confirmed_dynamic()
    finding = correlate([candidate], package="pkg", version="1.0",
                        run_id="run-1",
                        options=CorrelateOptions(known_db=db))[0]
    return ScanResult(
        run_id="run-1",
        started_at="2024-01-01T00:00:00Z",
        finished_at="2024-01-01T00:00:01Z",
        mode="full",
        packages=[PackageInfo(name="pkg", version="1.0", directory="/tmp/pkg")],
        findings=[finding],
        stats=ScanStats(packages=1, files=1, files_scanned=1, candidates=1,
                        confirmed=1, exploitable=1, known_matched=1,
                        duration_seconds=1.0),
    )


def test_reports_include_known_matches(tmp_path):
    result = _known_result(tmp_path)
    paths = write_reports(result, str(tmp_path / "reports"))
    payload = json.loads(open(paths["json"], encoding="utf-8").read())
    assert payload["findings"][0]["known"][0]["cve"] == "CVE-REPORT"
    assert payload["stats"]["known_matched"] == 1

    sarif = json.loads(open(paths["sarif"], encoding="utf-8").read())
    assert sarif["runs"][0]["results"][0]["properties"]["known"][0]["id"] == "CVE-REPORT"
    assert "known-vulnerability" in sarif["runs"][0]["tool"]["driver"]["rules"][0][
        "properties"]["tags"]

    html = open(paths["html"], encoding="utf-8").read()
    assert "CVE-REPORT" in html
    assert "known matches" in html

    summary = open(paths["summary"], encoding="utf-8").read()
    assert "Known matches" in summary
    assert "CVE-REPORT" in summary


def test_html_escapes_known_match_text(tmp_path):
    result = _known_result(tmp_path)
    result.findings[0].known[0].title = "<script>alert(known)</script>"
    html = build_html(result)
    assert "<script>alert(known)</script>" not in html
    assert "&lt;script&gt;alert(known)&lt;/script&gt;" in html


def test_sarif_known_properties_without_known(tmp_path):
    result = _known_result(tmp_path)
    result.findings[0].known = []
    sarif = build_sarif(result)
    item = sarif["runs"][0]["results"][0]
    assert item["properties"]["known"] == []
    assert "known-vulnerability" not in sarif["runs"][0]["tool"]["driver"]["rules"][0][
        "properties"]["tags"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_known_list_and_stats(capsys):
    assert main(["known", "list", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["entries"] == 5
    assert {entry.get("cve") for entry in payload["entries"]} == {
        "CVE-2023-28755", "CVE-2023-28756", "CVE-2023-36617", None}

    assert main(["known", "stats", "--json"]) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["entries"] == 5
    assert stats["vulnerable_patterns"] == 6

    # --language any must not filter everything out
    assert main(["known", "list", "--language", "any", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["entries"]) == 5


def test_cli_known_match(capsys):
    assert main(["known", "match", PORT_VULNERABLE,
                 "--language", "ruby", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["matches"][0]["cve"] == "CVE-2023-36617"
    assert payload["matches"][0]["kind"] == "exact"
    assert payload["static"]["complexity"] == "polynomial"


def test_cli_known_match_human(capsys):
    assert main(["known", "match", PORT_VULNERABLE, "--language", "ruby"]) == 0
    out = capsys.readouterr().out
    assert "CVE-2023-36617" in out
    assert "exact" in out


def test_cli_known_show(capsys):
    assert main(["known", "show", "CVE-2023-28756", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cve"] == "CVE-2023-28756"
    assert len(payload["patterns"]) == 2


def test_cli_known_check(capsys):
    assert main(["known", "check", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["stats"]["entries"] == 5


def test_cli_known_import(tmp_path, capsys):
    incoming = tmp_path / "incoming.json"
    output = tmp_path / "out.json"
    incoming.write_text(json.dumps({"entries": [_entry(
        "CVE-IMPORTED", cve="CVE-IMPORTED", pattern=r"^(q+)+$")]}))
    assert main(["known", "import", str(incoming), "--output", str(output),
                 "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["entries"] == 6
    database = KnownDatabase.load(str(output))
    assert {entry.id for entry in database.entries} == {
        "CVE-2023-28755", "CVE-2023-28756", "CVE-2023-36617",
        "RDOC-CALL-SEQ-REDOS", "H1-1485717-IPADDR-REDOS", "CVE-IMPORTED"}

    # --empty starts a database that contains only the imported entries
    empty = tmp_path / "empty.json"
    assert main(["known", "import", str(incoming), "--output", str(empty),
                 "--empty", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["stats"]["entries"] == 1
    assert KnownDatabase.load(str(empty)).entries[0].id == "CVE-IMPORTED"

    # a dry run must not create the target
    other = tmp_path / "dry.json"
    assert main(["known", "import", str(incoming), "--output", str(other),
                 "--dry-run", "--json"]) == 0
    assert not other.exists()


def test_cli_known_import_requires_output(tmp_path, capsys, monkeypatch):
    incoming = tmp_path / "incoming.json"
    incoming.write_text(json.dumps({"entries": [_entry("CVE-IMPORTED")]}))
    config = tmp_path / "scanners.yaml"
    config.write_text("known:\n  db: null\n")
    code = main(["known", "import", str(incoming), "--config", str(config),
                 "--json"])
    assert code == 2
    assert "requires" in capsys.readouterr().err


def test_cli_analyze_pattern_includes_known(capsys):
    assert main(["analyze-pattern", PORT_VULNERABLE,
                 "--language", "ruby", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["known"][0]["cve"] == "CVE-2023-36617"


def test_cli_doctor_reports_known_database(capsys):
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "known db" in out
    assert "known entries  5" in out


def test_known_witness_roundtrip(tmp_path):
    db = _database(tmp_path, [_entry(patterns=[{
        "pattern": r"^(a+)+$",
        "witness": {"prefix": "", "pump": "a", "suffix": "!", "kind": "exponential"},
    }])])
    assert db.entries[0].patterns[0].witness["pump"] == "a"
    match = _match(db, r"^(a+)+$")[0]
    assert match.witness == {"prefix": "", "pump": "a", "suffix": "!", "kind": "exponential"}
    serialized = db.to_dict()["entries"][0]["patterns"][0]
    assert serialized["witness"]["suffix"] == "!"


def test_known_witness_rejects_invalid_kind(tmp_path):
    with pytest.raises(ValueError):
        _database(tmp_path, [_entry(patterns=[{
            "pattern": r"^(a+)+$",
            "witness": {"pump": "a", "kind": "catastrophic"},
        }])])


def test_known_witness_is_prepended_to_attack_plans(tmp_path):
    db = _database(tmp_path, [_entry(patterns=[{
        "pattern": r"^(a+)+$",
        "witness": {"prefix": "", "pump": "b", "suffix": "!", "kind": "exponential"},
    }])])
    candidate = make_candidate(r"^(a+)+$")
    scanner = object.__new__(Scanner)
    scanner._inject_known_witnesses([candidate], db, KnownOptions())
    assert candidate.static.attack_plans[0].pump == "b"
    # A second run must not duplicate the same plan.
    scanner._inject_known_witnesses([candidate], db, KnownOptions())
    plans = [(p.prefix, p.pump, p.suffix, p.breaker, p.kind)
             for p in candidate.static.attack_plans]
    assert plans.count(("", "b", "!", "!", "exponential")) == 1


def test_entry_can_disable_core_matching(tmp_path):
    entry = _entry(patterns=[{"pattern": r"\A(0|[1-9]+\d*)\z"}], language="ruby")
    entry["match_core"] = False
    db = _database(tmp_path, [entry])
    # Unrelated polynomial expression must not be linked through the generic core.
    assert _match(db, r"[A-Z]+.*", language="ruby") == []
    # The exact expression still matches.
    matches = _match(db, r"\A(0|[1-9]+\d*)\z", language="ruby")
    assert matches and matches[0].kind == "exact"
