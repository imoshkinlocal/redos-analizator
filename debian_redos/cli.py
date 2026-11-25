"""Command line interface for the Debian ReDoS scanner.

Commands
--------
``scan``             discover packages, extract regexps, analyse and verify
``extract``          only extract regexp candidates (fast, no analysis)
``analyze-pattern``  run the static analyser on one pattern
``verify``           run static analysis + dynamic verification on one pattern
``report``           re-render reports from a stored run
``db``               inspect/prune the SQLite cache
``known``            inspect or match against known ReDoS advisories
``doctor``           show the environment and engine availability

Exit codes: ``0`` success, ``1`` findings at or above ``--fail-on``,
``2`` usage/runtime error.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
from typing import Dict, List, Optional, Sequence

from . import __version__
from .analyzers import heuristics
from .config import Config, load_config
from .core.database import Database
from .core.discovery import Discoverer, DiscoveryOptions
from .core.known import (
    BUNDLED_DB,
    KnownDatabase,
    KnownOptions,
    load_database,
    resolve_database_path,
)
from .core.pipeline import DEFAULT_DB_PATH, Scanner, ScanOptions, collect_candidates
from .dynamic.verifier import VerificationSettings, verify_candidate
from .models import (
    InputControl,
    PackageInfo,
    RegexCandidate,
    ScanResult,
    ScanStats,
    SEVERITY_ORDER,
    StaticAnalysis,
)
from .reports import FORMATS, write_reports
from .reports.summary import format_summary
from .workers.runner import WorkerPool, detect_engine, php_delimited

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG_CANDIDATES = [
    os.path.join("config", "scanners.yaml"),
    os.path.join(PROJECT_ROOT, "config", "scanners.yaml"),
]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _find_config(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        if not os.path.isfile(explicit):
            raise SystemExit(f"config file not found: {explicit}")
        return explicit
    for candidate in DEFAULT_CONFIG_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return None


def _load(args) -> Config:
    path = _find_config(getattr(args, "config", None))
    return load_config(path)


def _db_path(args, config: Config) -> str:
    return (getattr(args, "db", None) or config.get("cache.path")
            or DEFAULT_DB_PATH)


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _echo(args, message: str) -> None:
    if not getattr(args, "quiet", False):
        print(message)


def _severity_gate(result: ScanResult, threshold: Optional[str]) -> int:
    if not threshold or threshold == "none":
        return 0
    limit = SEVERITY_ORDER.get(threshold)
    if limit is None:
        return 0
    for finding in result.findings:
        if SEVERITY_ORDER.get(finding.severity, 0) >= limit:
            return 1
    return 0


def _print_analysis(pattern: str, analysis: StaticAnalysis) -> None:
    print(f"pattern:   {pattern}")
    print(f"status:    {analysis.status}")
    print(f"complexity: {analysis.complexity}")
    print(f"confidence: {analysis.confidence:.2f}")
    print(f"detector:  {analysis.detector}")
    if analysis.normalized_pattern and analysis.normalized_pattern != pattern:
        print(f"normalised: {analysis.normalized_pattern}")
    if analysis.evidence:
        print("evidence:")
        for evidence in analysis.evidence:
            span = f" [{evidence.span[0]}:{evidence.span[1]}]" if evidence.span else ""
            print(f"  - {evidence.rule}{span}: {evidence.message}")
            if evidence.node:
                print(f"    node: {evidence.node}")
    if analysis.attack_plans:
        print("attack plans:")
        for index, plan in enumerate(analysis.attack_plans, 1):
            print(f"  {index}. kind={plan.kind} prefix={plan.prefix!r} pump={plan.pump!r} "
                  f"suffix={plan.suffix!r} breaker={plan.breaker!r}")
    if analysis.notes:
        print("notes:")
        for note in analysis.notes:
            print(f"  - {note}")


def _print_dynamic(analysis) -> None:
    print(f"dynamic:   {analysis.status} ({analysis.growth_class})")
    if analysis.engine:
        print(f"engine:    {analysis.engine} {analysis.engine_version or ''}".rstrip())
    if analysis.growth_slope is not None:
        print(f"slope:     {analysis.growth_slope:.2f}")
    if analysis.max_elapsed_ms is not None:
        print(f"max:       {analysis.max_elapsed_ms:.1f} ms")
    if analysis.timeout_at is not None:
        print(f"timeout:   at {analysis.timeout_at} characters")
    if analysis.trials:
        print("trials:")
        print(f"  {'LENGTH':>8} {'MS':>10}  STATUS")
        for trial in analysis.trials:
            print(f"  {trial.input_length:>8} {trial.elapsed_ms:>10.2f}  {trial.status}")
    if analysis.evidence:
        print("evidence:")
        for evidence in analysis.evidence:
            print(f"  - {evidence}")
    if analysis.notes:
        print("notes:")
        for note in analysis.notes:
            print(f"  - {note}")


def _print_known(matches, title: str = "known") -> None:
    if not matches:
        print(f"{title}: no match")
        return
    print(f"{title}:")
    for index, match in enumerate(matches, 1):
        label = match.cve or match.id
        print(f"  {index}. {label} ({match.kind}, score={match.score:.2f}, "
              f"confidence={match.confidence})")
        print(f"     {match.title}")
        print(f"     types: {', '.join(match.match_types)}"
              + (" [package only]" if not match.pattern_matched else ""))
        if match.matched_pattern and match.kind != "exact":
            preview = match.matched_pattern.replace("\n", "\\n")
            if len(preview) > 160:
                preview = preview[:157] + "..."
            print(f"     pattern: {preview}")
        for reference in match.references[:3]:
            print(f"     ref: {reference}")
        for note in match.notes[:3]:
            print(f"     note: {note}")


def _candidate(pattern: str, language: str, flags: str = "") -> RegexCandidate:
    raw_pattern = None
    if language == "php":
        raw_pattern = pattern if _looks_php_delimited(pattern) else php_delimited(pattern, flags)
    return RegexCandidate(
        package="<command-line>",
        version=__version__,
        language=language,
        file="<command-line>",
        line=1,
        function="<command-line>",
        pattern=pattern,
        dialect=language,
        flags=flags,
        input_control=InputControl.USER_LOCAL.value,
        raw_pattern=raw_pattern,
        engine_hint=None,
        extractor="cli",
    )


_PHP_DELIMITER_PAIRS = {"(": ")", "[": "]", "{": "}", "<": ">"}


def _looks_php_delimited(pattern: str) -> bool:
    if len(pattern) < 3:
        return False
    opener = pattern[0]
    if opener.isalnum() or opener in "\\ \t\r\n":
        return False
    closer = _PHP_DELIMITER_PAIRS.get(opener, opener)
    # the delimiter must close the pattern (modifiers may follow)
    for index in range(len(pattern) - 1, 0, -1):
        ch = pattern[index]
        if ch.isalpha():
            continue
        return ch == closer
    return False


def _verify(pattern: str, language: str, flags: str, config: Config, args):
    candidate = _candidate(pattern, language, flags)
    candidate.static = heuristics.analyze(
        pattern, dialect=language, flags=flags,
        max_pattern_length=int(config.limit("max_pattern_length") or 4096),
        max_candidates=int(config.get("dynamic.max_candidates_per_finding", 4)),
    )
    settings = VerificationSettings.from_config(config)
    if getattr(args, "timeout", None):
        settings.timeout_s = float(args.timeout)
    if getattr(args, "budget", None):
        settings.budget_s = float(args.budget)
    if getattr(args, "max_candidates", None):
        settings.max_candidates = int(args.max_candidates)
    pool = WorkerPool(config)
    analysis = verify_candidate(candidate, candidate.static, pool, settings, log=None)
    return candidate.static, analysis


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------

def command_scan(args) -> int:
    config = _load(args)
    paths = args.paths or ["."]
    formats = args.format or None
    options = ScanOptions(
        paths=paths,
        mode=args.mode,
        jobs=max(1, args.jobs),
        dynamic_jobs=max(1, args.dynamic_jobs),
        dynamic=not args.no_dynamic,
        languages=args.language or None,
        min_severity=args.min_severity,
        write_reports=not args.no_reports,
        output_dir=args.output_dir,
        formats=formats,
        unpack_dsc=(True if args.unpack_dsc else None),
        max_candidates=args.max_candidates,
    )
    scanner = Scanner(config, db_path=_db_path(args, config), log=None if args.quiet else _log)
    try:
        result = scanner.scan(options)
    finally:
        scanner.close()
    if not args.quiet:
        print(format_summary(result))
    threshold = args.fail_on or config.get("severity.exit_code_on", "high")
    return _severity_gate(result, threshold)


def command_extract(args) -> int:
    config = _load(args)
    discovery_options = DiscoveryOptions.from_config(config)
    discoverer = Discoverer(discovery_options)
    packages = discoverer.discover([args.path])
    candidates: List[RegexCandidate] = []
    for package in packages:
        if not package.directory or not os.path.isdir(package.directory):
            continue
        files = [f for f in discoverer.files(package)
                 if (not args.language or f.language in args.language)
                 and config.language_enabled(f.language)]
        candidates.extend(collect_candidates(package, files, jobs=args.jobs))
    if args.limit:
        candidates = candidates[: args.limit]
    if args.json:
        json.dump([c.to_dict() for c in candidates], sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0
    print(f"packages:   {len(packages)}")
    print(f"candidates: {len(candidates)}")
    print(f"  {'LANGUAGE':<9} {'LOCATION':<45} PATTERN")
    for candidate in candidates:
        location = f"{candidate.package}/{candidate.file}:{candidate.line}"
        if len(location) > 45:
            location = "..." + location[-42:]
        pattern = (candidate.pattern or "<dynamic>").replace("\n", "\\n")
        if len(pattern) > 60:
            pattern = pattern[:57] + "..."
        print(f"  {candidate.language:<9} {location:<45} {pattern}")
    return 0


def command_analyze(args) -> int:
    config = _load(args)
    dynamic = None
    if args.dynamic:
        analysis, dynamic = _verify(args.pattern, args.language, args.flags or "",
                                    config, args)
    else:
        analysis = heuristics.analyze(
            args.pattern,
            dialect=args.language,
            flags=args.flags or "",
            max_pattern_length=int(config.limit("max_pattern_length") or 4096),
            max_candidates=int(config.get("dynamic.max_candidates_per_finding", 4)),
        )
    if args.json:
        payload: Dict = {"pattern": args.pattern, "language": args.language,
                         "static": analysis.to_dict()}
        if dynamic is not None:
            payload["dynamic"] = dynamic.to_dict()
        known_db = load_database(config)
        if known_db is not None:
            payload["known"] = [
                match.to_dict() for match in known_db.match(
                    args.pattern, args.language, args.flags or "",
                    static=analysis)
            ]
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0
    _print_analysis(args.pattern, analysis)
    if dynamic is not None:
        print("")
        _print_dynamic(dynamic)
    known_db = load_database(config)
    if known_db is not None:
        print("")
        _print_known(known_db.match(args.pattern, args.language,
                                    args.flags or "", static=analysis))
    return 0


def command_verify(args) -> int:
    config = _load(args)
    static, dynamic = _verify(args.pattern, args.language, args.flags or "", config, args)
    known_db = load_database(config)
    matches = (known_db.match(args.pattern, args.language, args.flags or "",
                              static=static) if known_db is not None else [])
    if args.json:
        payload = {"pattern": args.pattern, "language": args.language,
                   "static": static.to_dict(), "dynamic": dynamic.to_dict()}
        if known_db is not None:
            payload["known"] = [match.to_dict() for match in matches]
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
        return 0
    _print_analysis(args.pattern, static)
    print("")
    _print_dynamic(dynamic)
    if known_db is not None:
        print("")
        _print_known(matches)
    return 0


def command_report(args) -> int:
    config = _load(args)
    db = Database(_db_path(args, config))
    try:
        meta = db.run_meta(args.run_id)
        if meta is None:
            print("no stored run found", file=sys.stderr)
            return 2
        findings = db.query_findings(run_id=meta["id"],
                                     min_severity=args.min_severity)
        packages = db.load_packages()
        stats_data = meta.get("stats_json")
        stats = ScanStats.from_dict(stats_data) if isinstance(stats_data, dict) else ScanStats()
        result = ScanResult(
            run_id=meta["id"],
            started_at=meta.get("started_at") or "",
            finished_at=meta.get("finished_at") or "",
            mode=meta.get("mode") or "full",
            packages=packages,
            findings=findings,
            stats=stats,
            notes=meta.get("notes") or [],
        )
    finally:
        db.close()
    formats = args.format or [name for name in FORMATS
                              if config.get(f"output.{name}", True)]
    paths = write_reports(result, args.output_dir or config.output_dir, formats=formats)
    if not args.quiet:
        for name, path in paths.items():
            print(f"{name:<10} {path}")
        print("")
        print(format_summary(result))
    return 0


def command_db(args) -> int:
    config = _load(args)
    path = _db_path(args, config)
    if args.db_command == "stats":
        db = Database(path)
        try:
            print(json.dumps(db.stats(), indent=2, ensure_ascii=False))
        finally:
            db.close()
        return 0
    if args.db_command == "prune":
        db = Database(path)
        try:
            removed = db.prune(keep_runs=max(0, args.keep))
            print(f"removed {removed} run(s); kept {max(0, args.keep)}")
        finally:
            db.close()
        return 0
    if args.db_command == "clear-cache":
        db = Database(path)
        try:
            db.clear_cache()
            print("analysis and dynamic caches cleared")
        finally:
            db.close()
        return 0
    if args.db_command == "runs":
        db = Database(path)
        try:
            rows = db.connection.execute(
                "SELECT id, started_at, finished_at, mode FROM scan_runs "
                "ORDER BY started_at DESC LIMIT 50"
            ).fetchall()
            for row in rows:
                print(f"{row['id']}  {row['started_at']}  {row['mode']}  "
                      f"{'finished' if row['finished_at'] else 'running'}")
        finally:
            db.close()
        return 0
    return 2


def _known_db_path(args, config) -> str:
    return getattr(args, "known_db", None) or config.get("known.db") or BUNDLED_DB


def _load_known(args, config) -> KnownDatabase:
    return KnownDatabase.load(_known_db_path(args, config))


def command_known(args) -> int:
    config = _load(args)
    if args.known_command == "import":
        return _known_import(args, config)

    database = _load_known(args, config)
    if args.known_command == "list":
        entries = database.entries
        if getattr(args, "language", None) and args.language != "any":
            entries = [entry for entry in entries
                       if entry.language in (args.language, "any")]
        if getattr(args, "severity", None):
            entries = [entry for entry in entries
                       if entry.severity == args.severity]
        if getattr(args, "cve", None):
            needle = args.cve.lower()
            entries = [entry for entry in entries
                       if needle in (entry.cve or "").lower()
                       or needle in entry.id.lower()]
        if args.json:
            payload = {
                "source": database.source,
                "schema_version": database.schema_version,
                "updated": database.updated,
                "stats": database.stats(),
                "entries": [entry.to_dict() for entry in entries],
            }
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return 0
        print(f"source:  {database.source or '<none>'}")
        print(f"updated: {database.updated or '-'}  entries: {len(entries)}")
        print(f"  {'ID':<20} {'CVE':<18} {'LANG':<7} {'SEV':<8} "
              f"{'PAT':>4}  TITLE")
        for entry in entries:
            title = entry.title.replace("\n", " ")
            if len(title) > 52:
                title = title[:49] + "..."
            print(f"  {entry.id:<20} {(entry.cve or '-'):<18} "
                  f"{entry.language:<7} {entry.severity:<8} "
                  f"{len(entry.patterns):>4}  {title}")
        return 0

    if args.known_command == "show":
        entry = next((entry for entry in database.entries
                      if entry.id.lower() == args.identifier.lower()), None)
        if entry is None:
            print(f"no known entry with id {args.identifier!r}", file=sys.stderr)
            return 2
        if args.json:
            json.dump(entry.to_dict(), sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return 0
        print(f"id:         {entry.id}")
        print(f"cve:        {entry.cve or '-'}")
        print(f"title:      {entry.title}")
        print(f"language:   {entry.language}")
        print(f"severity:   {entry.severity}")
        print(f"packages:   {', '.join(entry.packages) or '-'}")
        print(f"affected:   {', '.join(entry.affected) or '-'}")
        if entry.references:
            print("references:")
            for reference in entry.references:
                print(f"  - {reference}")
        if entry.notes:
            print("notes:")
            for note in entry.notes:
                print(f"  - {note}")
        print(f"patterns:   {len(entry.patterns)}")
        for index, pattern in enumerate(entry.patterns, 1):
            body = pattern.pattern if args.full else pattern.pattern.replace("\n", "\\n")
            if not args.full and len(body) > 220:
                body = body[:217] + "..."
            print(f"  {index}. status={pattern.status} flags={pattern.flags or '-'}")
            print(f"     {body}")
            if pattern.note:
                print(f"     note: {pattern.note}")
        return 0

    if args.known_command == "match":
        static = heuristics.analyze(
            args.pattern, dialect=args.language, flags=args.flags or "",
            max_pattern_length=int(config.limit("max_pattern_length") or 4096),
            max_candidates=int(config.get("dynamic.max_candidates_per_finding", 4)),
        )
        options = KnownOptions.from_config(config)
        if args.min_score is not None:
            options.min_score = float(args.min_score)
        matches = database.match(args.pattern, args.language, args.flags or "",
                                 package=args.package or "", static=static,
                                 options=options)
        if args.json:
            json.dump({
                "pattern": args.pattern,
                "language": args.language,
                "flags": args.flags or "",
                "static": static.to_dict(),
                "matches": [match.to_dict() for match in matches],
            }, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return 0
        print(f"pattern:  {args.pattern}")
        print(f"static:   {static.status} / {static.complexity}")
        print("")
        _print_known(matches)
        return 0

    if args.known_command == "stats":
        stats = database.stats()
        if args.json:
            json.dump(stats, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return 0
        print(f"source:             {stats['source'] or '<none>'}")
        print(f"schema version:     {stats['schema_version']}")
        print(f"updated:            {stats['updated'] or '-'}")
        print(f"entries:            {stats['entries']}")
        print(f"patterns:           {stats['patterns']} "
              f"({stats['vulnerable_patterns']} vulnerable)")
        print("by language:        " + ", ".join(
            f"{name}={count}" for name, count in sorted(stats["by_language"].items())))
        print("by severity:        " + ", ".join(
            f"{name}={count}" for name, count in sorted(stats["by_severity"].items())))
        print("cves:               " + (", ".join(stats["cves"]) or "-"))
        print("packages:           " + (", ".join(stats["packages"]) or "-"))
        return 0

    if args.known_command == "check":
        stats = database.stats()
        if args.json:
            payload = {"ok": True, "stats": stats}
            json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return 0
        print(f"OK  {stats['source'] or '<none>'}")
        print(f"    {stats['entries']} entries, {stats['patterns']} patterns "
              f"({stats['vulnerable_patterns']} vulnerable)")
        print(f"    schema {stats['schema_version']}, updated {stats['updated'] or '-'}")
        for note in database.notes:
            print(f"    note: {note}")
        return 0

    return 2


def _known_import(args, config: Config) -> int:
    incoming = KnownDatabase.load(args.file)
    output = args.output or config.get("known.db")
    if not output:
        print("import requires --output or a known.db path in the configuration",
              file=sys.stderr)
        return 2
    base = KnownDatabase([], source=output)
    if os.path.isfile(output):
        base = KnownDatabase.load(output)
    elif not getattr(args, "empty", False):
        # Extend the bundled advisories by default so that a local database
        # does not silently lose the shipped CVE entries.
        base = KnownDatabase.bundled()
    base.source = output
    merged = base.merge(incoming)
    if args.json:
        json.dump({"output": output, "dry_run": bool(args.dry_run),
                   "stats": merged.stats()}, sys.stdout,
                  ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"input:   {args.file} ({len(incoming.entries)} entries)")
        print(f"output:  {output} ({len(merged.entries)} entries)")
        print(f"updated: {merged.updated or '-'}")
    if args.dry_run:
        if not args.json:
            print("dry-run: no file written")
        return 0
    directory = os.path.dirname(os.path.abspath(output))
    os.makedirs(directory, exist_ok=True)
    temporary = output + ".tmp"
    with open(temporary, "w", encoding="utf-8") as fh:
        json.dump(merged.to_dict(), fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    os.replace(temporary, output)
    if not args.json:
        print("written")
    return 0


def command_doctor(args) -> int:
    config = _load(args)
    print(f"debian-redos   {__version__}")
    print(f"python         {platform.python_version()} ({sys.executable})")
    print(f"ruby           {_tool_version(['ruby', '--version'])}")
    print(f"php            {_tool_version(['php', '-v'])}")
    print(f"docker         {_tool_version(['docker', '--version'])}")
    print(f"dpkg-source    {_tool_version(['dpkg-source', '--version'])}")
    print(f"platform       {platform.platform()}")
    path = _db_path(args, config)
    print(f"cache db       {path}")
    print(f"config         {_find_config(getattr(args, 'config', None)) or '<built-in defaults>'}")
    print(f"config hash    {config.config_hash}")
    known_path = resolve_database_path(config)
    print(f"known db       {known_path}")
    try:
        known_database = KnownDatabase.load(known_path)
        print(f"known entries  {len(known_database.entries)} "
              f"(updated {known_database.updated or '-'})")
    except (OSError, ValueError) as exc:
        print(f"known entries  NOT LOADED ({exc})")
    print("")
    print("languages / engines:")
    pool = WorkerPool(config)
    for language in ("python", "ruby", "php"):
        enabled = config.language_enabled(language)
        engine = detect_engine(language, config) if enabled else None
        if not enabled:
            print(f"  {language:<7} disabled in config")
            continue
        if engine is None:
            note = pool.unavailable_note(language)
            print(f"  {language:<7} NO ENGINE ({note})")
            continue
        print(f"  {language:<7} {engine.label} {engine.version}")
        for note in engine.notes:
            print(f"          note: {note}")
    php = shutil.which("php")
    if php:
        print("")
        print("PHP fallback: the native interpreter is preferred; Docker is used "
              "only when php is missing and the image is available.")
        print(f"  php_delimited('^a+$', 'i') -> {php_delimited('^a+$', 'i')!r}")
    print("")
    print("external detectors (optional):")
    for tool in ("regexploit", "redoshunter", "codeql"):
        print(f"  {tool:<12} {shutil.which(tool) or 'not installed'}")
    return 0


def _tool_version(command: Sequence[str]) -> str:
    try:
        import subprocess
        proc = subprocess.run(command, capture_output=True, text=True, timeout=15)
    except Exception:
        return "not available"
    text = (proc.stdout or proc.stderr or "").strip().splitlines()
    return text[0][:120] if text else "not available"


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def _add_common_options(parser: argparse.ArgumentParser) -> None:
    """Allow --config/--db after the subcommand as well as before it."""
    parser.add_argument("--config", default=argparse.SUPPRESS,
                        help="path to scanners.yaml")
    parser.add_argument("--db", default=argparse.SUPPRESS,
                        help=f"SQLite cache path (default: {DEFAULT_DB_PATH})")


def _add_known_db_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--known-db", default=argparse.SUPPRESS,
                        help="path to the JSON known-ReDoS database "
                             f"(default: configured path or {BUNDLED_DB})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="debian-redos",
        description="Two-stage ReDoS scanner for Debian source packages "
                    "(Python, Ruby, PHP).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  debian-redos scan /path/to/pkg-1.0 --jobs 4 --output-dir reports\n"
            "  debian-redos scan --mode incremental /path/to/pkg-1.0\n"
            "  debian-redos analyze-pattern '^(a+)+$' --language python\n"
            "  debian-redos verify '^(a+)+$' --language python\n"
            "  debian-redos report --run-id run-abc123\n"
            "  debian-redos db stats\n"
            "  debian-redos known match '(a|aa)+' --language ruby --package ruby3.1\n"
            "  debian-redos known list --language ruby\n"
        ))
    parser.add_argument("--version", action="version", version=f"debian-redos {__version__}")
    parser.add_argument("--config", help="path to scanners.yaml")
    parser.add_argument("--db", help=f"SQLite cache path (default: {DEFAULT_DB_PATH})")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one or more packages or source trees")
    _add_common_options(scan)
    scan.add_argument("paths", nargs="*", help="package tree, .dsc or directory of trees")
    scan.add_argument("--mode", choices=["full", "incremental"], default="full")
    scan.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1),
                      help="extraction processes (default: min(8, CPUs))")
    scan.add_argument("--dynamic-jobs", type=int, default=1,
                      help="concurrent engine sessions (keep at 1 for stable timings)")
    scan.add_argument("--static", dest="no_dynamic", action="store_true",
                      help="skip the dynamic stage")
    scan.add_argument("--no-dynamic", dest="no_dynamic", action="store_true",
                      help=argparse.SUPPRESS)
    scan.add_argument("--language", action="append",
                      choices=["python", "ruby", "php"], help="restrict languages")
    scan.add_argument("--min-severity", choices=list(SEVERITY_ORDER),
                      help="minimum severity to report")
    scan.add_argument("--fail-on", choices=list(SEVERITY_ORDER) + ["none"],
                      help="exit 1 when a finding reaches this severity")
    scan.add_argument("--output-dir", help="report directory")
    scan.add_argument("--format", action="append", choices=list(FORMATS),
                      help="report format (repeatable)")
    scan.add_argument("--no-reports", action="store_true")
    scan.add_argument("--unpack-dsc", action="store_true",
                      help="unpack .dsc files with dpkg-source")
    scan.add_argument("--max-candidates", type=int,
                      help="attack shapes tested per pattern")
    scan.add_argument("--quiet", action="store_true")
    scan.set_defaults(func=command_scan)

    extract = sub.add_parser("extract", help="extract regexp candidates only")
    _add_common_options(extract)
    extract.add_argument("path", nargs="?", default=".")
    extract.add_argument("--language", action="append",
                         choices=["python", "ruby", "php"])
    extract.add_argument("--jobs", type=int, default=1)
    extract.add_argument("--limit", type=int, default=0)
    extract.add_argument("--json", action="store_true")
    extract.set_defaults(func=command_extract)

    analyze = sub.add_parser("analyze-pattern", help="static analysis of one pattern")
    _add_common_options(analyze)
    analyze.add_argument("pattern")
    analyze.add_argument("--language", "--dialect", dest="language",
                         choices=["python", "ruby", "php"], default="python")
    analyze.add_argument("--flags", default="")
    analyze.add_argument("--dynamic", action="store_true",
                         help="also run the dynamic verifier")
    analyze.add_argument("--timeout", type=float)
    analyze.add_argument("--budget", type=float)
    analyze.add_argument("--max-candidates", type=int)
    analyze.add_argument("--json", action="store_true")
    analyze.set_defaults(func=command_analyze)

    verify = sub.add_parser("verify", help="static + dynamic verification of one pattern")
    _add_common_options(verify)
    verify.add_argument("pattern")
    verify.add_argument("--language", "--dialect", dest="language",
                        choices=["python", "ruby", "php"], default="python")
    verify.add_argument("--flags", default="")
    verify.add_argument("--timeout", type=float)
    verify.add_argument("--budget", type=float)
    verify.add_argument("--max-candidates", type=int)
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(func=command_verify)

    report = sub.add_parser("report", help="re-render reports for a stored run")
    _add_common_options(report)
    report.add_argument("--run-id", help="run id (default: the latest finished run)")
    report.add_argument("--output-dir")
    report.add_argument("--format", action="append", choices=list(FORMATS))
    report.add_argument("--min-severity", choices=list(SEVERITY_ORDER))
    report.add_argument("--quiet", action="store_true")
    report.set_defaults(func=command_report)

    db = sub.add_parser("db", help="inspect or prune the SQLite cache")
    _add_common_options(db)
    db_sub = db.add_subparsers(dest="db_command", required=True)
    _add_common_options(db_sub.add_parser("stats", help="counts by table, verdict and severity"))
    prune = db_sub.add_parser("prune", help="drop old runs")
    _add_common_options(prune)
    prune.add_argument("--keep", type=int, default=5)
    _add_common_options(db_sub.add_parser("clear-cache",
                                          help="clear analysis and dynamic caches"))
    _add_common_options(db_sub.add_parser("runs", help="list stored runs"))
    db.set_defaults(func=command_db)

    known = sub.add_parser("known", help="inspect or match against known ReDoS advisories")
    _add_common_options(known)
    _add_known_db_option(known)
    known_sub = known.add_subparsers(dest="known_command", required=True)

    known_list = known_sub.add_parser("list", help="list known advisory entries")
    _add_common_options(known_list)
    _add_known_db_option(known_list)
    known_list.add_argument("--language", choices=["python", "ruby", "php", "any"])
    known_list.add_argument("--severity", choices=list(SEVERITY_ORDER))
    known_list.add_argument("--cve", help="filter by CVE id substring")
    known_list.add_argument("--json", action="store_true")

    known_show = known_sub.add_parser("show", help="show one known advisory")
    _add_common_options(known_show)
    _add_known_db_option(known_show)
    known_show.add_argument("identifier")
    known_show.add_argument("--full", action="store_true",
                            help="print full pattern sources")
    known_show.add_argument("--json", action="store_true")

    known_match = known_sub.add_parser(
        "match", help="compare a pattern with the known database")
    _add_common_options(known_match)
    _add_known_db_option(known_match)
    known_match.add_argument("pattern")
    known_match.add_argument("--language", "--dialect", dest="language",
                             choices=["python", "ruby", "php"], default="ruby")
    known_match.add_argument("--flags", default="")
    known_match.add_argument("--package", default="",
                             help="source package name for package-level advisories")
    known_match.add_argument("--min-score", type=float,
                             help="minimum fuzzy similarity (0..1)")
    known_match.add_argument("--json", action="store_true")

    known_stats = known_sub.add_parser("stats", help="database statistics")
    _add_common_options(known_stats)
    _add_known_db_option(known_stats)
    known_stats.add_argument("--json", action="store_true")

    known_check = known_sub.add_parser("check", help="validate the database")
    _add_common_options(known_check)
    _add_known_db_option(known_check)
    known_check.add_argument("--json", action="store_true")

    known_import = known_sub.add_parser("import", help="merge entries from a JSON file")
    _add_common_options(known_import)
    known_import.add_argument("file")
    known_import.add_argument("--output", help="target JSON database")
    known_import.add_argument("--empty", action="store_true",
                              help="start from an empty database instead of "
                                   "the bundled advisories")
    known_import.add_argument("--dry-run", action="store_true")
    known_import.add_argument("--json", action="store_true")

    known.set_defaults(func=command_known)

    doctor = sub.add_parser("doctor", help="environment and engine availability")
    _add_common_options(doctor)
    doctor.set_defaults(func=command_doctor)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
