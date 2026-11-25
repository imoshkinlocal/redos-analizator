"""Scan pipeline: discovery -> extraction -> static -> dynamic -> correlate.

The pipeline is deliberately explicit.  Each stage can be driven from the CLI
(``scan``, ``extract``, ``analyze-pattern``, ``verify``) and every expensive
result is cached in SQLite:

* static analysis is keyed by pattern semantics + detector configuration,
* dynamic verification additionally includes the engine identity, the attack
  plans and the measurement settings,
* unchanged files in ``incremental`` mode reuse the previous run's findings.

No code from the scanned package is ever executed: only extracted pattern
strings and generated inputs are handed to the language workers.
"""

from __future__ import annotations

import os
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .. import __version__
from ..analyzers import heuristics
from ..config import Config
from ..dynamic.verifier import VerificationSettings, verify_candidate
from ..extractors import extract_file
from ..models import (
    AttackWitness,
    DynamicAnalysis,
    DynamicStatus,
    Finding,
    PackageInfo,
    RegexCandidate,
    ScanResult,
    ScanStats,
    SourceFile,
    StaticAnalysis,
    stable_hash,
)
from ..workers.runner import WorkerPool
from .correlate import CorrelateOptions, CveMap, correlate
from .database import Database, utcnow
from .discovery import Discoverer, DiscoveryOptions
from .known import KnownDatabase, KnownOptions, apply_known, load_database

STATIC_CACHE_VERSION = "static-v1"
DYNAMIC_CACHE_VERSION = "dynamic-v4"

DEFAULT_DB_PATH = os.path.join(".redos-cache", "redos.sqlite3")


@dataclass
class ScanOptions:
    paths: List[str] = field(default_factory=list)
    mode: str = "full"                  # full | incremental | static
    jobs: int = 1                       # extraction/static workers
    dynamic_jobs: int = 1               # concurrent engine sessions
    dynamic: bool = True
    languages: Optional[List[str]] = None
    min_severity: Optional[str] = None
    write_reports: bool = True
    output_dir: Optional[str] = None
    formats: Optional[List[str]] = None
    unpack_dsc: Optional[bool] = None
    max_candidates: Optional[int] = None


def _extract_task(args: Tuple[str, str, str, str, str, int]) -> List[RegexCandidate]:
    package, version, rel_path, abspath, language, max_bytes = args
    return extract_file(package, version, rel_path, abspath, language=language,
                        max_bytes=max_bytes)


class Scanner:
    def __init__(self, config: Optional[Config] = None,
                 db_path: Optional[str] = None, log=None):
        self.config = config or Config({})
        self.db_path = db_path or self.config.get("cache.path") or DEFAULT_DB_PATH
        self._log = log
        self._db: Optional[Database] = None

    # -- logging ------------------------------------------------------------
    def log(self, message: str) -> None:
        if self._log is not None:
            self._log(message)

    # -- public API ---------------------------------------------------------
    def scan(self, options: Optional[ScanOptions] = None) -> ScanResult:
        options = options or ScanOptions()
        started = time.monotonic()
        started_at = utcnow()
        config_hash = self.config.config_hash

        db = Database(self.db_path)
        self._db = db
        previous = db.previous_run()
        incremental = (options.mode == "incremental" and previous is not None
                       and previous.get("config_hash") == config_hash)
        if options.mode == "incremental" and not incremental:
            self.log("incremental requested but no compatible previous run; "
                     "falling back to a full scan")

        stats = ScanStats()
        notes: List[str] = [f"debian-redos {__version__}"]

        discovery_options = DiscoveryOptions.from_config(self.config)
        if options.unpack_dsc is not None:
            discovery_options.unpack_dsc = options.unpack_dsc
        discoverer = Discoverer(discovery_options)
        packages = [p for p in discoverer.discover(options.paths)
                    if self._package_enabled(p, options.languages)]
        notes.extend(discoverer.notes)
        stats.packages = len(packages)
        if not packages:
            notes.append("no package source tree found in the given paths")
        db.save_packages(packages)

        run_id = db.start_run(options.mode, config_hash,
                              labels={"packages": [p.key for p in packages],
                                      "tool": __version__})

        settings = VerificationSettings.from_config(self.config)
        if options.max_candidates is not None:
            settings.max_candidates = max(1, options.max_candidates)
        known_db = load_database(self.config, self.log)
        known_options = KnownOptions.from_config(self.config)
        if known_db is not None:
            notes.append(
                f"known database: {len(known_db.entries)} advisory entr"
                f"{'y' if len(known_db.entries) == 1 else 'ies'}"
            )
        pool: Optional[WorkerPool] = None
        if options.dynamic and options.mode != "static" and self.config.get("dynamic.enabled", True):
            pool = WorkerPool(self.config)
        else:
            notes.append("dynamic stage disabled for this run")

        all_candidates: List[RegexCandidate] = []
        reused_findings: List[Finding] = []
        max_bytes = 4 * 1024 * 1024

        for package in packages:
            if not package.directory or not os.path.isdir(package.directory):
                notes.append(
                    f"{package.name}: source tree not available "
                    f"({package.directory or 'dsc not unpacked'}); skipped"
                )
                continue
            files = [f for f in discoverer.files(package)
                     if self._language_enabled(f.language)
                     and (not options.languages or f.language in options.languages)]
            stats.files += len(files)
            if not files:
                continue

            reused_paths = set()
            if incremental:
                for item in files:
                    if db.file_is_unchanged(package.name, package.version,
                                            item.path, item.sha256):
                        reused_paths.add(item.path)
            db.save_files(files)

            if reused_paths:
                reused = db.findings_for_files(package.name, package.version,
                                               sorted(reused_paths),
                                               run_id=previous["id"])
                for finding in reused:
                    finding.run_id = run_id
                    apply_known(finding, known_db, known_options)
                    reused_findings.append(finding)
                stats.files_skipped_cached += len(reused_paths)
                self.log(f"{package.key}: reusing findings for "
                         f"{len(reused_paths)}/{len(files)} unchanged files")

            pending = [f for f in files if f.path not in reused_paths]
            candidates = self._extract(package, pending, options.jobs, max_bytes)
            stats.files_scanned += len(pending)
            stats.candidates += len(candidates)
            self._analyze_static(candidates, config_hash)
            all_candidates.extend(candidates)

        suspicious = [c for c in all_candidates if c.static and c.static.suspicious]
        stats.static_suspicious = len(suspicious)
        stats.unique_patterns = len({
            (c.pattern_hash or c.cache_key) for c in all_candidates})

        if pool is not None:
            if known_db is not None:
                self._inject_known_witnesses(suspicious, known_db, known_options)
            self.log(f"dynamic verification for {len(suspicious)} suspicious candidate(s)")
            self._verify_batch(suspicious, pool, settings, db, config_hash,
                               options.dynamic_jobs, stats)
        else:
            for candidate in suspicious:
                candidate.dynamic = DynamicAnalysis(
                    status=DynamicStatus.SKIPPED.value,
                    notes=["dynamic stage disabled"],
                )

        correlator_options = CorrelateOptions(
            cve_map=self._load_cve_map(),
            known_db=known_db,
            known_options=known_options,
            report_safe=bool(self.config.get("static.report_safe", False)),
            min_severity=(options.min_severity
                          or self.config.get("static.min_severity_to_report", "info")
                          or "info"),
        )
        by_package: Dict[str, List[RegexCandidate]] = {}
        for candidate in all_candidates:
            by_package.setdefault(candidate.package, []).append(candidate)
        findings: List[Finding] = list(reused_findings)
        created_at = utcnow()
        for package_name, candidates in by_package.items():
            version = candidates[0].version if candidates else ""
            findings.extend(correlate(candidates, package=package_name, version=version,
                                      run_id=run_id, options=correlator_options,
                                      created_at=created_at))
        findings.sort(key=lambda f: f.sort_key)

        stats.confirmed = sum(1 for f in findings
                              if f.verdict in ("confirmed", "exploitable"))
        stats.exploitable = sum(1 for f in findings if f.verdict == "exploitable")
        stats.needs_review = sum(1 for f in findings if f.verdict == "needs_review")
        stats.informational = sum(1 for f in findings if f.verdict == "informational")
        stats.known_matched = sum(1 for f in findings if f.known)
        stats.duration_seconds = round(time.monotonic() - started, 3)

        db.save_findings(findings)
        db.finish_run(run_id, stats, notes)

        result = ScanResult(
            run_id=run_id,
            started_at=started_at,
            finished_at=utcnow(),
            mode=options.mode,
            packages=packages,
            findings=findings,
            stats=stats,
            config=self.config.to_dict(),
            notes=notes,
        )

        if options.write_reports:
            from ..reports import write_reports

            formats = options.formats or self._enabled_formats()
            output_dir = options.output_dir or self.config.output_dir
            paths = write_reports(result, output_dir, formats=formats)
            result.notes.append("reports: " + ", ".join(sorted(paths.values())))
            self.log("reports written to " + output_dir)
        return result

    # -- stages -------------------------------------------------------------
    def _extract(self, package: PackageInfo, files: Sequence[SourceFile],
                 jobs: int, max_bytes: int) -> List[RegexCandidate]:
        if not files:
            return []
        tasks = [(package.name, package.version, item.path, item.abspath,
                  item.language, max_bytes) for item in files]
        self.log(f"{package.key}: extracting from {len(tasks)} file(s)")
        if jobs <= 1 or len(tasks) == 1:
            out: List[RegexCandidate] = []
            for task in tasks:
                out.extend(_extract_task(task))
            return out
        out = []
        with ProcessPoolExecutor(max_workers=max(1, jobs)) as pool:
            for chunk in pool.map(_extract_task, tasks, chunksize=4):
                out.extend(chunk)
        return out

    def _analyze_static(self, candidates: Sequence[RegexCandidate],
                        config_hash: str) -> None:
        max_length = int(self.config.limit("max_pattern_length") or 4096)
        max_plans = int(self.config.get("dynamic.max_candidates_per_finding", 4))
        db = self._db
        for candidate in candidates:
            key = stable_hash(
                STATIC_CACHE_VERSION, config_hash, candidate.dialect,
                "".join(sorted(set(candidate.flags or ""))),
                candidate.pattern_hash or "<dynamic>", str(max_length), str(max_plans),
            )
            if db is not None:
                cached = db.cache_get("analysis_cache", key)
                if cached is not None:
                    candidate.static = StaticAnalysis.from_dict(cached)
                    continue
            analysis = heuristics.analyze(
                candidate.pattern,
                dialect=candidate.dialect,
                flags=candidate.flags or "",
                max_pattern_length=max_length,
                max_candidates=max_plans,
                source_type=candidate.source_type,
            )
            candidate.static = analysis
            if db is not None:
                db.cache_put("analysis_cache", key, analysis.to_dict())

    def _inject_known_witnesses(self, candidates: Sequence[RegexCandidate],
                                known_db, known_options) -> None:
        """Prepend advisory-provided attack plans to suspicious candidates.

        The heuristics generate a witness from the shape of the expression,
        which is good enough for small patterns but can miss the exact
        invalid input that a published advisory used (for example the large
        RFC 3986 expression behind CVE-2023-28755).  When the known database
        carries a witness, the dynamic stage should try it first.
        """
        for candidate in candidates:
            if not candidate.static or not candidate.pattern:
                continue
            try:
                matches = known_db.match(
                    candidate.pattern, candidate.dialect, candidate.flags or "",
                    package=candidate.package, static=candidate.static,
                    options=known_options,
                )
            except Exception:
                continue
            for match in matches:
                witness = match.witness
                if not witness:
                    continue
                try:
                    plan = AttackWitness(**witness)
                except TypeError:
                    continue
                if plan.kind not in ("exponential", "polynomial"):
                    plan.kind = "exponential"
                if any(self._same_plan(plan, existing)
                       for existing in candidate.static.attack_plans):
                    continue
                candidate.static.attack_plans.insert(0, plan)

    @staticmethod
    def _same_plan(left: AttackWitness, right: AttackWitness) -> bool:
        return (left.prefix, left.pump, left.suffix, left.breaker, left.kind) == (
            right.prefix, right.pump, right.suffix, right.breaker, right.kind)

    def _verify_batch(self, candidates: Sequence[RegexCandidate], pool: WorkerPool,
                      settings: VerificationSettings, db: Database,
                      config_hash: str, dynamic_jobs: int,
                      stats: ScanStats) -> None:
        if not candidates:
            return
        work: Dict[str, Tuple[RegexCandidate, List[RegexCandidate]]] = {}
        for candidate in candidates:
            engine = pool.engine(candidate.language)
            if engine is None:
                candidate.dynamic = DynamicAnalysis(
                    status=DynamicStatus.SKIPPED.value,
                    notes=[pool.unavailable_note(candidate.language)],
                )
                continue
            key = self._dynamic_key(candidate, engine, settings, config_hash)
            if key in work:
                work[key][1].append(candidate)
                continue
            cached = db.cache_get("dynamic_cache", key)
            if cached is not None:
                analysis = DynamicAnalysis.from_dict(cached)
                candidate.dynamic = analysis
                stats.dynamic_run += 1
                continue
            work[key] = (candidate, [candidate])

        if not work:
            return
        items = list(work.items())
        self.log(f"running {len(items)} unique dynamic test(s) "
                 f"with {max(1, dynamic_jobs)} worker(s)")

        def run(item) -> Tuple[str, RegexCandidate, DynamicAnalysis]:
            key, (candidate, _clones) = item
            analysis = verify_candidate(candidate, candidate.static or StaticAnalysis(),
                                        pool, settings, log=self.log)
            return key, candidate, analysis

        if dynamic_jobs <= 1 or len(items) == 1:
            results = [run(item) for item in items]
        else:
            results = []
            with ThreadPoolExecutor(max_workers=max(1, dynamic_jobs)) as executor:
                futures = [executor.submit(run, item) for item in items]
                for future in as_completed(futures):
                    results.append(future.result())

        for key, candidate, analysis in results:
            stats.dynamic_run += 1
            db.cache_put("dynamic_cache", key, analysis.to_dict(),
                         engine=analysis.engine)
            candidate.dynamic = analysis
            _clones = work[key][1]
            for clone in _clones:
                clone.dynamic = analysis

    def _dynamic_key(self, candidate: RegexCandidate, engine,
                     settings: VerificationSettings, config_hash: str) -> str:
        plans = "|".join(
            f"{p.kind}:{p.prefix}:{p.pump}:{p.suffix}:{p.breaker}"
            for p in (candidate.static.attack_plans if candidate.static else [])
        )
        return stable_hash(
            DYNAMIC_CACHE_VERSION, config_hash, candidate.dialect,
            "".join(sorted(set(candidate.flags or ""))),
            candidate.pattern_hash or "<dynamic>",
            candidate.raw_pattern or "",
            candidate.engine_hint or "",
            engine.identity, str(settings.timeout_s), str(settings.budget_s),
            str(settings.max_input), str(settings.memory_mb),
            ",".join(str(s) for s in settings.exponential_sizes),
            ",".join(str(s) for s in settings.polynomial_sizes),
            str(settings.max_candidates), str(settings.stability_reruns), plans,
        )

    # -- helpers ------------------------------------------------------------
    def _package_enabled(self, package: PackageInfo,
                         languages: Optional[Sequence[str]]) -> bool:
        if not languages:
            return True
        # package-level filtering is a no-op unless the tree has no enabled
        # extension; file-level filtering happens in ``scan``.
        return True

    def _language_enabled(self, language: str) -> bool:
        return self.config.language_enabled(language)

    def _enabled_formats(self) -> List[str]:
        out = []
        for name in ("json", "jsonl", "sarif", "html", "summary"):
            if self.config.get(f"output.{name}", True):
                out.append(name)
        return out or ["json"]

    def _load_cve_map(self) -> Optional[CveMap]:
        path = self.config.get("cve.db")
        if not path:
            return None
        try:
            return CveMap.load(path)
        except (OSError, ValueError) as exc:
            self.log(f"cve map not loaded: {exc}")
            return None

    # -- close --------------------------------------------------------------
    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None


def scan(config: Config, paths: Sequence[str], **kwargs) -> ScanResult:
    """Convenience wrapper used by tests and embedders."""
    scanner = Scanner(config, db_path=kwargs.pop("db_path", None),
                      log=kwargs.pop("log", None))
    try:
        return scanner.scan(ScanOptions(paths=list(paths), **kwargs))
    finally:
        scanner.close()


def collect_candidates(package: PackageInfo, files: Sequence[SourceFile],
                       jobs: int = 1,
                       max_bytes: int = 4 * 1024 * 1024) -> List[RegexCandidate]:
    """Extraction-only helper used by the ``extract`` CLI command."""
    tasks = [(package.name, package.version, item.path, item.abspath,
              item.language, max_bytes) for item in files]
    if jobs <= 1 or len(tasks) <= 1:
        out: List[RegexCandidate] = []
        for task in tasks:
            out.extend(_extract_task(task))
        return out
    out = []
    with ProcessPoolExecutor(max_workers=max(1, jobs)) as pool:
        for chunk in pool.map(_extract_task, tasks, chunksize=4):
            out.extend(chunk)
    return out
