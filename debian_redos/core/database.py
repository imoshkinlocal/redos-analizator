"""SQLite persistence and caching.

Two kinds of cache live here:

* ``analysis_cache``  -- static analysis keyed by pattern semantics
  (dialect + flags + normalised source + detector version);
* ``dynamic_cache``   -- verification keyed by pattern + engine identity +
  attack plan + measurement settings, so re-scanning an unchanged package does
  not re-run a two-second engine test.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..models import Finding, PackageInfo, ScanStats, SourceFile

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scan_runs (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    mode TEXT,
    config_hash TEXT,
    labels TEXT,
    stats_json TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS packages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    directory TEXT,
    kind TEXT,
    maintainer TEXT,
    source TEXT,
    dsc_path TEXT,
    first_seen TEXT,
    UNIQUE(name, version)
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    path TEXT NOT NULL,
    language TEXT,
    sha256 TEXT,
    size INTEGER,
    lines INTEGER,
    scanned_at TEXT,
    UNIQUE(package, version, path)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT,
    language TEXT,
    file TEXT,
    line INTEGER,
    function TEXT,
    engine TEXT,
    pattern TEXT,
    pattern_hash TEXT,
    input_control TEXT,
    static_status TEXT,
    complexity TEXT,
    dynamic_status TEXT,
    growth_class TEXT,
    verdict TEXT,
    severity TEXT,
    priority TEXT,
    cve TEXT,
    payload TEXT NOT NULL,
    created_at TEXT,
    PRIMARY KEY (id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_package ON findings(package);
CREATE INDEX IF NOT EXISTS idx_findings_verdict ON findings(verdict);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_file ON findings(package, file);

CREATE TABLE IF NOT EXISTS analysis_cache (
    key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS dynamic_cache (
    key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    engine TEXT,
    created_at TEXT
);
"""

CACHE_TABLES = {"analysis_cache", "dynamic_cache"}


def utcnow() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Database:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        # Older databases keyed findings by id alone; a re-scan would then
        # silently move findings between runs.  Recreate the table (findings
        # are derived data, the source tree is the source of truth).
        row = self.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='findings'"
        ).fetchone()
        if row and "primary key (id, run_id)" not in (row["sql"] or "").lower():
            self.connection.execute("DROP TABLE findings")
        self.connection.executescript(SCHEMA)
        self.connection.commit()

    # -- lifecycle ----------------------------------------------------------
    def close(self) -> None:
        try:
            self.connection.commit()
        finally:
            self.connection.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -- runs ---------------------------------------------------------------
    def start_run(self, mode: str, config_hash: str, labels: Optional[Dict[str, Any]] = None) -> str:
        run_id = "run-" + uuid.uuid4().hex[:12]
        self.connection.execute(
            "INSERT INTO scan_runs (id, started_at, mode, config_hash, labels) VALUES (?,?,?,?,?)",
            (run_id, utcnow(), mode, config_hash, json.dumps(labels or {})),
        )
        self.connection.commit()
        return run_id

    def finish_run(self, run_id: str, stats: ScanStats, notes: Sequence[str] = ()) -> None:
        self.connection.execute(
            "UPDATE scan_runs SET finished_at=?, stats_json=?, notes=? WHERE id=?",
            (utcnow(), json.dumps(stats.to_dict()), json.dumps(list(notes)), run_id),
        )
        self.connection.commit()

    def last_run_id(self) -> Optional[str]:
        row = self.connection.execute(
            "SELECT id FROM scan_runs WHERE finished_at IS NOT NULL "
            "ORDER BY started_at DESC, rowid DESC LIMIT 1"
        ).fetchone()
        return row["id"] if row else None

    def previous_run(self) -> Optional[Dict[str, Any]]:
        """Metadata of the latest finished run (used for incremental scans)."""
        return self.run_meta()

    def run_meta(self, run_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if run_id:
            row = self.connection.execute(
                "SELECT * FROM scan_runs WHERE id=?", (run_id,)
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT * FROM scan_runs WHERE finished_at IS NOT NULL "
                "ORDER BY started_at DESC, rowid DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        data = dict(row)
        for key in ("stats_json", "labels", "notes"):
            if data.get(key):
                try:
                    data[key] = json.loads(data[key])
                except ValueError:
                    pass
        return data

    # -- packages / files ---------------------------------------------------
    def save_packages(self, packages: Sequence[PackageInfo]) -> None:
        now = utcnow()
        for package in packages:
            self.connection.execute(
                """INSERT INTO packages (name, version, directory, kind, maintainer, source,
                                         dsc_path, first_seen)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(name, version) DO UPDATE SET
                     directory=excluded.directory, kind=excluded.kind, source=excluded.source
                """,
                (package.name, package.version, package.directory, package.kind,
                 package.maintainer, package.source, package.dsc_path, now),
            )
        self.connection.commit()

    def save_files(self, files: Sequence[SourceFile]) -> None:
        now = utcnow()
        for item in files:
            self.connection.execute(
                """INSERT INTO files (package, version, path, language, sha256, size, lines, scanned_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(package, version, path) DO UPDATE SET
                     sha256=excluded.sha256, size=excluded.size, lines=excluded.lines,
                     language=excluded.language, scanned_at=excluded.scanned_at
                """,
                (item.package, item.version, item.path, item.language, item.sha256,
                 item.size, item.lines, now),
            )
        self.connection.commit()

    def file_is_unchanged(self, package: str, version: str, path: str, sha256: str) -> bool:
        row = self.connection.execute(
            "SELECT sha256 FROM files WHERE package=? AND version=? AND path=?",
            (package, version, path),
        ).fetchone()
        return bool(row) and row["sha256"] == sha256

    def load_packages(self) -> List[PackageInfo]:
        rows = self.connection.execute(
            "SELECT name, version, directory, kind, maintainer, source, dsc_path "
            "FROM packages ORDER BY name, version"
        ).fetchall()
        return [PackageInfo(
            name=row["name"], version=row["version"], directory=row["directory"] or "",
            kind=row["kind"] or "tree", maintainer=row["maintainer"],
            source=row["source"], dsc_path=row["dsc_path"],
        ) for row in rows]

    # -- findings -----------------------------------------------------------
    def save_findings(self, findings: Sequence[Finding]) -> None:
        for finding in findings:
            payload = json.dumps(finding.to_dict(), ensure_ascii=False, sort_keys=False)
            self.connection.execute(
                """INSERT OR REPLACE INTO findings
                   (id, run_id, package, version, language, file, line, function, engine,
                    pattern, pattern_hash, input_control, static_status, complexity,
                    dynamic_status, growth_class, verdict, severity, priority, cve,
                    payload, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (finding.id, finding.run_id or "", finding.package, finding.version,
                 finding.language, finding.file, finding.line, finding.function,
                 finding.engine, finding.pattern, finding.pattern_hash,
                 finding.input_control, finding.static.status, finding.static.complexity,
                 finding.dynamic.status, finding.dynamic.growth_class, finding.verdict,
                 finding.severity, finding.priority, finding.cve, payload,
                 finding.created_at or utcnow()),
            )
        self.connection.commit()

    def findings_for_files(self, package: str, version: str,
                           paths: Iterable[str],
                           run_id: Optional[str] = None) -> List[Finding]:
        """Stored findings for unchanged files (incremental scans)."""
        paths = list(paths)
        if not paths:
            return []
        run_id = run_id or self.last_run_id()
        if run_id is None:
            return []
        out: List[Finding] = []
        chunk_size = 400
        for start in range(0, len(paths), chunk_size):
            chunk = paths[start:start + chunk_size]
            placeholders = ",".join("?" for _ in chunk)
            rows = self.connection.execute(
                f"""SELECT payload FROM findings
                    WHERE run_id=? AND package=? AND version=? AND file IN ({placeholders})""",
                [run_id, package, version] + chunk,
            ).fetchall()
            for row in rows:
                out.append(Finding.from_dict(json.loads(row["payload"])))
        return out

    def query_findings(self, run_id: Optional[str] = None, package: Optional[str] = None,
                       min_severity: Optional[str] = None,
                       verdict: Optional[str] = None) -> List[Finding]:
        clauses = []
        params: List[Any] = []
        if run_id:
            clauses.append("run_id=?")
            params.append(run_id)
        if package:
            clauses.append("package=?")
            params.append(package)
        if verdict:
            clauses.append("verdict=?")
            params.append(verdict)
        if min_severity:
            from ..models import SEVERITY_ORDER
            allowed = [name for name, rank in SEVERITY_ORDER.items()
                       if rank >= SEVERITY_ORDER.get(min_severity, 0)]
            clauses.append("severity IN (" + ",".join("?" for _ in allowed) + ")")
            params.extend(allowed)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.connection.execute(
            "SELECT payload FROM findings" + where + " ORDER BY package, file, line", params
        ).fetchall()
        return [Finding.from_dict(json.loads(row["payload"])) for row in rows]

    def stats(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for table in ("scan_runs", "packages", "files", "findings", "analysis_cache",
                      "dynamic_cache"):
            row = self.connection.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
            out[table] = row["n"]
        rows = self.connection.execute(
            "SELECT verdict, COUNT(*) AS n FROM findings GROUP BY verdict"
        ).fetchall()
        out["by_verdict"] = {row["verdict"]: row["n"] for row in rows}
        rows = self.connection.execute(
            "SELECT severity, COUNT(*) AS n FROM findings GROUP BY severity"
        ).fetchall()
        out["by_severity"] = {row["severity"]: row["n"] for row in rows}
        rows = self.connection.execute(
            """SELECT package, COUNT(*) AS n FROM findings
               WHERE run_id=(SELECT id FROM scan_runs ORDER BY started_at DESC, rowid DESC LIMIT 1)
               GROUP BY package ORDER BY n DESC LIMIT 25"""
        ).fetchall()
        out["top_packages"] = {row["package"]: row["n"] for row in rows}
        return out

    def prune(self, keep_runs: int = 5) -> int:
        rows = self.connection.execute(
            "SELECT id FROM scan_runs ORDER BY started_at DESC, rowid DESC LIMIT -1 OFFSET ?",
            (max(0, keep_runs),),
        ).fetchall()
        removed = 0
        for row in rows:
            self.connection.execute("DELETE FROM findings WHERE run_id=?", (row["id"],))
            self.connection.execute("DELETE FROM scan_runs WHERE id=?", (row["id"],))
            removed += 1
        self.connection.commit()
        return removed

    # -- cache --------------------------------------------------------------
    def cache_get(self, table: str, key: str) -> Optional[Dict[str, Any]]:
        if table not in CACHE_TABLES:
            raise ValueError(f"unknown cache table {table}")
        row = self.connection.execute(
            f"SELECT payload FROM {table} WHERE key=?", (key,)
        ).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["payload"])
        except ValueError:
            return None

    def cache_put(self, table: str, key: str, payload: Dict[str, Any],
                  engine: Optional[str] = None) -> None:
        if table not in CACHE_TABLES:
            raise ValueError(f"unknown cache table {table}")
        columns = "key, payload, created_at" + (", engine" if table == "dynamic_cache" else "")
        placeholders = "?,?,?" + (",?" if table == "dynamic_cache" else "")
        values: List[Any] = [key, json.dumps(payload, ensure_ascii=False, sort_keys=True), utcnow()]
        if table == "dynamic_cache":
            values.append(engine)
        self.connection.execute(
            f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({placeholders})", values
        )
        self.connection.commit()

    def clear_cache(self) -> None:
        self.connection.execute("DELETE FROM analysis_cache")
        self.connection.execute("DELETE FROM dynamic_cache")
        self.connection.commit()
