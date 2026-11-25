"""Canonical data model for the Debian ReDoS scanner.

Everything that crosses a module boundary (extractor -> analyser -> dynamic
verifier -> report) is represented here.  The model is intentionally
JSON-first: every object round-trips through ``to_dict`` / ``from_dict`` so it
can be written to JSONL, stored in SQLite and consumed by external tooling.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


# ---------------------------------------------------------------------------
# enumerations (kept as plain strings on the wire for forward compatibility)
# ---------------------------------------------------------------------------

class Language(str, Enum):
    PYTHON = "python"
    RUBY = "ruby"
    PHP = "php"

    @classmethod
    def parse(cls, value: str) -> "Language":
        value = value.strip().lower()
        aliases = {"py": cls.PYTHON, "rb": cls.RUBY, "php7": cls.PHP, "php8": cls.PHP}
        if value in aliases:
            return aliases[value]
        return cls(value)


class SourceType(str, Enum):
    """How the pattern value was obtained by the extractor."""

    LITERAL = "literal"
    VARIABLE = "variable"
    CONCAT = "concat"
    DYNAMIC = "dynamic"          # value could not be resolved
    UNKNOWN = "unknown"


class InputControl(str, Enum):
    """Best-effort classification of the data the regexp is applied to."""

    USER_NETWORK = "user_network"   # HTTP request / socket / RPC payload
    USER_LOCAL = "user_local"       # argv, stdin, interactive input
    FILE = "file"
    ENV = "env"
    DATABASE = "database"
    INTERNAL = "internal"           # provably constant / library-internal
    UNKNOWN = "unknown"


class Complexity(str, Enum):
    EXPONENTIAL = "exponential"
    POLYNOMIAL = "polynomial"
    LINEAR = "linear"
    NONE = "none"
    UNKNOWN = "unknown"


class StaticStatus(str, Enum):
    VULNERABLE = "vulnerable"
    SUSPICIOUS = "suspicious"
    SAFE = "safe"
    UNSUPPORTED = "unsupported"
    DYNAMIC_PATTERN_UNRESOLVED = "dynamic_pattern_unresolved"
    NOT_ANALYZED = "not_analyzed"


class DynamicStatus(str, Enum):
    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not_confirmed"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"
    ERROR = "error"


class Verdict(str, Enum):
    """Final state of a finding after static + dynamic correlation."""

    POTENTIAL = "potential"            # static only, not reproduced
    CONFIRMED = "confirmed"            # dynamic degradation reproduced
    EXPLOITABLE = "exploitable"        # confirmed + attacker controlled input
    NEEDS_REVIEW = "needs_review"
    INFORMATIONAL = "informational"


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def stable_hash(*parts: Optional[str]) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update((part or "").encode("utf-8", "surrogatepass"))
        h.update(b"\x1f")
    return "sha256:" + h.hexdigest()


_WS = re.compile(r"\s+")


def normalize_pattern(pattern: str, dialect: str, flags: str) -> str:
    """Pattern identity used for caching and de-duplication.

    The hash covers the dialect and the normalised flag set, because the same
    source string has different semantics in ``re``, Onigmo and PCRE2.
    Whitespace inside the pattern is *not* stripped -- it may be significant.
    """
    flag_key = "".join(sorted(set(flags or "")))
    return stable_hash(dialect.lower(), flag_key, pattern)


def pattern_hash(pattern: str, dialect: str, flags: str = "") -> str:
    return normalize_pattern(pattern, dialect, flags)


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _drop_none(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_drop_none(v) for v in value]
    return value


class ModelMixin:
    def to_dict(self) -> Dict[str, Any]:
        return _drop_none(dataclasses.asdict(self))  # type: ignore[arg-type]

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Any:
        return _build(cls, data)


def _build(cls, data: Dict[str, Any]) -> Any:
    """Reconstruct a dataclass, recursing into nested model fields.

    ``dataclasses.asdict`` is used for serialisation, so the inverse has to
    rebuild ``Evidence`` / ``AttackWitness`` / ``Trial`` objects; otherwise a
    finding loaded from SQLite or JSON would expose plain dicts and break the
    reporters and the dynamic verifier.
    """
    if data is None:
        return None
    if not isinstance(data, dict):
        return data
    nested = _NESTED.get(cls, {})
    kwargs: Dict[str, Any] = {}
    for f in dataclasses.fields(cls):  # type: ignore[arg-type]
        if f.name not in data:
            continue
        value = data[f.name]
        builder = nested.get(f.name)
        if builder is None:
            kwargs[f.name] = value
        elif isinstance(value, list):
            kwargs[f.name] = [builder(item) for item in value]
        elif value is None:
            kwargs[f.name] = None
        else:
            kwargs[f.name] = builder(value)
    return cls(**kwargs)  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------

@dataclass
class PackageInfo(ModelMixin):
    name: str
    version: str
    directory: str                      # absolute path to the unpacked tree
    kind: str = "tree"                  # tree | dsc | dir
    architecture: Optional[str] = None
    maintainer: Optional[str] = None
    source: Optional[str] = None        # debian Source field, may differ from name
    dsc_path: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.name}/{self.version}"


@dataclass
class SourceFile(ModelMixin):
    package: str
    version: str
    path: str                           # relative to the source tree
    abspath: str
    language: str
    sha256: str
    size: int
    lines: int = 0

    @property
    def key(self) -> str:
        return f"{self.package}/{self.path}"


# ---------------------------------------------------------------------------
# extraction
# ---------------------------------------------------------------------------

@dataclass
class RegexCandidate(ModelMixin):
    """A single regexp use-site found in the source tree."""

    package: str
    version: str
    language: str
    file: str
    line: int
    function: str
    pattern: Optional[str]                   # None => unresolved dynamic pattern
    dialect: str                             # python | ruby | php
    flags: str = ""
    column: Optional[int] = None
    end_line: Optional[int] = None
    source_type: str = SourceType.LITERAL.value
    input_control: str = InputControl.UNKNOWN.value
    input_evidence: Optional[str] = None
    raw_pattern: Optional[str] = None        # e.g. PHP pattern including delimiters
    extractor: str = ""
    engine_hint: Optional[str] = None        # regex | redis | ... (dialect specific)
    confidence: float = 1.0
    notes: List[str] = field(default_factory=list)
    # filled in later
    pattern_hash: Optional[str] = None
    static: Optional["StaticAnalysis"] = None
    dynamic: Optional["DynamicAnalysis"] = None
    finding_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.pattern is not None and not self.pattern_hash:
            self.pattern_hash = pattern_hash(self.pattern, self.dialect, self.flags)

    @property
    def location(self) -> str:
        return f"{self.file}:{self.line}"

    @property
    def is_resolved(self) -> bool:
        return self.pattern is not None

    @property
    def cache_key(self) -> str:
        return f"{self.dialect}|{''.join(sorted(set(self.flags)))}|{self.pattern}"


# ---------------------------------------------------------------------------
# static analysis
# ---------------------------------------------------------------------------

@dataclass
class Evidence(ModelMixin):
    """One machine-readable reason supporting a static conclusion."""

    rule: str
    message: str
    node: Optional[str] = None            # normalised sub-expression
    span: Optional[List[int]] = None      # [start, end) offsets in the pattern
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackWitness(ModelMixin):
    """A concrete ambiguity witness: prefix + pump* + suffix + breaker."""

    prefix: str = ""
    pump: str = ""
    suffix: str = ""
    breaker: str = "!"
    kind: str = "exponential"             # exponential | polynomial
    note: Optional[str] = None


@dataclass
class StaticAnalysis(ModelMixin):
    status: str = StaticStatus.NOT_ANALYZED.value
    complexity: str = Complexity.UNKNOWN.value
    confidence: float = 0.0
    detector: str = ""
    evidence: List[Evidence] = field(default_factory=list)
    witness: Optional[AttackWitness] = None
    attack_plans: List[AttackWitness] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    normalized_pattern: Optional[str] = None

    @property
    def suspicious(self) -> bool:
        return self.status in (
            StaticStatus.VULNERABLE.value,
            StaticStatus.SUSPICIOUS.value,
            StaticStatus.DYNAMIC_PATTERN_UNRESOLVED.value,
        )


# ---------------------------------------------------------------------------
# dynamic analysis
# ---------------------------------------------------------------------------

@dataclass
class Trial(ModelMixin):
    input_length: int
    elapsed_ms: float
    status: str = "completed"             # completed | timeout | error | crash
    error: Optional[str] = None
    input_preview: Optional[str] = None   # truncated, never the full payload


@dataclass
class DynamicAnalysis(ModelMixin):
    status: str = DynamicStatus.SKIPPED.value
    engine: Optional[str] = None
    engine_version: Optional[str] = None
    growth_class: str = "unknown"         # constant|linear|polynomial|exponential|timeout|unknown
    growth_slope: Optional[float] = None  # log-log slope at the tail
    max_elapsed_ms: Optional[float] = None
    timeout_at: Optional[int] = None
    attack: Optional[str] = None
    attack_inputs: List[str] = field(default_factory=list)
    trials: List[Trial] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def confirmed(self) -> bool:
        return self.status == DynamicStatus.CONFIRMED.value


# ---------------------------------------------------------------------------
# findings / reports
# ---------------------------------------------------------------------------

@dataclass
class KnownMatch(ModelMixin):
    """A link between a finding and an entry of the known-ReDoS database.

    The database is an *advisory* source: a match is an annotation, not an
    automatically assigned CVE.  ``match_types`` records how the link was
    established (``exact``/``canonical``/``shape``/``core``/``fuzzy``/
    ``package``) so consumers can apply their own policy.
    """

    id: str
    title: str
    cve: Optional[str] = None
    language: Optional[str] = None
    severity: Optional[str] = None
    kind: str = "fuzzy"                   # strongest match type
    score: float = 0.0
    confidence: str = "low"               # high | medium | low
    match_types: List[str] = field(default_factory=list)
    matched_pattern: Optional[str] = None
    matched_flags: str = ""
    # Optional attack witness carried by the advisory.  The dynamic stage
    # prefers it over the heuristically generated plan because a published
    # reproducer is usually more accurate for large, hand-written patterns.
    witness: Optional[Dict[str, Any]] = None
    pattern_matched: bool = True
    package_match: bool = False
    auto_assigned: bool = False
    source: Optional[str] = None
    references: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


@dataclass
class Finding(ModelMixin):
    id: str
    package: str
    version: str
    language: str
    file: str
    line: int
    function: str
    engine: str
    dialect: str
    pattern: Optional[str] = None
    flags: str = ""
    pattern_hash: Optional[str] = None
    source_type: str = SourceType.LITERAL.value
    input_control: str = InputControl.UNKNOWN.value
    input_evidence: Optional[str] = None
    static: StaticAnalysis = field(default_factory=StaticAnalysis)
    dynamic: DynamicAnalysis = field(default_factory=DynamicAnalysis)
    verdict: str = Verdict.POTENTIAL.value
    severity: str = "info"
    priority: str = "info"
    cve: Optional[str] = None
    cve_source: Optional[str] = None
    known: List[KnownMatch] = field(default_factory=list)
    detectors: List[str] = field(default_factory=list)
    duplicates: int = 0
    created_at: str = ""
    run_id: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    @property
    def sort_key(self) -> tuple:
        return (
            -SEVERITY_ORDER.get(self.severity, 0),
            self.package,
            self.file,
            self.line,
        )


@dataclass
class ScanStats(ModelMixin):
    packages: int = 0
    files: int = 0
    files_scanned: int = 0
    files_skipped_cached: int = 0
    candidates: int = 0
    unique_patterns: int = 0
    static_suspicious: int = 0
    dynamic_run: int = 0
    confirmed: int = 0
    exploitable: int = 0
    needs_review: int = 0
    informational: int = 0
    known_matched: int = 0
    errors: int = 0
    duration_seconds: float = 0.0


@dataclass
class ScanResult(ModelMixin):
    run_id: str
    started_at: str
    finished_at: str
    mode: str = "full"
    packages: List[PackageInfo] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    config: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def counts_by_severity(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out


def iter_jsonl(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


# ---------------------------------------------------------------------------
# nested model builders (see ``_build``)
# ---------------------------------------------------------------------------

def _model(cls):
    return lambda item: _build(cls, item)


_NESTED = {
    RegexCandidate: {"static": _model(StaticAnalysis), "dynamic": _model(DynamicAnalysis)},
    StaticAnalysis: {
        "evidence": _model(Evidence),
        "witness": _model(AttackWitness),
        "attack_plans": _model(AttackWitness),
    },
    DynamicAnalysis: {"trials": _model(Trial)},
    Finding: {
        "static": _model(StaticAnalysis),
        "dynamic": _model(DynamicAnalysis),
        "known": _model(KnownMatch),
    },
    ScanResult: {
        "packages": _model(PackageInfo),
        "findings": _model(Finding),
        "stats": _model(ScanStats),
    },
}
