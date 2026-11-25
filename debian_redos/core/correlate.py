"""Correlation: candidates -> findings.

This module is the single place where the final verdict is decided.  Keeping
the policy here (instead of in the pipeline or the reporters) means static,
dynamic and reporting code never duplicate the severity matrix.

Policy summary
--------------
* ``exploitable``  -- degradation was reproduced **and** the matched data is
  attacker controlled (network or local user input);
* ``confirmed``   -- degradation was reproduced, but the data source is a
  file, a database, the environment or unknown;
* ``needs_review``-- the pattern is structurally dangerous (exponential or an
  unmodelled construct) yet dynamic verification did not settle it, or the
  data source is unknown for an exponential pattern;
* ``potential``   -- dangerous shape, no confirmation attempt (or the attempt
  was not conclusive) and no reason to escalate;
* ``informational``-- safe/linear patterns that were nevertheless recorded.

Severity is a function of (verdict, complexity), then adjusted for confidence
and for non-attacker-controlled input.  The priority is the severity with an
extra bump for ``exploitable`` findings so reports can be sorted cheaply.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import (
    Complexity,
    DynamicAnalysis,
    DynamicStatus,
    Finding,
    InputControl,
    RegexCandidate,
    SEVERITY_ORDER,
    StaticStatus,
    Verdict,
    stable_hash,
)
from .known import KnownDatabase, KnownOptions, apply_known

_ATTACKER_CONTROLLED = {InputControl.USER_NETWORK.value, InputControl.USER_LOCAL.value}
_NON_ATTACKER = {InputControl.FILE.value, InputControl.ENV.value,
                 InputControl.DATABASE.value, InputControl.INTERNAL.value}


def _severity_ladder(value: str, steps: int = 1) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    try:
        index = order.index(value)
    except ValueError:
        return value
    return order[max(0, min(len(order) - 1, index + steps))]


def _downgrade(value: str, steps: int = 1) -> str:
    return _severity_ladder(value, -steps)


def _base_severity(verdict: str, complexity: str) -> str:
    exponential = complexity in (Complexity.EXPONENTIAL.value, Complexity.UNKNOWN.value)
    if verdict == Verdict.EXPLOITABLE.value:
        return "critical" if complexity == Complexity.EXPONENTIAL.value else "high"
    if verdict == Verdict.CONFIRMED.value:
        return "high" if exponential else "medium"
    if verdict == Verdict.NEEDS_REVIEW.value:
        return "medium" if exponential else "low"
    if verdict == Verdict.POTENTIAL.value:
        return "medium" if exponential else "low"
    return "info"


# ---------------------------------------------------------------------------
# CVE map (loaded from JSON, never assigned automatically)
# ---------------------------------------------------------------------------

@dataclass
class CveMap:
    patterns: Dict[str, Dict[str, str]] = field(default_factory=dict)
    locations: Dict[str, Dict[str, str]] = field(default_factory=dict)
    packages: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    source: Optional[str] = None

    @classmethod
    def load(cls, path: Optional[str]) -> "CveMap":
        if not path:
            return cls()
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"{path}: CVE map must be a JSON object")
        return cls(
            patterns=dict(data.get("patterns") or {}),
            locations=dict(data.get("locations") or {}),
            packages=dict(data.get("packages") or {}),
            source=os.path.abspath(path),
        )

    def lookup(self, package: str, pattern_hash: Optional[str], file: str,
               line: int) -> Tuple[Optional[str], Optional[str]]:
        """Return ``(cve, provenance)``; exact location wins over pattern."""
        location_key = f"{package}:{file}:{line}"
        for key in (location_key, f"{package}:{file}", f"{file}:{line}"):
            entry = self.locations.get(key)
            if entry:
                return _entry_cve(entry)
        if pattern_hash:
            entry = self.patterns.get(pattern_hash)
            if entry:
                return _entry_cve(entry)
        for entry in self.packages.get(package, []) or []:
            if not isinstance(entry, dict):
                return _entry_cve(entry)
            entry_file = entry.get("file")
            entry_pattern = entry.get("pattern")
            if entry_file and entry_file != file:
                continue
            if entry_pattern and entry_pattern != pattern_hash:
                continue
            return _entry_cve(entry)
        return None, None


def _entry_cve(entry) -> Tuple[Optional[str], Optional[str]]:
    if isinstance(entry, str):
        return entry, "cve-map"
    if isinstance(entry, dict):
        return entry.get("cve"), entry.get("source") or "cve-map"
    return None, None


# ---------------------------------------------------------------------------
# correlation
# ---------------------------------------------------------------------------

@dataclass
class CorrelateOptions:
    cve_map: Optional[CveMap] = None
    known_db: Optional[KnownDatabase] = None
    known_options: Optional[KnownOptions] = None
    report_safe: bool = False
    min_severity: str = "info"
    max_line_distance: int = 3


def correlate(candidates: Sequence[RegexCandidate],
              *,
              package: str = "",
              version: str = "",
              run_id: Optional[str] = None,
              options: Optional[CorrelateOptions] = None,
              created_at: str = "") -> List[Finding]:
    """Turn analysed candidates into de-duplicated findings."""
    options = options or CorrelateOptions()
    findings: List[Finding] = []
    for group in _group(candidates):
        finding = _build_finding(group, package=package, version=version,
                                 run_id=run_id, options=options,
                                 created_at=created_at)
        if finding is None:
            continue
        if SEVERITY_ORDER.get(finding.severity, 0) < SEVERITY_ORDER.get(options.min_severity, 0):
            continue
        findings.append(finding)
    findings.sort(key=lambda f: f.sort_key)
    return findings


def _group(candidates: Sequence[RegexCandidate]) -> Iterable[List[RegexCandidate]]:
    """Group use-sites of the same pattern in the same file."""
    buckets: Dict[Tuple[str, str, str, str, str], List[RegexCandidate]] = {}
    order: List[Tuple[str, str, str, str, str]] = []
    for candidate in candidates:
        key = (
            candidate.package,
            candidate.version,
            candidate.file,
            candidate.pattern_hash or candidate.pattern or "<dynamic>",
            "".join(sorted(set(candidate.flags or ""))),
        )
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(candidate)
    for key in order:
        yield buckets[key]


def _build_finding(group: List[RegexCandidate], *, package: str, version: str,
                   run_id: Optional[str], options: CorrelateOptions,
                   created_at: str) -> Optional[Finding]:
    representative = _representative(group)
    static = representative.static
    dynamic = representative.dynamic
    if static is None:
        return None

    if static.status == StaticStatus.SAFE.value and not options.report_safe:
        return None

    if dynamic is None:
        dynamic = DynamicAnalysis(
            status=DynamicStatus.SKIPPED.value,
            notes=["dynamic stage was not run for this candidate"],
        )

    complexity = static.complexity
    input_control = _merged_input_control(group)
    evidence = next((c.input_evidence for c in group if c.input_evidence), None)

    verdict, notes = _decide(static, dynamic, input_control)
    severity = _base_severity(verdict, complexity)

    if static.confidence and static.confidence < 0.7 and verdict in (
            Verdict.POTENTIAL.value, Verdict.NEEDS_REVIEW.value):
        severity = _downgrade(severity)
    if input_control in _NON_ATTACKER and verdict in (
            Verdict.EXPLOITABLE.value, Verdict.CONFIRMED.value):
        severity = _downgrade(severity)

    priority = severity
    if verdict == Verdict.EXPLOITABLE.value:
        priority = _severity_ladder(severity, 1)

    pattern_hash = representative.pattern_hash
    finding_id = stable_hash(representative.package or package,
                             representative.version or version,
                             representative.file,
                             str(representative.line),
                             pattern_hash or representative.pattern or "<dynamic>")

    cve, cve_source = (None, None)
    if options.cve_map is not None:
        cve, cve_source = options.cve_map.lookup(
            representative.package or package, pattern_hash,
            representative.file, representative.line,
        )

    duplicates = _duplicate_locations(group)
    if duplicates:
        notes.append("same pattern also at " + ", ".join(duplicates[:10])
                     + (" ..." if len(duplicates) > 10 else ""))
    if len(group) > 1:
        notes.append(f"{len(group)} use-sites merged into this finding")

    detectors = sorted({static.detector} | {
        c.static.detector for c in group if c.static and c.static.detector})
    detectors = [d for d in detectors if d]

    finding = Finding(
        id=finding_id,
        package=representative.package or package,
        version=representative.version or version,
        language=representative.language,
        file=representative.file,
        line=representative.line,
        function=representative.function,
        engine=_engine_label(representative, dynamic),
        dialect=representative.dialect,
        pattern=representative.pattern,
        flags=representative.flags or "",
        pattern_hash=pattern_hash,
        source_type=representative.source_type,
        input_control=input_control,
        input_evidence=evidence,
        static=static,
        dynamic=dynamic,
        verdict=verdict,
        severity=severity,
        priority=priority,
        cve=cve,
        cve_source=cve_source,
        detectors=detectors,
        duplicates=len(group) - 1,
        created_at=created_at,
        run_id=run_id,
        notes=notes,
    )
    apply_known(finding, options.known_db, options.known_options)
    return finding


def _representative(group: List[RegexCandidate]) -> RegexCandidate:
    """Prefer a confirmed use-site, then attacker-controlled input, then line."""

    def score(candidate: RegexCandidate):
        confirmed = 1 if candidate.dynamic and candidate.dynamic.confirmed else 0
        control = 2 if candidate.input_control in _ATTACKER_CONTROLLED else (
            1 if candidate.input_control == InputControl.UNKNOWN.value else 0)
        confidence = candidate.static.confidence if candidate.static else 0.0
        return (confirmed, control, confidence, -candidate.line)

    return max(group, key=score)


def _merged_input_control(group: List[RegexCandidate]) -> str:
    rank = {
        InputControl.USER_NETWORK.value: 5,
        InputControl.USER_LOCAL.value: 4,
        InputControl.UNKNOWN.value: 3,
        InputControl.FILE.value: 2,
        InputControl.DATABASE.value: 1,
        InputControl.ENV.value: 1,
        InputControl.INTERNAL.value: 0,
    }
    return max((c.input_control for c in group),
               key=lambda value: rank.get(value, 3))


def _duplicate_locations(group: List[RegexCandidate]) -> List[str]:
    primary = _representative(group)
    out = []
    for candidate in group:
        location = f"{candidate.line}:{candidate.function or '?'}"
        if candidate.line == primary.line and candidate.function == primary.function:
            continue
        out.append(location)
    return out


def _decide(static, dynamic, input_control: str) -> Tuple[str, List[str]]:
    notes: List[str] = []
    complexity = static.complexity
    attack_controlled = input_control in _ATTACKER_CONTROLLED
    dynamic_status = dynamic.status if dynamic is not None else DynamicStatus.SKIPPED.value

    if static.status == StaticStatus.SAFE.value:
        return Verdict.INFORMATIONAL.value, notes

    if dynamic_status == DynamicStatus.CONFIRMED.value:
        if attack_controlled:
            notes.append("degradation reproduced and the matched data is attacker controlled")
            return Verdict.EXPLOITABLE.value, notes
        if input_control in _NON_ATTACKER:
            notes.append("degradation reproduced; matched data is not attacker controlled")
        else:
            notes.append("degradation reproduced; data provenance is unknown")
        return Verdict.CONFIRMED.value, notes

    if static.status in (StaticStatus.UNSUPPORTED.value,
                         StaticStatus.DYNAMIC_PATTERN_UNRESOLVED.value):
        return Verdict.NEEDS_REVIEW.value, notes

    if complexity == Complexity.UNKNOWN.value:
        notes.append("pattern contains constructs the static model does not cover")
        return Verdict.NEEDS_REVIEW.value, notes

    if dynamic_status == DynamicStatus.ERROR.value:
        notes.append("dynamic verification failed; static evidence only")
        return Verdict.NEEDS_REVIEW.value, notes

    if dynamic_status == DynamicStatus.INCONCLUSIVE.value:
        if attack_controlled:
            notes.append("dynamic verification was inconclusive for attacker controlled input")
            return Verdict.NEEDS_REVIEW.value, notes
        return Verdict.POTENTIAL.value, notes

    if complexity == Complexity.EXPONENTIAL.value:
        if attack_controlled:
            return Verdict.POTENTIAL.value, notes
        if input_control == InputControl.UNKNOWN.value:
            notes.append("exponential pattern, but the data source could not be classified")
            return Verdict.NEEDS_REVIEW.value, notes
        return Verdict.POTENTIAL.value, notes

    if complexity == Complexity.POLYNOMIAL.value:
        return Verdict.POTENTIAL.value, notes

    return Verdict.POTENTIAL.value, notes


def _engine_label(candidate: RegexCandidate, dynamic) -> str:
    if dynamic is not None and dynamic.engine:
        return dynamic.engine
    return {
        "python": "python-re",
        "ruby": "ruby-onigmo",
        "php": "php-pcre2",
    }.get(candidate.language, candidate.language)
