"""Known-vulnerability database and pattern matching.

The scanner can compare a discovered regexp with a local database of known
ReDoS advisories (CVE records, distribution advisories, vendor notes).  The
comparison is deliberately *multi-level* because the same vulnerable construct
is rarely copied verbatim:

``exact``
    identical pattern, dialect and flag set (the strongest signal);
``canonical``
    semantically identical after parsing/normalising (``(?P<x>)`` vs
    ``(?<x>)``, ``(?:a)`` vs ``(a)``, inline flags, ...);
``shape``
    same structural fingerprint with character classes and literals
    abstracted (``^(a+)+$`` vs ``^(b+)+$``);
``core``
    the same dangerous sub-expression is present even though the envelope
    around it differs (``^prefix(a+)+suffix$`` vs ``\\Afoo(a+)+bar\\z``);
``fuzzy``
    high textual similarity after normalisation (small edits such as an
    added quantifier or a changed separator);
``package``
    the source package matches an advisory that has no pattern (for example
    because the upstream fix was an input-length limit rather than a regexp
    change).

The database is advisory.  A match never overwrites the CVE field unless
``known.auto_assign_cve`` is explicitly enabled, and even then only exact or
canonical matches above ``known.auto_assign_min_score`` are eligible.

Database format (JSON)::

    {
      "schema_version": "1.0",
      "updated": "2026-11-06",
      "entries": [
        {
          "id": "CVE-2023-28756",
          "cve": "CVE-2023-28756",
          "title": "ReDoS in Ruby Time.rfc2822",
          "language": "ruby",
          "severity": "high",
          "packages": ["ruby", "time"],
          "affected": ["ruby < 3.1.4", "time < 0.2.2"],
          "references": ["https://..."],
          "patterns": [
            {"pattern": "...", "flags": "ix", "status": "vulnerable"},
            {"pattern": "...", "flags": "ix", "status": "fixed"}
          ]
        }
      ]
    }

``language`` may be ``"any"``; a pattern may override the dialect with its own
``dialect`` key.  ``status`` is one of ``vulnerable``, ``fixed`` or ``test``.
Only ``vulnerable`` patterns are matched, so a source tree that already
contains the patched expression is not flagged.
"""

from __future__ import annotations

import difflib
import json
import os
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..analyzers import heuristics
from ..analyzers import regex_ast
from ..models import (
    Complexity,
    Finding,
    KnownMatch,
    pattern_hash,
)

SCHEMA_VERSION = "1.0"
BUNDLED_DB = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "data", "known_redos.json")

_MATCH_ORDER = ("exact", "canonical", "shape", "core", "fuzzy", "package")

_CORE_RULES = {
    "nested_quantifier",
    "nullable_body",
    "ambiguous_repetition",
    "bounded_ambiguous_repeat",
    "sequential_overlap",
}

_COMPLEXITY_KIND = {
    Complexity.EXPONENTIAL.value: "exponential",
    Complexity.POLYNOMIAL.value: "polynomial",
}


# ---------------------------------------------------------------------------
# options
# ---------------------------------------------------------------------------

@dataclass
class KnownOptions:
    """Policy for known-database matching.

    ``min_score`` only controls fuzzy matching; exact/canonical/shape/core
    matches are structural and are always reported.  ``max_matches`` is a
    report-size guard (``0`` means unlimited).
    """

    min_score: float = 0.78
    match_core: bool = True
    match_packages: bool = True
    max_matches: int = 5
    auto_assign_cve: bool = False
    auto_assign_min_score: float = 0.95

    @classmethod
    def from_config(cls, config) -> "KnownOptions":
        def _get(name, default):
            try:
                value = config.get(f"known.{name}", default)
            except AttributeError:
                return default
            return default if value is None else value

        return cls(
            min_score=float(_get("min_score", 0.78)),
            match_core=bool(_get("match_core", True)),
            match_packages=bool(_get("match_packages", True)),
            max_matches=int(_get("max_matches", 5)),
            auto_assign_cve=bool(_get("auto_assign_cve", False)),
            auto_assign_min_score=float(_get("auto_assign_min_score", 0.95)),
        )


# ---------------------------------------------------------------------------
# shape fingerprint
# ---------------------------------------------------------------------------

def _repeat_token(node: regex_ast.Repeat) -> str:
    if node.min == 0 and node.max is None:
        quant = "*"
    elif node.min == 1 and node.max is None:
        quant = "+"
    elif node.min == 0 and node.max == 1:
        quant = "?"
    elif node.max is None:
        quant = "{%d,}" % node.min
    elif node.min == node.max:
        quant = "{%d}" % node.min
    else:
        quant = "{%d,%d}" % (node.min, node.max)
    if node.possessive:
        quant += "p"
    elif node.lazy:
        quant += "l"
    return quant


def shape_tokens(node: Optional[regex_ast.Node]) -> List[str]:
    """Structural token stream with literals and character classes abstracted.

    The fingerprint keeps everything that determines where backtracking paths
    can multiply: group nesting/kind, alternation, quantifier bounds and
    greediness, anchors and backreferences.  Character identity is reduced to
    ``C`` so ``a``, ``[a-z]`` and ``\\d`` have the same structural role.
    """

    if node is None:
        return []
    if isinstance(node, regex_ast.Char):
        return ["C"]
    if isinstance(node, regex_ast.Empty):
        return ["E"]
    if isinstance(node, regex_ast.Anchor):
        return ["^" + node.kind]
    if isinstance(node, regex_ast.Backref):
        return ["B"]
    if isinstance(node, regex_ast.Unsupported):
        return ["U"]
    if isinstance(node, regex_ast.Seq):
        out: List[str] = ["S("]
        for item in node.items:
            out.extend(shape_tokens(item))
        out.append(")")
        return out
    if isinstance(node, regex_ast.Alt):
        out = ["A("]
        for index, option in enumerate(node.options):
            if index:
                out.append("|")
            out.extend(shape_tokens(option))
        out.append(")")
        return out
    if isinstance(node, regex_ast.Repeat):
        return (["R" + _repeat_token(node) + "("] +
                shape_tokens(node.node) + [")"])
    if isinstance(node, regex_ast.Group):
        kind = node.kind if node.kind in (
            "atomic", "lookahead", "lookbehind",
            "negative_lookahead", "negative_lookbehind",
        ) else "group"
        return ["G" + kind + "("] + shape_tokens(node.node) + [")"]
    return ["?"]


def shape_of(node: Optional[regex_ast.Node]) -> str:
    return "".join(shape_tokens(node))


def canonical_tokens(node: Optional[regex_ast.Node]) -> List[str]:
    """Semantic fingerprint that ignores capture-group spelling.

    Unlike the shape fingerprint it keeps character-class identity, so
    ``a`` and ``b`` are different, but ``\\w`` and ``[0-9A-Za-z_]`` are the
    same.  Capturing, non-capturing, named and inline-flag groups all collapse
    to the same token; atomic groups, lookarounds and possessive/lazy
    quantifiers remain distinct because they change the semantics.
    """

    if node is None:
        return []
    if isinstance(node, regex_ast.Char):
        return ["C:" + node.chars.to_key()]
    if isinstance(node, regex_ast.Empty):
        return ["E"]
    if isinstance(node, regex_ast.Anchor):
        return ["^" + node.kind]
    if isinstance(node, regex_ast.Backref):
        return ["B:" + (str(node.index) if node.index is not None else node.ref)]
    if isinstance(node, regex_ast.Unsupported):
        return ["U:" + (node.raw or "")]
    if isinstance(node, regex_ast.Seq):
        out: List[str] = ["S("]
        for item in node.items:
            out.extend(canonical_tokens(item))
        out.append(")")
        return out
    if isinstance(node, regex_ast.Alt):
        out = ["A("]
        for index, option in enumerate(node.options):
            if index:
                out.append("|")
            out.extend(canonical_tokens(option))
        out.append(")")
        return out
    if isinstance(node, regex_ast.Repeat):
        return (["R" + _repeat_token(node) + "("] +
                canonical_tokens(node.node) + [")"])
    if isinstance(node, regex_ast.Group):
        if node.kind == "atomic":
            kind = "Gatomic"
        elif node.kind in ("lookahead", "lookbehind",
                           "negative_lookahead", "negative_lookbehind"):
            kind = "G" + node.kind
        else:
            kind = "G"           # capturing/noncapturing/named/flags
        return [kind + "("] + canonical_tokens(node.node) + [")"]
    return ["?"]


def canonical_of(node: Optional[regex_ast.Node]) -> str:
    return "".join(canonical_tokens(node))


def _shape_eligible(tokens: Sequence[str]) -> bool:
    """Ignore trivial fingerprints: no repetition means no ReDoS ambiguity."""
    return len(tokens) >= 6 and any(token.startswith("R") for token in tokens)


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------

@dataclass
class Core:
    rule: str
    kind: str                 # exponential | polynomial
    shape: str
    source: str


class PatternProfile:
    """Parsed/normalised view of one pattern, computed lazily and cached."""

    __slots__ = ("pattern", "dialect", "flags", "hash", "parsed", "parse_error",
                 "canonical", "tokens", "shape", "_static", "_cores")

    def __init__(self, pattern: str, dialect: str, flags: str = "",
                 static=None):
        self.pattern = pattern
        self.dialect = dialect or "python"
        self.flags = flags or ""
        self.hash = pattern_hash(pattern, self.dialect, self.flags)
        self.parsed = None
        self.parse_error: Optional[str] = None
        try:
            self.parsed = regex_ast.parse(pattern, self.dialect, self.flags)
        except Exception as exc:  # parse errors are not fatal for matching
            self.parse_error = f"{type(exc).__name__}: {exc}"
        try:
            self.canonical = (canonical_of(self.parsed.ast)
                              if self.parsed is not None else pattern)
        except Exception as exc:
            self.parse_error = self.parse_error or f"{type(exc).__name__}: {exc}"
            self.canonical = pattern
        try:
            self.tokens = (shape_tokens(self.parsed.ast)
                           if self.parsed is not None else [])
        except Exception as exc:
            self.parse_error = self.parse_error or f"{type(exc).__name__}: {exc}"
            self.tokens = []
        self.shape = "".join(self.tokens)
        self._static = static
        self._cores: Optional[List[Core]] = None

    @property
    def parsed_ok(self) -> bool:
        return self.parsed is not None

    def static_analysis(self):
        if self._static is None:
            if not self.parsed_ok:
                return None
            self._static = heuristics.analyze(
                self.pattern, dialect=self.dialect, flags=self.flags)
        return self._static

    def complexity(self) -> str:
        static = self.static_analysis()
        return static.complexity if static is not None else Complexity.UNKNOWN.value

    def cores(self) -> List[Core]:
        if self._cores is None:
            self._cores = _extract_cores(
                self.static_analysis(),
                self.parsed.ast if self.parsed is not None else None,
                self.dialect,
            )
        return self._cores


def _extract_cores(static, ast, dialect: str) -> List[Core]:
    if static is None:
        return []
    cores: List[Core] = []
    seen = set()

    def add(rule: str, kind: str, source: str) -> None:
        try:
            node = regex_ast.parse(source, dialect=dialect)
        except Exception:
            return
        shape = shape_of(node.ast)
        if len(shape) < 3:
            return
        key = (kind, shape)
        if key in seen:
            return
        seen.add(key)
        cores.append(Core(rule=rule, kind=kind,
                          shape=shape, source=node.normalized))

    for evidence in static.evidence:
        if evidence.rule not in _CORE_RULES:
            continue
        kind = ("polynomial" if evidence.rule == "sequential_overlap"
                else "exponential")
        if evidence.node:
            add(evidence.rule, kind, evidence.node)
        # Do not add the bare inner/left/right fragments here: a fragment such
        # as "\\s*" or "(a+)" matches almost every other ReDoS pattern and
        # produces cross-advisory false positives.  The full witness node keeps
        # enough surrounding structure to be meaningful.

    if not cores and ast is not None:
        complexity = static.complexity
        if complexity in _COMPLEXITY_KIND:
            shape = shape_of(ast)
            if len(shape) >= 3:
                cores.append(Core(rule="pattern",
                                  kind=_COMPLEXITY_KIND[complexity],
                                  shape=shape, source=ast.to_source()))
    return cores


def _structural_eligible(profile: PatternProfile) -> bool:
    """Shape/core/fuzzy matching requires a structurally dangerous finding."""
    complexity = profile.complexity()
    return complexity in (Complexity.EXPONENTIAL.value,
                          Complexity.POLYNOMIAL.value,
                          Complexity.UNKNOWN.value)


def _core_score(observed: PatternProfile,
                known: PatternProfile) -> Optional[float]:
    obs_complexity = observed.complexity()
    known_complexity = known.complexity()
    if (obs_complexity != known_complexity
            and Complexity.UNKNOWN.value not in (obs_complexity, known_complexity)):
        return None
    best: Optional[float] = None
    for left in observed.cores():
        for right in known.cores():
            if left.kind != right.kind or left.shape != right.shape:
                continue
            score = 0.80
            if left.source == right.source:
                score = 0.88
            if left.rule == right.rule:
                score += 0.02
            if best is None or score > best:
                best = score
    return best


def _fuzzy_score(observed: PatternProfile, known: PatternProfile,
                 min_score: float, max_length: int = 2048) -> Optional[float]:
    if not observed.parsed_ok or not known.parsed_ok:
        return None
    if not observed.shape or not known.shape:
        return None
    observed_len = len(observed.canonical)
    known_len = len(known.canonical)
    if max(observed_len, known_len) > max_length:
        return None
    if min(observed_len, known_len) == 0:
        return None
    length_ratio = observed_len / known_len
    if not 0.55 <= length_ratio <= 1.8:
        return None
    if not _shape_eligible(observed.tokens) or not _shape_eligible(known.tokens):
        return None

    matcher = difflib.SequenceMatcher(
        None, observed.canonical, known.canonical, autojunk=False)
    if matcher.real_quick_ratio() < min_score or matcher.quick_ratio() < min_score:
        return None
    ratio = matcher.ratio()
    if ratio < min_score:
        return None
    shape_ratio = difflib.SequenceMatcher(
        None, observed.shape, known.shape, autojunk=False).ratio()
    if shape_ratio < 0.72:
        return None
    # Keep fuzzy below exact/canonical, even for a one-character change.
    return round(min(0.94, 0.90 * ratio + 0.10 * shape_ratio), 4)


# ---------------------------------------------------------------------------
# database model
# ---------------------------------------------------------------------------

@dataclass
class KnownPattern:
    pattern: str
    flags: str = ""
    status: str = "vulnerable"
    note: Optional[str] = None
    dialect: Optional[str] = None
    witness: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {"pattern": self.pattern}
        if self.flags:
            data["flags"] = self.flags
        if self.status != "vulnerable":
            data["status"] = self.status
        if self.dialect:
            data["dialect"] = self.dialect
        if self.note:
            data["note"] = self.note
        if self.witness:
            data["witness"] = dict(self.witness)
        return data


@dataclass
class KnownEntry:
    id: str
    title: str
    language: str = "any"
    cve: Optional[str] = None
    severity: str = "high"
    packages: List[str] = field(default_factory=list)
    affected: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    patterns: List[KnownPattern] = field(default_factory=list)
    source: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        if self.raw:
            return json.loads(json.dumps(self.raw, ensure_ascii=False))
        data: Dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "language": self.language,
            "severity": self.severity,
            "patterns": [pattern.to_dict() for pattern in self.patterns],
        }
        if self.cve:
            data["cve"] = self.cve
        if self.packages:
            data["packages"] = list(self.packages)
        if self.affected:
            data["affected"] = list(self.affected)
        if self.references:
            data["references"] = list(self.references)
        if self.notes:
            data["notes"] = list(self.notes)
        return data


class KnownDatabase:
    def __init__(self, entries: Sequence[KnownEntry], *,
                 source: Optional[str] = None,
                 schema_version: str = SCHEMA_VERSION,
                 updated: Optional[str] = None,
                 notes: Optional[Sequence[str]] = None):
        self.entries = list(entries)
        self.source = source
        self.schema_version = schema_version
        self.updated = updated
        self.notes = list(notes or [])
        self._profiles: Dict[Tuple[str, str, str], PatternProfile] = {}

    # -- construction -------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[str]) -> "KnownDatabase":
        if not path:
            return cls([], source=None)
        with open(path, "r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}: invalid JSON ({exc})") from exc
        return cls.from_dict(data, source=os.path.abspath(path))

    @classmethod
    def from_dict(cls, data: Any, *,
                  source: Optional[str] = None) -> "KnownDatabase":
        if not isinstance(data, dict):
            raise ValueError("known database must be a JSON object")
        raw_entries = data.get("entries")
        if not isinstance(raw_entries, list):
            raise ValueError("known database must contain an 'entries' list")
        errors: List[str] = []
        entries: List[KnownEntry] = []
        seen_ids = set()
        for index, item in enumerate(raw_entries):
            if not isinstance(item, dict):
                errors.append(f"entries[{index}]: expected an object")
                continue
            entry = _parse_entry(item, index, source, errors)
            if entry is None:
                continue
            if entry.id in seen_ids:
                errors.append(f"entries[{index}]: duplicate id {entry.id!r}")
                continue
            seen_ids.add(entry.id)
            entries.append(entry)
        if errors:
            raise ValueError("invalid known database:\n  - " + "\n  - ".join(errors))
        schema = data.get("schema_version") or SCHEMA_VERSION
        return cls(entries, source=source, schema_version=str(schema),
                   updated=data.get("updated"),
                   notes=list(data.get("notes") or []))

    @classmethod
    def bundled(cls) -> "KnownDatabase":
        if not os.path.isfile(BUNDLED_DB):
            return cls([], source=None,
                       notes=[f"bundled database not found at {BUNDLED_DB}"])
        return cls.load(BUNDLED_DB)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "schema_version": self.schema_version,
            "entries": [entry.to_dict() for entry in self.entries],
        }
        if self.updated:
            data["updated"] = self.updated
        if self.notes:
            data["notes"] = list(self.notes)
        return data

    def merge(self, other: "KnownDatabase") -> "KnownDatabase":
        """Return a new database where entries from ``other`` win by id."""
        by_id: Dict[str, Dict[str, Any]] = {
            entry.id: entry.to_dict() for entry in self.entries}
        order = [entry.id for entry in self.entries]
        for entry in other.entries:
            if entry.id not in by_id:
                order.append(entry.id)
            by_id[entry.id] = entry.to_dict()
        data = {
            "schema_version": self.schema_version,
            "updated": other.updated or self.updated,
            "entries": [by_id[identifier] for identifier in order],
        }
        return KnownDatabase.from_dict(data, source=self.source or other.source)

    # -- introspection ------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        languages: Dict[str, int] = {}
        severities: Dict[str, int] = {}
        cves = []
        packages = set()
        vulnerable = 0
        for entry in self.entries:
            languages[entry.language] = languages.get(entry.language, 0) + 1
            severities[entry.severity] = severities.get(entry.severity, 0) + 1
            if entry.cve:
                cves.append(entry.cve)
            packages.update(entry.packages)
            vulnerable += sum(1 for pattern in entry.patterns
                              if pattern.status == "vulnerable")
        return {
            "source": self.source,
            "schema_version": self.schema_version,
            "updated": self.updated,
            "entries": len(self.entries),
            "patterns": sum(len(entry.patterns) for entry in self.entries),
            "vulnerable_patterns": vulnerable,
            "by_language": languages,
            "by_severity": severities,
            "cves": sorted(cves),
            "packages": sorted(packages),
        }

    # -- matching -----------------------------------------------------------
    def _profile(self, pattern: str, dialect: str,
                 flags: str = "") -> PatternProfile:
        dialect = (dialect or "python").lower()
        key = (dialect, "".join(sorted(set(flags or ""))), pattern)
        profile = self._profiles.get(key)
        if profile is None:
            profile = PatternProfile(pattern, dialect, flags)
            self._profiles[key] = profile
        return profile

    def observe(self, pattern: str, dialect: str, flags: str = "",
                static=None) -> PatternProfile:
        dialect = (dialect or "python").lower()
        key = (dialect, "".join(sorted(set(flags or ""))), pattern)
        profile = self._profiles.get(key)
        if profile is None or (static is not None and profile._static is None):
            profile = PatternProfile(pattern, dialect, flags, static=static)
            self._profiles[key] = profile
        return profile

    def match(self, pattern: Optional[str], dialect: str, flags: str = "",
              *, package: str = "", static=None,
              options: Optional[KnownOptions] = None) -> List[KnownMatch]:
        options = options or KnownOptions()
        observed = (self.observe(pattern, dialect, flags, static=static)
                    if pattern else None)
        results: List[KnownMatch] = []
        for entry in self.entries:
            if not _language_compatible(entry.language, dialect):
                continue
            if observed is None:
                match = self._package_match(entry, package, options)
            else:
                match = self._match_entry(entry, observed, package, options)
            if match is not None:
                results.append(match)
        results.sort(key=lambda item: (-item.score, item.cve or "", item.id))
        if options.max_matches and options.max_matches > 0:
            results = results[:options.max_matches]
        return results

    def match_finding(self, finding: Finding,
                      options: Optional[KnownOptions] = None) -> List[KnownMatch]:
        return self.match(
            finding.pattern, finding.dialect, finding.flags or "",
            package=finding.package,
            static=finding.static,
            options=options,
        )

    def annotate(self, finding: Finding,
                 options: Optional[KnownOptions] = None) -> None:
        options = options or KnownOptions()
        finding.known = self.match_finding(finding, options)
        if not options.auto_assign_cve or finding.cve:
            return
        for match in finding.known:
            if not match.cve:
                continue
            if match.score < options.auto_assign_min_score:
                continue
            # Only an unambiguous pattern identity may assign a CVE.
            if not ({"exact", "canonical"} & set(match.match_types)):
                continue
            finding.cve = match.cve
            finding.cve_source = f"known:{match.id}"
            match.auto_assigned = True
            break

    def _package_match(self, entry: KnownEntry, package: str,
                       options: KnownOptions) -> Optional[KnownMatch]:
        """Match an advisory that has no pattern against a source package.

        Package-only advisories describe cases where the upstream fix was not
        a regexp change (for example an input-length limit), so they are the
        only thing that can be attached to a patternless dynamic finding.
        """
        if (not options.match_packages or entry.patterns or not package
                or not _package_matches(package, entry.packages)):
            return None
        return KnownMatch(
            id=entry.id,
            title=entry.title,
            cve=entry.cve,
            language=entry.language,
            severity=entry.severity,
            kind="package",
            score=0.40,
            confidence="low",
            match_types=["package"],
            pattern_matched=False,
            package_match=True,
            source=entry.source or self.source,
            references=list(entry.references),
            notes=list(entry.notes) + [
                "package matches the advisory, but no known pattern "
                "is available for comparison"
            ],
        )

    def _match_entry(self, entry: KnownEntry, observed: PatternProfile,
                     package: str, options: KnownOptions) -> Optional[KnownMatch]:
        best: Optional[Tuple[float, List[str], KnownPattern]] = None
        # Short advisories such as ``\A(0|[1-9]+\d*)\z`` have a very generic
        # core (``X+Y*``) that would otherwise match unrelated expressions.
        # An entry can opt out of core matching while exact/canonical/shape
        # still work.
        entry_options = (replace(options, match_core=False)
                         if entry.raw.get("match_core") is False else options)
        for known_pattern in entry.patterns:
            if known_pattern.status != "vulnerable":
                continue
            if known_pattern.dialect:
                dialect = known_pattern.dialect
            elif entry.language in ("any", "*", ""):
                # Language-agnostic advisories are interpreted with the
                # dialect of the pattern being scanned so that an identical
                # expression still yields an exact match.
                dialect = observed.dialect
            else:
                dialect = entry.language
            profile = self._profile(known_pattern.pattern, dialect,
                                    known_pattern.flags)
            types, score = self._compare(observed, profile, entry_options)
            if not types:
                continue
            if best is None or score > best[0]:
                best = (score, types, known_pattern)

        if best is None:
            return self._package_match(entry, package, options)

        score, types, known_pattern = best
        package_match = (bool(package) and _package_matches(package, entry.packages))
        notes = list(entry.notes)
        if package_match:
            notes.append("the source package name also matches the advisory")
        return KnownMatch(
            id=entry.id,
            title=entry.title,
            cve=entry.cve,
            language=entry.language,
            severity=entry.severity,
            kind=_primary_type(types),
            score=round(score, 4),
            confidence=_confidence(score),
            match_types=types,
            matched_pattern=known_pattern.pattern,
            matched_flags=known_pattern.flags,
            witness=dict(known_pattern.witness) if known_pattern.witness else None,
            pattern_matched=True,
            package_match=package_match,
            source=entry.source or self.source,
            references=list(entry.references),
            notes=notes,
        )

    def _compare(self, observed: PatternProfile, known: PatternProfile,
                 options: KnownOptions) -> Tuple[List[str], float]:
        types: List[str] = []
        score = 0.0

        if observed.hash == known.hash:
            return ["exact"], 1.0

        if (observed.parsed_ok and known.parsed_ok
                and observed.canonical and observed.canonical == known.canonical):
            types.append("canonical")
            score = 0.97

        structural = _structural_eligible(observed)
        if (structural and known.shape and observed.shape == known.shape
                and _shape_eligible(observed.tokens)
                and _shape_eligible(known.tokens)):
            types.append("shape")
            score = max(score, 0.82)

        if options.match_core and structural:
            core_score = _core_score(observed, known)
            if core_score is not None:
                types.append("core")
                score = max(score, core_score)

        fuzzy_score = None
        if structural and options.min_score > 0:
            fuzzy_score = _fuzzy_score(observed, known, options.min_score)
            if fuzzy_score is not None:
                types.append("fuzzy")
                score = max(score, fuzzy_score)

        types.sort(key=lambda item: _MATCH_ORDER.index(item)
                   if item in _MATCH_ORDER else len(_MATCH_ORDER))
        return types, score


def _parse_entry(item: Dict[str, Any], index: int, source: Optional[str],
                 errors: List[str]) -> Optional[KnownEntry]:
    identifier = item.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        errors.append(f"entries[{index}]: 'id' must be a non-empty string")
        return None
    identifier = identifier.strip()
    title = item.get("title") or identifier
    if not isinstance(title, str):
        errors.append(f"entries[{index}]: 'title' must be a string")
        title = identifier
    language = str(item.get("language") or "any").lower()
    severity = str(item.get("severity") or "high").lower()
    cve = item.get("cve")
    if cve is not None and not isinstance(cve, str):
        errors.append(f"entries[{index}]: 'cve' must be a string or null")
        cve = None

    def _string_list(key: str) -> List[str]:
        value = item.get(key) or []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            errors.append(f"entries[{index}]: '{key}' must be a list of strings")
            return []
        return list(value)

    patterns: List[KnownPattern] = []
    raw_patterns = item.get("patterns") or []
    if not isinstance(raw_patterns, list):
        errors.append(f"entries[{index}]: 'patterns' must be a list")
        raw_patterns = []
    for pattern_index, raw in enumerate(raw_patterns):
        label = f"entries[{index}].patterns[{pattern_index}]"
        if isinstance(raw, str):
            if not raw:
                errors.append(f"{label}: pattern must not be empty")
                continue
            patterns.append(KnownPattern(
                pattern=raw,
                dialect=None if language in ("any", "*", "") else language,
            ))
            continue
        if not isinstance(raw, dict):
            errors.append(f"{label}: expected a string or an object")
            continue
        pattern = raw.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            errors.append(f"{label}: 'pattern' must be a non-empty string")
            continue
        status = str(raw.get("status") or "vulnerable").lower()
        if status not in ("vulnerable", "fixed", "test"):
            errors.append(f"{label}: 'status' must be vulnerable, fixed or test")
            continue
        flags = raw.get("flags") or ""
        if not isinstance(flags, str):
            errors.append(f"{label}: 'flags' must be a string")
            flags = ""
        dialect = raw.get("dialect")
        if dialect is not None and not isinstance(dialect, str):
            errors.append(f"{label}: 'dialect' must be a string")
            dialect = None
        note = raw.get("note")
        if note is not None and not isinstance(note, str):
            errors.append(f"{label}: 'note' must be a string")
            note = None
        witness = _parse_witness(raw.get("witness"), label, errors)
        patterns.append(KnownPattern(
            pattern=pattern,
            flags=flags,
            status=status,
            note=note,
            dialect=dialect or (None if language in ("any", "*", "") else language),
            witness=witness,
        ))

    return KnownEntry(
        id=identifier,
        title=title,
        language=language,
        cve=cve,
        severity=severity,
        packages=_string_list("packages"),
        affected=_string_list("affected"),
        references=_string_list("references"),
        notes=_string_list("notes"),
        patterns=patterns,
        source=source,
        raw=item,
    )


def _parse_witness(value: Any, label: str,
                   errors: List[str]) -> Optional[Dict[str, Any]]:
    """Validate an optional advisory-provided attack witness.

    The witness has the same shape as :class:`AttackWitness`: ``prefix``,
    ``pump``, ``suffix``, ``breaker`` and ``kind``.  Unknown extra keys are
    dropped so a malformed advisory cannot crash the dynamic stage.
    """
    if value is None:
        return None
    if not isinstance(value, dict):
        errors.append(f"{label}: 'witness' must be an object")
        return None
    witness: Dict[str, Any] = {}
    for key in ("prefix", "pump", "suffix", "breaker", "kind", "note"):
        item = value.get(key)
        if item is None:
            continue
        if not isinstance(item, str):
            errors.append(f"{label}.witness: '{key}' must be a string")
            return None
        witness[key] = item
    kind = witness.get("kind", "exponential")
    if kind not in ("exponential", "polynomial"):
        errors.append(f"{label}.witness: 'kind' must be exponential or polynomial")
        return None
    if not witness.get("pump"):
        errors.append(f"{label}.witness: 'pump' must be a non-empty string")
        return None
    return witness


def _language_compatible(entry_language: str, finding_language: str) -> bool:
    entry = (entry_language or "any").lower()
    finding = (finding_language or "").lower()
    return entry in ("any", "*", "") or entry == finding


def _package_matches(package: str, names: Sequence[str]) -> bool:
    """Best-effort source-package match (ruby3.1 ~ ruby, ruby-uri ~ uri)."""
    if not package:
        return False
    candidate = package.lower().replace("_", "-")
    for name in names or []:
        normalized = str(name).lower().replace("_", "-").strip()
        if not normalized:
            continue
        if candidate == normalized:
            return True
        if candidate.startswith(normalized + "-") or candidate.startswith(normalized + "."):
            return True
        if (candidate.startswith(normalized)
                and candidate[len(normalized):len(normalized) + 1].isdigit()):
            return True
        if normalized.startswith(candidate + "-") or normalized.startswith(candidate + "."):
            return True
    return False


def _primary_type(types: Sequence[str]) -> str:
    for name in _MATCH_ORDER:
        if name in types:
            return name
    return types[0] if types else "fuzzy"


def _confidence(score: float) -> str:
    if score >= 0.95:
        return "high"
    if score >= 0.80:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# helpers used by the pipeline / CLI
# ---------------------------------------------------------------------------

def load_database(config, log=None) -> Optional[KnownDatabase]:
    """Load the configured database (or the bundled one)."""
    if not config.get("known.enabled", True):
        return None
    path = config.get("known.db")
    try:
        if path:
            database = KnownDatabase.load(path)
            if log:
                log(f"known database: {path} ({len(database.entries)} entries)")
            return database
        database = KnownDatabase.bundled()
        if log:
            log(f"known database: bundled ({len(database.entries)} entries)")
        return database
    except (OSError, ValueError) as exc:
        if log:
            log(f"known database not loaded: {exc}")
        return None


def apply_known(finding: Finding, database: Optional[KnownDatabase],
                options: Optional[KnownOptions] = None) -> None:
    if database is None:
        return
    database.annotate(finding, options)


def resolve_database_path(config) -> str:
    """Path shown by the CLI: configured DB, otherwise the bundled file."""
    return config.get("known.db") or BUNDLED_DB
