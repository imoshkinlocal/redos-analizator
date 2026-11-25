"""Structural ReDoS analysis ("heuristics" detector).

The detector combines three sources of evidence:

1. structural rules over the AST (nested quantifiers, nullable bodies,
   overlapping sequential repetitions, bounded repeats of unbounded bodies);
2. a real ambiguity measurement over a Thompson NFA (path counting), which is
   what distinguishes ``(a|aa)+`` from ``(ab|a)+``;
3. an attack witness (prefix / pump / suffix / breaker) that the dynamic
   verifier can execute.

Every conclusion is emitted as machine-readable :class:`Evidence`, and a static
"exponential" verdict is explicitly a *hypothesis*: only the dynamic stage can
promote a finding to ``confirmed``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .. import models
from ..models import (
    Complexity,
    Evidence,
    SourceType,
    StaticAnalysis,
    StaticStatus,
)
from . import attacks, regex_ast
from .nfa import StateLimitExceeded, ambiguity_of, repeat_ambiguity, sequential_overlap
from .regex_ast import (
    Alt,
    Anchor,
    Backref,
    Char,
    CharSet,
    Empty,
    Group,
    Node,
    ParseResult,
    RegexParseError,
    Repeat,
    Seq,
    Unsupported,
    all_chars,
    contains_unbounded_repeat,
    first_chars,
    iter_repeats,
    last_chars,
    max_len,
    min_len,
    nullable,
    parse,
    shortest_sample,
)

DETECTOR_NAME = "heuristics"

CONFIDENCE = {
    "nested_quantifier": 0.92,
    "nullable_body": 0.9,
    "ambiguous_repetition": 0.86,
    "bounded_ambiguous_repeat": 0.72,
    "sequential_overlap": 0.75,
    "backreference_in_repeat": 0.4,
    "unsupported_in_repeat": 0.3,
}


@dataclass
class Hint:
    rule: str
    kind: str                       # exponential | polynomial | unknown
    confidence: float
    message: str
    repeat: Optional[Repeat] = None
    pump: str = ""
    node: Optional[Node] = None
    details: Dict[str, object] = field(default_factory=dict)

    def to_evidence(self) -> Evidence:
        span = None
        if self.node is not None and self.node.start >= 0:
            span = [self.node.start, self.node.end]
        return Evidence(
            rule=self.rule,
            message=self.message,
            node=self.node.to_source() if self.node is not None else None,
            span=span,
            details=dict(self.details),
        )


@dataclass
class AnalysisContext:
    """Everything the rules need to know about one pattern."""
    ast: Node
    parsed: ParseResult
    dialect: str
    flags: str
    max_pattern_length: int = 4096
    approx: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def analyze(
    pattern: Optional[str],
    dialect: str = "python",
    flags: str = "",
    *,
    max_pattern_length: int = 4096,
    max_candidates: int = 4,
    source_type: str = SourceType.LITERAL.value,
) -> StaticAnalysis:
    if pattern is None:
        return StaticAnalysis(
            status=StaticStatus.DYNAMIC_PATTERN_UNRESOLVED.value,
            complexity=Complexity.UNKNOWN.value,
            confidence=0.5,
            detector=DETECTOR_NAME,
            notes=["pattern value could not be resolved statically"],
        )
    if len(pattern) > max_pattern_length:
        return StaticAnalysis(
            status=StaticStatus.UNSUPPORTED.value,
            complexity=Complexity.UNKNOWN.value,
            confidence=0.0,
            detector=DETECTOR_NAME,
            notes=[f"pattern longer than {max_pattern_length} characters, skipped"],
        )

    try:
        parsed = parse(pattern, dialect=dialect, flags=flags)
    except RegexParseError as exc:
        return StaticAnalysis(
            status=StaticStatus.UNSUPPORTED.value,
            complexity=Complexity.UNKNOWN.value,
            confidence=0.0,
            detector=DETECTOR_NAME,
            notes=[f"parse error: {exc}"],
        )

    ctx = AnalysisContext(ast=parsed.ast, parsed=parsed, dialect=dialect, flags=flags,
                          max_pattern_length=max_pattern_length,
                          approx=list(parsed.notes))
    hints = collect_hints(ctx)
    return _summarise(ctx, hints, max_candidates=max_candidates)


def analyze_node(node: Node, dialect: str = "python") -> StaticAnalysis:
    """Analyse an already parsed sub-expression (used by tests/tools)."""
    parsed = ParseResult(ast=node, normalized=node.to_source(), flags=set())
    ctx = AnalysisContext(ast=node, parsed=parsed, dialect=dialect, flags="")
    return _summarise(ctx, collect_hints(ctx), max_candidates=4)


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

def collect_hints(ctx: AnalysisContext) -> List[Hint]:
    hints: List[Hint] = []
    seen: set = set()

    def add(hint: Hint) -> None:
        key = (hint.rule, id(hint.repeat) if hint.repeat is not None else None,
               hint.details.get("inner"))
        if key in seen:
            return
        seen.add(key)
        hints.append(hint)

    for repeat, path in iter_repeats(ctx.ast):
        if _in_non_backtracking_context(repeat, path):
            continue
        if repeat.possessive:
            continue
        try:
            hints.extend(_rules_for_repeat(ctx, repeat))
        except StateLimitExceeded:
            add(Hint(rule="unsupported_in_repeat", kind="unknown",
                     confidence=CONFIDENCE["unsupported_in_repeat"],
                     message="automaton too large to analyse this repetition",
                     repeat=repeat, node=repeat))
        except RecursionError:
            add(Hint(rule="unsupported_in_repeat", kind="unknown",
                     confidence=CONFIDENCE["unsupported_in_repeat"],
                     message="pattern nesting too deep to analyse",
                     repeat=repeat, node=repeat))

    hints.extend(_sequential_hints(ctx))

    # de-duplicate identical (rule, node) pairs produced by nested repeats
    unique: List[Hint] = []
    keys = set()
    for hint in hints:
        key = (hint.rule, hint.node.start if hint.node is not None else -1,
               hint.node.end if hint.node is not None else -1)
        if key in keys:
            continue
        keys.add(key)
        unique.append(hint)
    return unique


def _in_non_backtracking_context(repeat: Repeat, path: Sequence[Node]) -> bool:
    for ancestor in path:
        if isinstance(ancestor, Group) and ancestor.kind == "atomic":
            return True
        if isinstance(ancestor, Repeat) and ancestor.possessive:
            return True
    return False


def _path_is_protected(path: Sequence[Node]) -> bool:
    """True when an atomic group / possessive repeat encloses the node."""
    for ancestor in path:
        if isinstance(ancestor, Group) and ancestor.kind == "atomic":
            return True
        if isinstance(ancestor, Repeat) and ancestor.possessive:
            return True
    return False


def _body_non_backtracking(body: Node) -> bool:
    """True when every unbounded repeat in ``body`` is atomic/possessive.

    ``(?>a+)+`` and ``(a++)+`` cannot split the run of ``a`` between
    iterations, so the classic exponential shape does not apply.  Bounded
    repeats are ignored here: ``(a?)*`` still needs the nullable-body rule.
    """
    if isinstance(body, Group) and body.kind == "atomic":
        return True
    if isinstance(body, Repeat) and body.possessive:
        return True
    saw_unbounded = False
    for sub, path in iter_repeats(body):
        if sub.max is None and not sub.possessive:
            saw_unbounded = True
            if not _path_is_protected(path):
                return False
        elif sub.possessive or _path_is_protected(path):
            saw_unbounded = True
    return saw_unbounded


def _rules_for_repeat(ctx: AnalysisContext, repeat: Repeat) -> List[Hint]:
    hints: List[Hint] = []
    body = repeat.node
    if body is None:
        return hints
    # An atomic group never gives characters back, so a quantifier inside it
    # cannot be re-split by the outer repetition.
    if _body_non_backtracking(body):
        return hints

    unbounded = repeat.max is None

    # --- rule 1: nested unbounded quantifiers -----------------------------
    if unbounded:
        inner_unbounded = [
            sub for sub, path in iter_repeats(body)
            if sub.max is None and not sub.possessive and not _path_is_protected(path)
        ]
        if inner_unbounded:
            overlap = first_chars(body).intersect(last_chars(body))
            if overlap:
                pump = _pump_for_nested(inner_unbounded[0], overlap)
                hints.append(Hint(
                    rule="nested_quantifier",
                    kind="exponential",
                    confidence=CONFIDENCE["nested_quantifier"],
                    message=(
                        "unbounded quantifier applied to an unbounded group whose "
                        "first and last character sets overlap: the same characters "
                        "can be split between the inner and outer repetition"
                    ),
                    repeat=repeat,
                    pump=pump,
                    node=repeat,
                    details={
                        "outer": repeat.to_source(),
                        "inner": inner_unbounded[0].to_source(),
                        "overlap": overlap.to_source(),
                        "pump": pump,
                    },
                ))

    # --- rule 2: nullable body inside unbounded repetition ----------------
    if unbounded and nullable(body):
        pump = _body_pump(body)
        hints.append(Hint(
            rule="nullable_body",
            kind="exponential",
            confidence=CONFIDENCE["nullable_body"],
            message=(
                "unbounded quantifier over an expression that can match the empty "
                "string: every iteration can loop without consuming input"
            ),
            repeat=repeat,
            pump=pump,
            node=repeat,
            details={"pump": pump, "nullable_body": body.to_source()},
        ))

    # --- rule 3: measured ambiguity of the repeated unit -------------------
    if unbounded:
        result = repeat_ambiguity(repeat)
        if result.ambiguous and result.pump:
            hints.append(Hint(
                rule="ambiguous_repetition",
                kind="exponential",
                confidence=CONFIDENCE["ambiguous_repetition"],
                message=(
                    f"repeated expression has {result.path_count}+ distinct parses "
                    f"for {result.pump!r}: repeating the unit multiplies the number "
                    "of backtracking paths"
                ),
                repeat=repeat,
                pump=result.pump,
                node=repeat,
                details={"pump": result.pump, "path_count": result.path_count},
            ))

    # --- rule 4: bounded repetition of an ambiguous unbounded body --------
    if repeat.max is not None and repeat.max >= 4 and contains_unbounded_repeat(body):
        overlap = first_chars(body).intersect(last_chars(body))
        if overlap:
            pump = _body_pump(body)
            hints.append(Hint(
                rule="bounded_ambiguous_repeat",
                kind="exponential",
                confidence=CONFIDENCE["bounded_ambiguous_repeat"],
                message=(
                    f"bounded repetition {{...{repeat.max}}} of a body containing an "
                    "unbounded quantifier with overlapping character sets: each "
                    "iteration can consume characters needed by the next one"
                ),
                repeat=repeat,
                pump=pump,
                node=repeat,
                details={"pump": pump, "count": repeat.max,
                         "overlap": overlap.to_source()},
            ))

    # --- rule 4b: large bounded repetition of an ambiguous body -----------
    if repeat.max is not None and repeat.max >= 16 and not hints:
        body_ambiguous = nullable(body)
        if not body_ambiguous:
            body_ambiguous = ambiguity_of(body, cap=8).ambiguous
        if body_ambiguous:
            pump = _body_pump(body)
            hints.append(Hint(
                rule="bounded_ambiguous_repeat",
                kind="exponential",
                confidence=0.55,
                message=(
                    f"repetition bounded at {repeat.max} over an ambiguous body: the "
                    "number of backtracking paths grows with the bound (2^n in the "
                    "worst case)"
                ),
                repeat=repeat,
                pump=pump,
                node=repeat,
                details={"pump": pump, "count": repeat.max},
            ))

    # --- rule 5: backreference inside a repetition ------------------------
    if unbounded and any(isinstance(sub, Backref) for sub in body.walk()):
        hints.append(Hint(
            rule="backreference_in_repeat",
            kind="unknown",
            confidence=CONFIDENCE["backreference_in_repeat"],
            message="backreference inside a quantifier: not modelled, requires review",
            repeat=repeat,
            node=repeat,
            details={},
        ))

    # --- rule 6: unsupported constructs inside a repetition ---------------
    if unbounded and any(isinstance(sub, Unsupported) for sub in body.walk()):
        hints.append(Hint(
            rule="unsupported_in_repeat",
            kind="unknown",
            confidence=CONFIDENCE["unsupported_in_repeat"],
            message="quantifier contains a construct that could not be modelled",
            repeat=repeat,
            node=repeat,
            details={},
        ))
    return hints


def _sequential_hints(ctx: AnalysisContext) -> List[Hint]:
    """Overlapping unbounded repetitions => polynomial (quadratic) ReDoS."""
    hints: List[Hint] = []
    for node in ctx.ast.walk():
        if not isinstance(node, Seq):
            continue
        items = node.items
        repeat_items = [i for i, item in enumerate(items)
                        if contains_unbounded_repeat(item)]
        for position, left_index in enumerate(repeat_items):
            for right_index in repeat_items[position + 1:]:
                left, right = items[left_index], items[right_index]
                if not _middle_is_absorbable(items[left_index + 1:right_index], left):
                    continue
                common = last_chars(left).intersect(first_chars(right))
                if not common:
                    continue
                pump = _preferred_pump(common)
                repeat = _first_unbounded(left)
                hints.append(Hint(
                    rule="sequential_overlap",
                    kind="polynomial",
                    confidence=CONFIDENCE["sequential_overlap"],
                    message=(
                        "two unbounded quantifiers in the same sequence can consume "
                        "the same characters: the left one backtracks into the right "
                        "one for every possible split point"
                    ),
                    repeat=repeat,
                    pump=pump,
                    node=node,
                    details={
                        "left": left.to_source(),
                        "right": right.to_source(),
                        "overlap": common.to_source(),
                        "pump": pump,
                    },
                ))
                break
    return hints


def _middle_is_absorbable(middle: Sequence[Node], left: Node) -> bool:
    """Can the left repetition consume everything that separates it from right?"""
    if max_len(left) is not None:
        return False
    left_chars = all_chars(left)
    for item in middle:
        if min_len(item) == 0:
            continue
        chars = all_chars(item)
        if not chars or chars.intersect(left_chars) != chars:
            return False
    return True


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _first_unbounded(node: Node) -> Optional[Repeat]:
    for sub in node.walk():
        if isinstance(sub, Repeat) and sub.max is None and not sub.possessive:
            return sub
    return None


def _preferred_pump(chars: CharSet) -> str:
    for ch in ("a", "0", " ", "_", "x", "-", "/"):
        if chars.contains(ch):
            return ch
    sample = chars.first_char()
    return sample or "a"


def _body_pump(body: Node) -> str:
    sample = shortest_sample(body)
    if sample:
        return sample[:4]
    chars = first_chars(body)
    return _preferred_pump(chars) if chars else "a"


def _pump_for_nested(inner: Repeat, overlap: CharSet) -> str:
    inner_sample = shortest_sample(inner.node) if inner.node is not None else ""
    if inner_sample and all(overlap.contains(ch) for ch in inner_sample):
        return inner_sample[:4]
    single = _preferred_pump(overlap)
    return single


def _summarise(ctx: AnalysisContext, hints: List[Hint], max_candidates: int = 4) -> StaticAnalysis:
    evidence = [hint.to_evidence() for hint in hints]
    notes = list(ctx.parsed.notes)

    exponential = [h for h in hints if h.kind == "exponential"]
    polynomial = [h for h in hints if h.kind == "polynomial"]
    unknown = [h for h in hints if h.kind == "unknown"]

    analysis = StaticAnalysis(
        detector=DETECTOR_NAME,
        evidence=evidence,
        notes=notes,
        normalized_pattern=ctx.parsed.normalized,
    )

    chosen: Optional[Hint] = None
    if exponential:
        chosen = max(exponential, key=lambda h: h.confidence)
        analysis.complexity = Complexity.EXPONENTIAL.value
        analysis.confidence = chosen.confidence
        analysis.status = (StaticStatus.VULNERABLE.value
                           if chosen.confidence >= 0.75
                           else StaticStatus.SUSPICIOUS.value)
    elif unknown:
        chosen = max(unknown, key=lambda h: h.confidence)
        analysis.complexity = Complexity.UNKNOWN.value
        analysis.confidence = chosen.confidence
        analysis.status = StaticStatus.SUSPICIOUS.value
    elif polynomial:
        chosen = max(polynomial, key=lambda h: h.confidence)
        analysis.complexity = Complexity.POLYNOMIAL.value
        analysis.confidence = chosen.confidence
        analysis.status = StaticStatus.SUSPICIOUS.value
    else:
        analysis.complexity = (Complexity.LINEAR.value
                               if contains_unbounded_repeat(ctx.ast)
                               else Complexity.NONE.value)
        analysis.confidence = 0.6 if ctx.parsed.unsupported else 0.75
        analysis.status = StaticStatus.SAFE.value
        if ctx.parsed.unsupported and contains_unbounded_repeat(ctx.ast):
            analysis.status = StaticStatus.SUSPICIOUS.value
            analysis.complexity = Complexity.UNKNOWN.value
            analysis.notes.append("analysis is partial: unsupported constructs present")

    if analysis.status in (StaticStatus.VULNERABLE.value, StaticStatus.SUSPICIOUS.value) and chosen:
        plans: List[models.AttackWitness] = []
        if chosen.kind == "exponential" and chosen.repeat is not None:
            raw_plans = attacks.plan_attacks(
                ctx.ast, chosen.repeat, chosen.pump, "exponential", chosen.rule,
                pattern_chars=all_chars(ctx.ast),
                limit=max(1, max_candidates),
            )
        elif chosen.kind == "polynomial" and chosen.repeat is not None:
            raw_plans = attacks.plan_for_sequential(chosen.repeat, chosen.repeat,
                                                    chosen.pump or "a")
        else:
            raw_plans = []
        for plan in raw_plans:
            plans.append(models.AttackWitness(
                prefix=plan.prefix, pump=plan.pump, suffix=plan.suffix,
                breaker=plan.breaker, kind=plan.kind, note=plan.note,
            ))
        analysis.attack_plans = plans
        if plans:
            analysis.witness = plans[0]

    if ctx.parsed.approx:
        analysis.notes.append("some constructs were approximated; confidence reduced")
        analysis.confidence = min(analysis.confidence, 0.6)
    return analysis
