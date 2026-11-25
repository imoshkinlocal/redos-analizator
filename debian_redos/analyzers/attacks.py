"""Attack-string generation from a static witness.

The generator is intentionally structural: it takes the ambiguous repetition
found by the analyser and builds ``prefix + pump*k + suffix + breaker``.  The
dynamic verifier then decides which of the candidate shapes really degrade, so
the generator only has to be *complete enough*, not perfect.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from .regex_ast import (
    Alt,
    Anchor,
    Char,
    CharSet,
    Empty,
    Group,
    Node,
    Repeat,
    Seq,
    shortest_sample,
)

# printable ASCII characters that are rarely part of a legitimately matched
# token; used as "match breakers" so that a failing suffix exists.
_BREAKER_POOL = "!\"#%&',;<=>@`~^]}\u0001\n\t"
_PUMP_ALPHABET = "a0_ x-/:@"


@dataclass
class AttackPlan:
    prefix: str
    pump: str
    suffix: str
    breaker: str
    kind: str = "exponential"
    source_rule: str = ""
    note: Optional[str] = None

    def build(self, repetitions: int, include_suffix: bool = True) -> str:
        body = self.prefix + (self.pump * max(1, repetitions))
        if include_suffix:
            body += self.suffix
        return body + self.breaker

    def to_dict(self) -> dict:
        return {
            "prefix": self.prefix,
            "pump": self.pump,
            "suffix": self.suffix,
            "breaker": self.breaker,
            "kind": self.kind,
            "source_rule": self.source_rule,
        }


def choose_breaker(pattern_chars: CharSet, pump: str, forbidden: Sequence[str] = ()) -> str:
    for ch in _BREAKER_POOL:
        if ch in pump or ch in forbidden:
            continue
        if not pattern_chars.contains(ch):
            return ch
    # the pattern accepts everything (e.g. ``.*``): any character forces the
    # anchor to fail after full backtracking
    for ch in _BREAKER_POOL:
        if ch not in pump and ch not in forbidden:
            return ch
    return "!"


def _pick_pump_chars(pattern_chars: CharSet, fallback: str = "a") -> List[str]:
    out: List[str] = []
    for ch in pattern_chars.sample(8):
        if ch.isprintable() and ch not in out:
            out.append(ch)
    for ch in _PUMP_ALPHABET:
        if pattern_chars.contains(ch) and ch not in out:
            out.append(ch)
    for ch in _PUMP_ALPHABET:
        if ch not in out:
            out.append(ch)
    return out or [fallback]


def plan_attacks(
    ast: Node,
    target: Repeat,
    pump: Optional[str],
    kind: str,
    rule: str,
    pattern_chars: Optional[CharSet] = None,
    limit: int = 2,
) -> List[AttackPlan]:
    """Build up to ``limit`` attack shapes for one ambiguous repetition."""
    from .regex_ast import prefix_before, suffix_after

    prefix = prefix_before(ast, target)
    suffix = suffix_after(ast, target)

    pump_value = pump or ""
    if not pump_value:
        # nullable or empty-pump case: use a character the body can consume
        body_chars = _body_chars(target)
        if body_chars:
            pump_value = body_chars[0]
        else:
            pump_value = "a"
    if len(pump_value) > 8:
        pump_value = pump_value[:8]

    suffix_first = suffix[:1]
    chars = pattern_chars if pattern_chars is not None else CharSet.any()
    breaker = choose_breaker(chars, pump_value, forbidden=[suffix_first] if suffix_first else [])

    plans: List[AttackPlan] = []
    plans.append(AttackPlan(prefix=prefix, pump=pump_value, suffix=suffix,
                            breaker=breaker, kind=kind, source_rule=rule))
    if suffix and len(plans) < limit:
        plans.append(AttackPlan(prefix=prefix, pump=pump_value, suffix="",
                                breaker=breaker, kind=kind, source_rule=rule,
                                note="suffix omitted to attack earlier in the match"))
    if len(plans) < limit and pump_value and len(pump_value) > 1:
        plans.append(AttackPlan(prefix=prefix, pump=pump_value[:1], suffix=suffix,
                                breaker=breaker, kind=kind, source_rule=rule,
                                note="shorter pump unit"))
    return plans[:limit]


def _body_chars(repeat: Repeat) -> List[str]:
    from .regex_ast import first_chars

    chars = first_chars(repeat.node)
    out: List[str] = []
    for ch in chars.sample(8):
        if ch.isprintable():
            out.append(ch)
    for ch in _PUMP_ALPHABET:
        if chars.contains(ch) and ch not in out:
            out.append(ch)
    return out


def plan_for_sequential(first: Repeat, second: Repeat, pump: str) -> List[AttackPlan]:
    """Attack for two overlapping sequential unbounded repetitions (polynomial)."""
    return [AttackPlan(prefix="", pump=pump, suffix="", breaker="!",
                       kind="polynomial", source_rule="sequential_overlap")]
