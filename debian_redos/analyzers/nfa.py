"""Thompson NFA construction and ambiguity measurement.

The NFA is not used to *decide* vulnerability on its own; it is used to answer
one precise question that the structural rules cannot answer reliably:

    does this sub-expression admit two or more distinct parse paths for the
    same string, and can that string be repeated?

If yes, backtracking has to explore an exponentially growing set of parses for
``w**k``.  That is exactly the "exponential degree of ambiguity" (EDA)
condition, and it is measured here by counting accepting paths with a hard cap.

This is what separates ``(a|aa)+`` (ambiguous: ``aa`` has two parses) from
``(ab|a)+`` (unambiguous on every string) without hard-coding pattern shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .regex_ast import (
    Alt,
    Anchor,
    Backref,
    Char,
    CharSet,
    Empty,
    Group,
    Node,
    Repeat,
    Seq,
    Unsupported,
    iter_repeats,
    max_len,
    nullable,
)

MAX_STATES = 6000
MAX_REPEAT_EXPANSION = 8


@dataclass
class NFA:
    transitions: List[List[Tuple[CharSet, int]]] = field(default_factory=list)
    epsilons: List[List[int]] = field(default_factory=list)
    start: int = 0
    accept: int = 0
    approx: List[str] = field(default_factory=list)

    # -- construction -------------------------------------------------------
    def new_state(self) -> int:
        if len(self.transitions) >= MAX_STATES:
            raise StateLimitExceeded(f"NFA exceeded {MAX_STATES} states")
        self.transitions.append([])
        self.epsilons.append([])
        return len(self.transitions) - 1

    def add_edge(self, src: int, dst: int, chars: CharSet) -> None:
        if chars:
            self.transitions[src].append((chars, dst))

    def add_epsilon(self, src: int, dst: int) -> None:
        self.epsilons[src].append(dst)

    # -- queries ------------------------------------------------------------
    def closure(self, states: Iterable[int]) -> Set[int]:
        out: Set[int] = set()
        stack = list(states)
        while stack:
            state = stack.pop()
            if state in out:
                continue
            out.add(state)
            stack.extend(self.epsilons[state])
        return out

    def step(self, states: Iterable[int], ch: str) -> Set[int]:
        targets: Set[int] = set()
        for state in states:
            for chars, dst in self.transitions[state]:
                if chars.contains(ch):
                    targets.add(dst)
        return self.closure(targets)

    def accepts(self, text: str) -> bool:
        states = self.closure([self.start])
        for ch in text:
            states = self.step(states, ch)
            if not states:
                return False
        return self.accept in states

    def path_count(self, text: str, cap: int = 64) -> int:
        """Number of distinct consuming paths accepting ``text`` (capped).

        Epsilon transitions are collapsed per position: they are not counted as
        distinct parses.  That is the right granularity for backtracking cost,
        which is driven by consuming choice points.  Pure-epsilon loops are
        handled separately by the ``nullable body`` rule.
        """
        counts: Dict[int, int] = {self.start: 1}
        counts = self._settle_epsilon(counts, cap)
        for ch in text:
            nxt: Dict[int, int] = {}
            for state, count in counts.items():
                for chars, dst in self.transitions[state]:
                    if chars.contains(ch):
                        nxt[dst] = min(cap, nxt.get(dst, 0) + count)
            if not nxt:
                return 0
            counts = self._settle_epsilon(nxt, cap)
        return min(cap, counts.get(self.accept, 0))

    def _settle_epsilon(self, counts: Dict[int, int], cap: int) -> Dict[int, int]:
        result: Dict[int, int] = {}
        totals = dict(counts)
        queue: List[int] = list(counts.keys())
        while queue:
            state = queue.pop()
            total = min(cap, totals.get(state, 0))
            if result.get(state) == total:
                continue
            result[state] = total
            for dst in self.epsilons[state]:
                previous = totals.get(dst, 0)
                updated = min(cap, previous + total)
                if updated > previous:
                    totals[dst] = updated
                    queue.append(dst)
        return result


class StateLimitExceeded(Exception):
    pass


class NFABuilder:
    def __init__(self) -> None:
        self.nfa = NFA()
        self._in_progress = False

    def build(self, ast: Node) -> NFA:
        start = self.nfa.new_state()
        accept = self.nfa.new_state()
        self.nfa.start = start
        self.nfa.accept = accept
        self._emit(ast, start, accept, depth=0)
        return self.nfa

    # -- recursive emission -------------------------------------------------
    def _emit(self, node: Optional[Node], entry: int, exit_: int, depth: int) -> None:
        if depth > 200:
            self.nfa.add_epsilon(entry, exit_)
            self.nfa.approx.append("nesting too deep")
            return
        if node is None:
            self.nfa.add_epsilon(entry, exit_)
            return
        if isinstance(node, Empty):
            self.nfa.add_epsilon(entry, exit_)
            return
        if isinstance(node, Char):
            self.nfa.add_edge(entry, exit_, node.chars)
            return
        if isinstance(node, Anchor):
            self.nfa.add_epsilon(entry, exit_)
            return
        if isinstance(node, Backref):
            # a backreference consumes at least one character of unknown shape
            self.nfa.add_edge(entry, exit_, CharSet.any())
            self.nfa.approx.append("backreference approximated as any character")
            return
        if isinstance(node, Unsupported):
            mid = self.nfa.new_state()
            self.nfa.add_edge(entry, mid, CharSet.any())
            self.nfa.add_epsilon(entry, exit_)
            self.nfa.add_epsilon(mid, exit_)
            self.nfa.add_epsilon(mid, mid)
            self.nfa.approx.append(f"unsupported construct approximated: {node.reason}")
            return
        if isinstance(node, Seq):
            current = entry
            for index, item in enumerate(node.items):
                nxt = exit_ if index == len(node.items) - 1 else self.nfa.new_state()
                self._emit(item, current, nxt, depth + 1)
                current = nxt
            if not node.items:
                self.nfa.add_epsilon(entry, exit_)
            return
        if isinstance(node, Alt):
            for option in node.options:
                branch_in = self.nfa.new_state()
                branch_out = self.nfa.new_state()
                self.nfa.add_epsilon(entry, branch_in)
                self._emit(option, branch_in, branch_out, depth + 1)
                self.nfa.add_epsilon(branch_out, exit_)
            if not node.options:
                self.nfa.add_epsilon(entry, exit_)
            return
        if isinstance(node, Group):
            if node.zero_width:
                # lookarounds are zero-width for the consuming automaton; the
                # body is still walked so that nested repeats are found by the
                # AST rules.
                self.nfa.add_epsilon(entry, exit_)
                self.nfa.approx.append("lookaround treated as zero-width")
                return
            self._emit(node.node, entry, exit_, depth + 1)
            return
        if isinstance(node, Repeat):
            self._emit_repeat(node, entry, exit_, depth)
            return
        self.nfa.add_epsilon(entry, exit_)

    def _emit_repeat(self, node: Repeat, entry: int, exit_: int, depth: int) -> None:
        minimum = max(0, node.min or 0)
        maximum = node.max
        # Explicit expansion keeps bounded repetition exact for small counts.
        if maximum is not None:
            expansion = maximum
        else:
            expansion = min(minimum, MAX_REPEAT_EXPANSION)
        if expansion > MAX_REPEAT_EXPANSION:
            expansion = MAX_REPEAT_EXPANSION
            self.nfa.approx.append(
                f"bounded repetition {{{node.min},{node.max}}} truncated for analysis"
            )
        current = entry
        for _ in range(minimum if maximum is None else min(minimum, expansion)):
            nxt = self.nfa.new_state()
            self._emit(node.node, current, nxt, depth + 1)
            current = nxt
        if maximum is None:
            # body* : loop back to `current`
            loop_in = self.nfa.new_state()
            self.nfa.add_epsilon(current, loop_in)
            self.nfa.add_epsilon(loop_in, exit_)
            self._emit(node.node, loop_in, current, depth + 1)
        else:
            optional = max(0, minimum - expansion) if minimum > expansion else 0
            remaining = expansion - min(minimum, expansion)
            for _ in range(remaining + optional):
                nxt = self.nfa.new_state()
                self.nfa.add_epsilon(current, nxt)
                self._emit(node.node, current, nxt, depth + 1)
                current = nxt
            self.nfa.add_epsilon(current, exit_)


def build_nfa(ast: Node) -> NFA:
    return NFABuilder().build(ast)


# ---------------------------------------------------------------------------
# ambiguity checks used by the heuristics
# ---------------------------------------------------------------------------

@dataclass
class AmbiguityResult:
    ambiguous: bool = False
    pump: Optional[str] = None
    path_count: int = 0
    checked: int = 0
    note: Optional[str] = None


def _candidate_pumps(node: Node, limit: int = 12) -> List[str]:
    """Short concrete strings that could be the repeated unit."""
    from .regex_ast import shortest_sample

    candidates: List[str] = []

    def add(value: str) -> None:
        if value and value not in candidates and len(value) <= 8 and len(candidates) < limit:
            candidates.append(value)

    add(shortest_sample(node))

    def walk(sub: Node, depth: int = 0) -> None:
        if depth > 4 or len(candidates) >= limit:
            return
        if isinstance(sub, Alt):
            for option in sub.options:
                add(shortest_sample(option))
                walk(option, depth + 1)
            for i, a in enumerate(sub.options):
                for b in sub.options[i + 1:]:
                    add(shortest_sample(a) + shortest_sample(b))
        elif isinstance(sub, Repeat):
            base = shortest_sample(sub.node)
            if base:
                add(base)
                add(base * 2)
                add(base * 3)
            walk(sub.node, depth + 1)
        elif isinstance(sub, Seq):
            for item in sub.items:
                walk(item, depth + 1)
            joined = "".join(shortest_sample(item) for item in sub.items)
            add(joined)
        elif isinstance(sub, Group):
            walk(sub.node, depth + 1)

    walk(node)
    return candidates


def repeat_ambiguity(repeat: Repeat, cap: int = 32) -> AmbiguityResult:
    """Check whether the repeated expression is ambiguous for a pumpable string."""
    if repeat.node is None or repeat.max is not None:
        return AmbiguityResult(note="bounded repetition")
    try:
        nfa = build_nfa(repeat)
    except StateLimitExceeded:
        return AmbiguityResult(note="state limit exceeded")
    best = AmbiguityResult()
    for pump in _candidate_pumps(repeat.node):
        count = nfa.path_count(pump, cap=cap)
        best.checked += 1
        if count >= 2:
            return AmbiguityResult(ambiguous=True, pump=pump, path_count=count,
                                   checked=best.checked)
    return best


def ambiguity_of(node: Node, cap: int = 32) -> AmbiguityResult:
    """Ambiguity of a standalone expression (used for evidence/tests)."""
    try:
        nfa = build_nfa(node)
    except StateLimitExceeded:
        return AmbiguityResult(note="state limit exceeded")
    for pump in _candidate_pumps(node):
        count = nfa.path_count(pump, cap=cap)
        if count >= 2:
            return AmbiguityResult(ambiguous=True, pump=pump, path_count=count)
    return AmbiguityResult()


def sequential_overlap(first: Repeat, second: Repeat) -> Optional[str]:
    """A character both sequential unbounded repeats can consume."""
    from .regex_ast import first_chars

    a = first_chars(first.node)
    b = first_chars(second.node)
    common = a.intersect(b)
    if common:
        return common.first_char()
    return None
