"""Thompson NFA and ambiguity measurement tests."""

from __future__ import annotations

from debian_redos.analyzers.nfa import (
    ambiguity_of,
    build_nfa,
    repeat_ambiguity,
    sequential_overlap,
)
from debian_redos.analyzers.regex_ast import iter_repeats, parse


def test_nfa_accepts_and_rejects():
    nfa = build_nfa(parse("ab*c").ast)
    assert nfa.accepts("ac")
    assert nfa.accepts("abbc")
    assert not nfa.accepts("ab")
    assert not nfa.accepts("x")


def test_path_count_counts_ambiguous_parses():
    nfa = build_nfa(parse("(a|aa)+").ast)
    assert nfa.path_count("aa", cap=64) >= 2
    assert nfa.path_count("aaa", cap=64) >= 3
    plain = build_nfa(parse("(ab|a)+").ast)
    assert plain.path_count("aa", cap=64) <= 1


def test_repeat_ambiguity_distinguishes_alt_shapes():
    ambiguous = next(node for node, _ in iter_repeats(parse("(a|aa)+").ast))
    result = repeat_ambiguity(ambiguous)
    assert result.ambiguous is True
    assert result.pump in ("aa", "a")

    safe = next(node for node, _ in iter_repeats(parse("(ab|a)+").ast))
    result = repeat_ambiguity(safe)
    assert result.ambiguous is False


def test_ambiguity_of_standalone_expression():
    # ambiguity requires two accepting paths for the *same* string
    assert ambiguity_of(parse("(a|a)").ast).ambiguous is True
    assert ambiguity_of(parse("(a|aa)+").ast).ambiguous is True
    assert ambiguity_of(parse("ab").ast).ambiguous is False


def test_repeat_ambiguity_bounded_is_not_exponential():
    repeat = next(node for node, _ in iter_repeats(parse("(a|aa){2,4}").ast))
    result = repeat_ambiguity(repeat)
    assert result.ambiguous is False
    assert result.note == "bounded repetition"


def test_sequential_overlap():
    repeats = [node for node, _ in iter_repeats(parse("a*a*").ast)]
    assert len(repeats) == 2
    assert sequential_overlap(repeats[0], repeats[1]) is not None
    repeats = [node for node, _ in iter_repeats(parse("a*b*").ast)]
    assert sequential_overlap(repeats[0], repeats[1]) is None
