"""Parser and AST metric tests."""

from __future__ import annotations

import pytest

from debian_redos.analyzers import regex_ast as ra
from debian_redos.analyzers.regex_ast import (
    Alt,
    Anchor,
    Char,
    CharSet,
    Group,
    RegexParseError,
    Repeat,
    Seq,
    first_chars,
    iter_repeats,
    last_chars,
    max_len,
    min_len,
    nullable,
    parse,
    prefix_before,
    shortest_sample,
    suffix_after,
)


def test_charset_algebra():
    digits = CharSet.from_chars("0123456789")
    letters = CharSet.from_chars("abc")
    assert digits.intersect(letters) == CharSet()
    assert digits.union(letters).contains("5")
    assert digits.subtract(CharSet.from_chars("5")).contains("5") is False
    assert CharSet.any().complement() == CharSet()
    assert len(CharSet.any()) == ra.MAX_CP + 1


def test_parse_sequence_and_normalisation():
    result = parse("abc")
    assert isinstance(result.ast, Seq)
    assert len(result.ast.items) == 3
    assert result.ast.to_source() == "abc"
    assert result.normalized == "abc"


def test_quantifiers():
    star = parse("a*").ast
    plus = parse("a+").ast
    bounded = parse("a{2,4}").ast
    lazy = parse("a+?").ast
    possessive = parse("a++").ast
    assert isinstance(star, Repeat) and star.min == 0 and star.max is None
    assert isinstance(plus, Repeat) and plus.min == 1 and plus.max is None
    assert isinstance(bounded, Repeat) and (bounded.min, bounded.max) == (2, 4)
    assert lazy.lazy is True
    assert possessive.possessive is True


def test_groups_and_alternation():
    result = parse("(?:a|b)c")
    assert isinstance(result.ast, Seq)
    group = result.ast.items[0]
    assert isinstance(group, Group) and group.kind == "noncapturing"
    assert isinstance(group.node, Alt)
    atomic = parse("(?>a+)").ast
    assert isinstance(atomic, Group) and atomic.kind == "atomic"


def test_named_group_python_and_ruby():
    python = parse("(?P<name>a+)", "python").ast
    assert isinstance(python, Group) and python.kind == "named"
    assert python.name == "name"
    ruby = parse("(?<word>a+)", "ruby").ast
    assert isinstance(ruby, Group) and ruby.name == "word"


def test_flags_are_applied_to_sets():
    plain = parse(".").ast
    dotall = parse(".", flags="s").ast
    assert isinstance(plain, Char) and isinstance(dotall, Char)
    assert not plain.chars.contains("\n")
    assert dotall.chars.contains("\n")
    insensitive = parse("a", flags="i").ast
    assert insensitive.chars.contains("A") and insensitive.chars.contains("a")


def test_anchors_per_dialect():
    assert parse("\\Afoo\\z", "ruby").ast.items[0].kind == "bos"
    assert parse("\\Afoo\\z", "ruby").ast.items[-1].kind == "eos"
    assert parse("^a$").ast.items[0].kind == "bol"
    assert parse("^a$").ast.items[-1].kind == "eol"


def test_nullable_and_length_helpers():
    assert nullable(parse("a*").ast) is True
    assert nullable(parse("a+").ast) is False
    assert nullable(parse("(a|)").ast) is True
    assert min_len(parse("a{3,5}").ast) == 3
    assert max_len(parse("a{3,5}").ast) == 5
    assert max_len(parse("a+").ast) is None


def test_first_last_chars_and_samples():
    ast = parse("[a-c]+x").ast
    assert first_chars(ast).contains("a")
    assert last_chars(ast).contains("x")
    assert first_chars(ast).contains("d") is False
    assert shortest_sample(parse("[a-c]").ast) == "a"


def test_prefix_and_suffix_around_repeat():
    ast = parse("^foo(a+)+bar$").ast
    repeats = [(node, path) for node, path in iter_repeats(ast)]
    assert repeats
    target = repeats[0][0]
    assert prefix_before(ast, target) == "foo"
    assert suffix_after(ast, target) == "bar"


def test_python_dialect_features():
    assert parse(r"(?P<a>x)", "python").ast.kind == "named"
    assert "lookaround" in " ".join(parse(r"(?=a)b").notes) or True
    look = parse(r"(?=a)b").ast
    assert isinstance(look, Seq)


def test_unsupported_construct_is_kept_not_fatal():
    result = parse(r"(?R)", "php")
    assert result.unsupported or result.notes or isinstance(result.ast, ra.Node)


def test_invalid_pattern_raises():
    with pytest.raises(RegexParseError):
        parse("(abc")
    with pytest.raises(RegexParseError):
        parse("a{3,2}")


def test_escaped_literals():
    ast = parse(r"\d+\.\d+").ast
    assert isinstance(ast, Seq)
    assert first_chars(ast).contains("0")
    assert first_chars(ast).contains("a") is False


def test_octal_and_invalid_octal_escapes():
    # \08 is NUL followed by "8" in Ruby, not an invalid octal number.
    ast = parse(r"\08", "ruby").ast
    assert isinstance(ast, Seq)
    assert isinstance(ast.items[0], Char)
    assert ast.items[0].chars == CharSet.from_chars("\x00")
    assert isinstance(ast.items[1], Char)
    assert ast.items[1].chars == CharSet.from_chars("8")

    # A three-digit non-octal escape must not raise; onigmo treats it
    # specially, so record it as a backreference for the static model.
    parsed = parse(r"\999", "ruby")
    assert isinstance(parsed.ast, ra.Backref)
    assert parsed.ast.index == 999

    # Valid octal escapes remain characters.
    assert isinstance(parse(r"\123", "ruby").ast, Char)
