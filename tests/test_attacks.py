"""Attack-string generation tests."""

from __future__ import annotations

from debian_redos.analyzers import attacks
from debian_redos.analyzers.regex_ast import all_chars, iter_repeats, parse


def test_plan_builds_prefix_pump_suffix_breaker():
    plan = attacks.AttackPlan(prefix="pre", pump="a", suffix="suf", breaker="!")
    assert plan.build(3) == "pre" + "aaa" + "suf!"
    assert plan.build(2, include_suffix=False) == "preaa!"
    assert plan.to_dict()["kind"] == "exponential"


def test_choose_breaker_avoids_pattern_and_pump():
    chars = all_chars(parse("^[a-z]+$").ast)
    breaker = attacks.choose_breaker(chars, "a")
    assert breaker not in "a"
    assert not chars.contains(breaker)


def test_plan_attacks_for_nested_repeat():
    ast = parse("^/foo/(a+)+$").ast
    repeat = next(node for node, _ in iter_repeats(ast))
    plans = attacks.plan_attacks(ast, repeat, "a", "exponential",
                                 "nested_quantifier", pattern_chars=all_chars(ast),
                                 limit=2)
    assert plans
    assert plans[0].prefix == "/foo/"
    assert plans[0].pump == "a"
    assert plans[0].breaker
    assert plans[0].build(4).startswith("/foo/aaaa")


def test_plan_for_empty_pump_uses_body_character():
    ast = parse("^(a*)+$").ast
    repeat = next(node for node, _ in iter_repeats(ast))
    plans = attacks.plan_attacks(ast, repeat, "", "exponential", "nullable_body",
                                 pattern_chars=all_chars(ast))
    assert plans and plans[0].pump


def test_sequential_plan_is_polynomial():
    plans = attacks.plan_for_sequential(None, None, "a")
    assert plans[0].kind == "polynomial"
    assert plans[0].pump == "a"
