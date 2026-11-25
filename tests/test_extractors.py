"""Extractor tests for Python, Ruby and PHP."""

from __future__ import annotations

import shutil

import pytest

from debian_redos.extractors import base, php_extractor, python_extractor, ruby_extractor

PY_SOURCE = r'''
import re
import re as _re
import sys
from re import compile as rx_compile
from flask import request

PAT = r"^(a+)+$"
COMPILED = re.compile(r"^(b+)+$", re.I)


def handler(value):
    local = "(c|cc)+$"
    re.match(PAT, request.args.get("q", ""))
    re.search(local, request.args.get("q", ""))
    COMPILED.match(sys.argv[1])
    _re.match(r"^(d+)+$", input())
    rx_compile("(e+)+$")
    return re.match(pattern_from_config, value)
'''

RUBY_SOURCE = r'''
require 'sinatra'
VULN = /\A(a|aa)+\z/

def handle(params)
  params[:q] =~ VULN
end

get '/other' do
  gets.chomp.match(/(b+)+/)
end
'''

PHP_SOURCE = r'''<?php
$vuln = '/^(a+)+$/';
if (preg_match($vuln, $_GET['q'])) {
    echo "match";
}
preg_match('~(b|bb)+$~i', $argv[1]);
preg_match($dynamic_pattern, $value);
'''


def test_detect_language():
    assert base.detect_language("x.py") == "python"
    assert base.detect_language("Rakefile") == "ruby"
    assert base.detect_language("x.php5") == "php"
    assert base.detect_language("x.txt") is None


def test_classify_input_control():
    cases = {
        "request.args.get('q')": "user_network",
        "$_POST['x']": "user_network",
        "sys.argv[1]": "user_local",
        "gets.chomp": "user_local",
        "open('x').read()": "file",
        "os.environ['X']": "env",
        "cursor.fetchone()[0]": "database",
        "'literal'": "internal",
        "something_else": "unknown",
    }
    for expression, expected in cases.items():
        control, evidence = base.classify_input_control(expression)
        assert control == expected, expression
        assert evidence


def test_python_extractor_literals_aliases_and_dataflow():
    candidates = python_extractor.extract("pkg", "1.0", "app.py", PY_SOURCE)
    patterns = {c.pattern for c in candidates}
    assert "^(a+)+$" in patterns
    assert "^(b+)+$" in patterns
    assert "(c|cc)+$" in patterns
    assert "^(d+)+$" in patterns
    assert "(e+)+$" in patterns
    assert None in patterns  # pattern_from_config is unresolved
    assert any(c.pattern == "^(a+)+$" and c.input_control == "user_network"
               for c in candidates)
    assert any(c.pattern == "^(d+)+$" and c.input_control == "user_local"
               for c in candidates)
    compiled = [c for c in candidates if c.pattern == "^(b+)+$"]
    assert compiled and any(c.flags == "i" for c in compiled)
    unresolved = [c for c in candidates if c.pattern is None]
    assert unresolved and "could not be resolved" in " ".join(unresolved[0].notes)


@pytest.mark.skipif(not shutil.which("ruby"), reason="ruby is not installed")
def test_ruby_extractor_uses_ripper_and_classifies_use_site():
    candidates = ruby_extractor.extract("pkg", "1.0", "lib.rb", RUBY_SOURCE)
    patterns = {c.pattern for c in candidates}
    assert r"\A(a|aa)+\z" in patterns
    vuln = next(c for c in candidates if c.pattern == r"\A(a|aa)+\z")
    assert vuln.input_control == "user_network"
    assert "use-site line" in (vuln.input_evidence or "")
    other = next(c for c in candidates if c.pattern == r"(b+)+")
    assert other.input_control == "user_local"


def test_ruby_fallback_without_interpreter(monkeypatch):
    monkeypatch.setattr(ruby_extractor.shutil, "which", lambda name: None)
    candidates = ruby_extractor.extract("pkg", "1.0", "lib.rb", RUBY_SOURCE)
    assert candidates
    patterns = {c.pattern for c in candidates}
    assert r"\A(a|aa)+\z" in patterns
    assert all("heuristic scan" in " ".join(c.notes) for c in candidates)


@pytest.mark.skipif(not shutil.which("php"), reason="php is not installed")
def test_php_extractor_resolves_variables_and_input():
    candidates = php_extractor.extract("pkg", "1.0", "web.php", PHP_SOURCE)
    patterns = {c.pattern for c in candidates}
    assert "^(a+)+$" in patterns
    assert "(b|bb)+$" in patterns
    assert None in patterns
    vuln = next(c for c in candidates if c.pattern == "^(a+)+$")
    assert vuln.input_control == "user_network"
    local = next(c for c in candidates if c.pattern == "(b|bb)+$")
    assert local.input_control == "user_local"
    assert local.flags == "i"
    assert local.raw_pattern  # PHP patterns keep their delimiters for the worker


def test_php_fallback_without_interpreter(monkeypatch):
    monkeypatch.setattr(php_extractor.shutil, "which", lambda name: None)
    candidates = php_extractor.extract("pkg", "1.0", "web.php", PHP_SOURCE)
    patterns = {c.pattern for c in candidates}
    # the fallback does not resolve variables; it only sees literal arguments
    assert "(b|bb)+$" in patterns
    assert "^(a+)+$" not in patterns
    local = next(c for c in candidates if c.pattern == "(b|bb)+$")
    assert local.input_control == "user_local"
    assert all("heuristic scan" in " ".join(c.notes) for c in candidates)


@pytest.mark.parametrize("raw,body,flags", [
    ("/abc/i", "abc", "i"),
    ("~a\\/b~", "a\\/b", ""),
    ("#^x+$#s", "^x+$", "s"),
    ("{abc}x", "abc", "x"),
])
def test_php_split_delimiters(raw, body, flags):
    assert php_extractor._split_delimiters(raw) == (body, flags)


def test_read_source_rejects_binary(tmp_path):
    path = tmp_path / "x.py"
    path.write_bytes(b"abc\x00def")
    assert base.read_source(str(path)) is None
    assert base.read_source(str(tmp_path / "missing.py")) is None
