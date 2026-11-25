"""Ruby regexp extraction.

Primary path: a Ripper-based helper (``workers/ruby_extract.rb``) which sees the
real parse tree, so regexp literals, ``%r{}``, ``Regexp.new`` and the call that
receives them are all identified precisely.  When no Ruby interpreter is
available a conservative line scanner is used and marked as low confidence.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import List, Optional, Tuple

from ..models import RegexCandidate, SourceType
from .base import classify_input_control, make_candidate

EXTRACTOR_NAME = "ruby-ripper"
FALLBACK_NAME = "ruby-fallback"

_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "workers", "ruby_extract.rb")

_FLAG_MAP = {"i": "i", "x": "x", "m": "s"}   # Ruby /m == dot-all
_ENCODING_FLAGS = set("ounes")


def extract(package: str, version: str, rel_path: str, source: str) -> List[RegexCandidate]:
    ruby = shutil.which("ruby")
    if ruby:
        candidates = _extract_with_ripper(package, version, rel_path, source, ruby)
        if candidates is not None:
            _refine_input_control(candidates, source)
            return candidates
    return _extract_fallback(package, version, rel_path, source)


_ASSIGNMENT = re.compile(r"^\s*(?:self\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*")
_USE_OPERATORS = ("=~", "!~", ".match", ".match?", ".scan", ".gsub", ".sub",
                  ".split", "match(", "scan(")


def _refine_input_control(candidates: List[RegexCandidate], source: str) -> None:
    """Classify a regexp assigned to a name from the lines where it is used.

    ``VULN = /.../`` followed by ``params[:q] =~ VULN`` used to be classified
    from the assignment line, which says nothing about the data.  A small
    intra-file search finds the use-site instead; it is still deliberately
    conservative (only same-file uses, no cross-file dataflow).
    """
    lines = source.splitlines()
    for candidate in candidates:
        if candidate.input_control not in ("unknown", "internal"):
            continue
        if candidate.line < 1 or candidate.line > len(lines):
            continue
        match = _ASSIGNMENT.match(lines[candidate.line - 1])
        if not match:
            continue
        name = match.group(1)
        pattern = re.compile(r"\b" + re.escape(name) + r"\b")
        contexts: List[str] = []
        use_lines: List[int] = []
        for index in range(candidate.line, len(lines)):
            text = lines[index]
            if not pattern.search(text):
                continue
            if not any(operator in text for operator in _USE_OPERATORS):
                continue
            contexts.append(text.strip())
            use_lines.append(index + 1)
            if len(contexts) >= 3:
                break
        if not contexts:
            continue
        control, evidence = classify_input_control(" ".join(contexts), "ruby")
        if control == "unknown":
            continue
        candidate.input_control = control
        candidate.input_evidence = (
            f"use-site line {use_lines[0]} for {name}: {evidence}"
        )
        candidate.notes.append(
            f"input classified from use-site line {use_lines[0]} of {name}"
        )
        if candidate.pattern is not None:
            candidate.confidence = min(1.0, candidate.confidence + 0.05)


def _extract_with_ripper(package: str, version: str, rel_path: str, source: str,
                         ruby: str) -> Optional[List[RegexCandidate]]:
    try:
        proc = subprocess.run(
            [ruby, _SCRIPT, rel_path],
            input=source,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    try:
        payload = json.loads(proc.stdout)
    except ValueError:
        return None
    if not payload.get("ok"):
        return None

    candidates: List[RegexCandidate] = []
    for item in payload.get("regexes", []):
        flags = _normalise_flags(item.get("flags") or "")
        notes = list(item.get("notes") or [])
        line = int(item.get("line") or 1)
        pattern = item.get("pattern")
        source_type = item.get("source_type") or SourceType.LITERAL.value
        function = _normalise_function(item.get("function") or "Regexp literal")
        context = _line_context(source, line)
        input_control, evidence = classify_input_control(context, "ruby")
        if input_control == "internal" and not context.strip().startswith(("'", '"')):
            input_control, evidence = classify_input_control(context, "ruby")
        if pattern is None:
            notes.append("pattern value could not be resolved statically")
        candidates.append(make_candidate(
            package=package,
            version=version,
            language="ruby",
            rel_path=rel_path,
            line=line,
            column=item.get("column"),
            function=function,
            pattern=pattern,
            flags=flags,
            source_type=source_type,
            input_control=input_control,
            input_evidence=evidence,
            extractor=EXTRACTOR_NAME,
            confidence=1.0 if pattern is not None else 0.4,
            notes=notes,
        ))
    return candidates


def _normalise_flags(flags: str) -> str:
    out = []
    for ch in flags:
        mapped = _FLAG_MAP.get(ch)
        if mapped and mapped not in out:
            out.append(mapped)
    return "".join(sorted(out))


def _normalise_function(name: str) -> str:
    mapping = {
        "match": "String#match",
        "match?": "String#match?",
        "scan": "String#scan",
        "gsub": "String#gsub",
        "gsub!": "String#gsub!",
        "sub": "String#sub",
        "sub!": "String#sub!",
        "=~": "String#=~",
        "split": "String#split",
        "Regexp literal": "Regexp literal",
        "Regexp.new": "Regexp.new",
        "compile": "Regexp.compile",
    }
    return mapping.get(name, name)


def _line_context(source: str, line: int, span: int = 3) -> str:
    lines = source.splitlines()
    if not lines:
        return ""
    start = max(0, line - 1)
    return " ".join(part.strip() for part in lines[start:start + span])


# ---------------------------------------------------------------------------
# fallback scanner (no Ruby interpreter)
# ---------------------------------------------------------------------------

_CALL_REGEX = re.compile(
    r"(?:\.|\b)(match\?|match|scan|gsub!|gsub|sub!|sub|split)\s*\(?\s*"
    r"/((?:[^/\\\n]|\\.)+)/([imxounse]*)"
)
_BINARY_REGEX = re.compile(r"(?:=~|!~)\s*/((?:[^/\\\n]|\\.)+)/([imxounse]*)")
_PERCENT_REGEX = re.compile(r"%r(.)(.*?)\1([imxounse]*)", re.DOTALL)
_CONSTRUCTOR_REGEX = re.compile(
    r"Regexp\.(?:new|compile)\s*\(\s*(['\"])((?:\\.|(?!\1).)*)\1([^)]*)"
)
_ASSIGNED_REGEX = re.compile(r"=\s*/((?:[^/\\\n]|\\.)+)/([imxounse]*)")


def _extract_fallback(package: str, version: str, rel_path: str,
                      source: str) -> List[RegexCandidate]:
    candidates: List[RegexCandidate] = []
    seen = set()

    def add(match: re.Match, function: str, pattern: Optional[str], flags: str,
            note: str) -> None:
        line = source.count("\n", 0, match.start()) + 1
        key = (line, pattern, function)
        if key in seen:
            return
        seen.add(key)
        context = _line_context(source, line)
        input_control, evidence = classify_input_control(context, "ruby")
        candidates.append(make_candidate(
            package=package, version=version, language="ruby", rel_path=rel_path,
            line=line, function=function, pattern=pattern,
            flags=_normalise_flags(flags), source_type=SourceType.LITERAL.value if pattern else SourceType.DYNAMIC.value,
            input_control=input_control, input_evidence=evidence,
            extractor=FALLBACK_NAME, confidence=0.45,
            notes=[note, "ruby interpreter unavailable: heuristic scan, verify manually"],
        ))

    for match in _CALL_REGEX.finditer(source):
        add(match, f"String#{match.group(1)}", match.group(2), match.group(3), "literal scan")
    for match in _BINARY_REGEX.finditer(source):
        add(match, "String#=~", match.group(1), match.group(2), "literal scan")
    for match in _PERCENT_REGEX.finditer(source):
        add(match, "Regexp literal", match.group(2), match.group(3), "%r literal scan")
    for match in _CONSTRUCTOR_REGEX.finditer(source):
        add(match, "Regexp.new", match.group(2), "", "constructor scan")
    for match in _ASSIGNED_REGEX.finditer(source):
        add(match, "Regexp literal", match.group(1), match.group(2), "assignment scan")
    _refine_input_control(candidates, source)
    return candidates
