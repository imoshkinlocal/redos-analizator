"""PHP regexp extraction via ``token_get_all`` (nikic/PHP-Parser-free).

The helper script resolves literals, concatenations, single-assignment
variables and class constants; array patterns produce one candidate per
element.  Anything that depends on runtime data is reported as an unresolved
dynamic pattern.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import List, Optional

from ..models import SourceType
from .base import classify_input_control, make_candidate

EXTRACTOR_NAME = "php-tokenizer"
FALLBACK_NAME = "php-fallback"

_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "workers", "php_extract.php")

_KNOWN_MODIFIERS = set("imsxuADUJSXn")
_FALLBACK_CALL = re.compile(
    r"(?<![\w>$:])(preg_match_all|preg_match|preg_replace_callback|preg_replace|"
    r"preg_filter|preg_split|preg_grep)\s*\(\s*(['\"])((?:\\.|(?!\2).)*)\2",
    re.DOTALL,
)


def extract(package: str, version: str, rel_path: str, source: str) -> List:
    php = shutil.which("php")
    if php:
        candidates = _extract_with_php(package, version, rel_path, source, php)
        if candidates is not None:
            return candidates
    return _extract_fallback(package, version, rel_path, source)


def _extract_with_php(package: str, version: str, rel_path: str, source: str,
                      php: str) -> Optional[List]:
    try:
        proc = subprocess.run(
            [php, _SCRIPT, rel_path],
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

    candidates = []
    for item in payload.get("regexes", []):
        flags = _normalise_flags(item.get("flags") or "")
        notes = list(item.get("notes") or [])
        input_expr = item.get("input_expr") or ""
        input_control, evidence = classify_input_control(input_expr, "php")
        pattern = item.get("pattern")
        source_type = item.get("source_type") or SourceType.LITERAL.value
        if pattern is None:
            notes.append("pattern value could not be resolved statically")
        notes = list(dict.fromkeys(notes))
        candidates.append(make_candidate(
            package=package,
            version=version,
            language="php",
            rel_path=rel_path,
            line=int(item.get("line") or 1),
            function=item.get("function") or "preg_",
            pattern=pattern,
            flags=flags,
            source_type=source_type,
            input_control=input_control,
            input_evidence=evidence,
            raw_pattern=item.get("raw_pattern"),
            extractor=EXTRACTOR_NAME,
            confidence=1.0 if pattern is not None else 0.4,
            notes=notes,
            engine_hint="pcre2",
        ))
    return candidates


def _normalise_flags(flags: str) -> str:
    """Keep only modifiers that change matching semantics for our model."""
    out = []
    for ch in flags:
        if ch in "imsx" and ch not in out:
            out.append(ch)
    return "".join(sorted(out))


def _extract_fallback(package: str, version: str, rel_path: str, source: str) -> List:
    candidates = []
    for match in _FALLBACK_CALL.finditer(source):
        line = source.count("\n", 0, match.start()) + 1
        raw = match.group(2) + match.group(3) + match.group(2)
        body, flags = _split_delimiters(match.group(3))
        input_control, evidence = classify_input_control(
            _line_context(source, line), "php")
        candidates.append(make_candidate(
            package=package, version=version, language="php", rel_path=rel_path,
            line=line, function=match.group(1), pattern=body, flags=flags,
            source_type=SourceType.LITERAL.value, raw_pattern=raw,
            input_control=input_control, input_evidence=evidence,
            extractor=FALLBACK_NAME, confidence=0.5,
            notes=["php interpreter unavailable: heuristic scan, verify manually"],
            engine_hint="pcre2",
        ))
    return candidates


def _split_delimiters(raw: str):
    if not raw:
        return None, ""
    delimiter = raw[0]
    if delimiter.isalnum() or delimiter in "\\ \t\n":
        return raw, ""
    pairs = {"(": ")", "[": "]", "{": "}", "<": ">"}
    closing = pairs.get(delimiter, delimiter)
    i = 1
    body = []
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            body.append(ch + raw[i + 1])
            i += 2
            continue
        if ch == closing:
            break
        body.append(ch)
        i += 1
    flags = "".join(ch for ch in raw[i + 1:] if ch in _KNOWN_MODIFIERS)
    return "".join(body), _normalise_flags(flags)


def _line_context(source: str, line: int, span: int = 3) -> str:
    lines = source.splitlines()
    start = max(0, line - 1)
    return " ".join(part.strip() for part in lines[start:start + span])
