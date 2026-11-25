"""Extractor registry: path -> language -> candidates."""

from __future__ import annotations

import os
from typing import Callable, Dict, List, Optional

from ..models import RegexCandidate
from . import php_extractor, python_extractor, ruby_extractor
from .base import detect_language, read_source

EXTRACTORS: Dict[str, Callable[[str, str, str, str], List[RegexCandidate]]] = {
    "python": python_extractor.extract,
    "ruby": ruby_extractor.extract,
    "php": php_extractor.extract,
}


def extract_file(
    package: str,
    version: str,
    rel_path: str,
    abspath: str,
    language: Optional[str] = None,
    max_bytes: int = 4 * 1024 * 1024,
) -> List[RegexCandidate]:
    language = language or detect_language(abspath)
    if language is None:
        return []
    extractor = EXTRACTORS.get(language)
    if extractor is None:
        return []
    source = read_source(abspath, max_bytes=max_bytes)
    if source is None:
        return []
    try:
        return extractor(package, version, rel_path, source)
    except RecursionError:
        return []
    except Exception:  # a broken file must not abort the whole scan
        return []


def available_languages() -> List[str]:
    return sorted(EXTRACTORS)


def engine_status() -> Dict[str, Dict[str, object]]:
    """Report which language runtimes are present (used by `doctor`)."""
    import shutil

    status: Dict[str, Dict[str, object]] = {
        "python": {"extractor": "python-ast", "runtime": "built-in"},
        "ruby": {"extractor": "ruby-ripper",
                 "runtime": shutil.which("ruby") or "missing (fallback scanner)"},
        "php": {"extractor": "php-tokenizer",
                "runtime": shutil.which("php") or "missing (fallback scanner)"},
    }
    return status
