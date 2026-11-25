"""Shared extractor helpers: language detection, input-control classification."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..models import InputControl, RegexCandidate, SourceType

# ---------------------------------------------------------------------------
# file handling
# ---------------------------------------------------------------------------

LANGUAGE_BY_EXTENSION: Dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".rb": "ruby", ".rake": "ruby", ".gemspec": "ruby",
    ".php": "php", ".php5": "php", ".phtml": "php", ".inc": "php",
}

SPECIAL_RUBY_FILES = {"Rakefile", "Gemfile", "Guardfile", "Capfile"}

MAX_SOURCE_BYTES = 4 * 1024 * 1024


def detect_language(path: str) -> Optional[str]:
    name = os.path.basename(path)
    if name in SPECIAL_RUBY_FILES:
        return "ruby"
    extension = os.path.splitext(name)[1].lower()
    return LANGUAGE_BY_EXTENSION.get(extension)


def read_source(path: str, max_bytes: int = MAX_SOURCE_BYTES) -> Optional[str]:
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size > max_bytes:
        return None
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
            if b"\x00" in head:
                return None
            fh.seek(0)
            data = fh.read()
    except OSError:
        return None
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# input-control classification (light, intra-file)
# ---------------------------------------------------------------------------

_NETWORK_MARKERS = (
    "request.args", "request.form", "request.json", "request.data", "request.values",
    "request.files", "request.body", "request.GET", "request.POST", "request.query_params",
    "request.headers", "request.cookies", "request.stream", "request.get_data",
    "self.request", "flask.request", "quart.request", "tornado.web", "aiohttp",
    "wsgi.input", ".recv(", ".recvfrom(", "urlopen(", "http.client",
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER['QUERY_STRING']",
    "$_SERVER[\"QUERY_STRING\"]", "$_SERVER['REQUEST_URI']", "php://input",
    "params[", "req.body", "req.query", "req.params", "ctx.request", "c.Request",
    "request.getParameter", "getParameter(", "ServletRequest",
)

_LOCAL_MARKERS = (
    "sys.argv", "input(", "raw_input(", "sys.stdin", "readline()", "STDIN",
    "ARGV", "gets.chomp", "gets(", "$argv", "getopt", "readline(",
    "console.readLine", "cin >>", "scanf(",
)

_FILE_MARKERS = (
    "open(", "io.open(", "Path(", ".read_text(", ".read_bytes(", "File.read",
    "File.open", "IO.read", "file_get_contents(", "fopen(", "fread(", "SplFileObject",
    "Files.read", "Files.newInputStream", "FileInputStream", "fs.readFile",
)

_ENV_MARKERS = (
    "os.environ", "os.getenv", "getenv(", "$_ENV", "ENV[", "ENV.fetch",
    "process.env", "System.getenv", "getenv(",
)

_DATABASE_MARKERS = (
    "cursor.", ".fetchone(", ".fetchall(", ".fetchmany(", "execute(", "query(",
    "->fetch(", "->fetchAll(", "PDO", "mysqli_query", "pg_query", "db.query",
)


def classify_input_control(expression: str, language: str = "python") -> Tuple[str, Optional[str]]:
    """Best-effort classification of where the matched data comes from."""
    text = (expression or "").strip()
    if not text:
        return InputControl.UNKNOWN.value, None

    for markers, control in (
        (_NETWORK_MARKERS, InputControl.USER_NETWORK),
        (_LOCAL_MARKERS, InputControl.USER_LOCAL),
        (_FILE_MARKERS, InputControl.FILE),
        (_ENV_MARKERS, InputControl.ENV),
        (_DATABASE_MARKERS, InputControl.DATABASE),
    ):
        for marker in markers:
            if marker in text:
                return control.value, f"data expression contains {marker!r}: {text[:200]}"
    if text.startswith(("'", '"')) or re.fullmatch(r"\d+", text):
        return InputControl.INTERNAL.value, "data expression is a literal"
    return InputControl.UNKNOWN.value, f"unrecognised data source: {text[:200]}"


def classify_line_markers(line_text: str) -> Tuple[str, Optional[str]]:
    """Weaker classification used when only the source line is available."""
    return classify_input_control(line_text, "text")


# ---------------------------------------------------------------------------
# candidate factory
# ---------------------------------------------------------------------------

def make_candidate(
    package: str,
    version: str,
    language: str,
    rel_path: str,
    line: int,
    function: str,
    pattern: Optional[str],
    *,
    flags: str = "",
    column: Optional[int] = None,
    source_type: str = SourceType.LITERAL.value,
    input_control: str = InputControl.UNKNOWN.value,
    input_evidence: Optional[str] = None,
    raw_pattern: Optional[str] = None,
    extractor: str = "",
    confidence: float = 1.0,
    notes: Optional[List[str]] = None,
    engine_hint: Optional[str] = None,
) -> RegexCandidate:
    return RegexCandidate(
        package=package,
        version=version,
        language=language,
        file=rel_path,
        line=max(1, int(line)),
        function=function,
        pattern=pattern,
        dialect=language,
        flags=flags or "",
        column=column,
        source_type=source_type,
        input_control=input_control,
        input_evidence=input_evidence,
        raw_pattern=raw_pattern,
        extractor=extractor,
        confidence=confidence,
        notes=list(notes or []),
        engine_hint=engine_hint,
    )
