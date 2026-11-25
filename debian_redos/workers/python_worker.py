"""Python `re` / `regex` measurement worker.

Protocol: one JSON object per line on stdin, one JSON object per line on
stdout.  The parent process enforces the wall-clock timeout by killing the
whole process group; this worker never decides that a test "timed out" on its
own.  Compilation is cached per process and warmed up before the first
measurement so that compile time does not pollute the timing curve.
"""

from __future__ import annotations

import json
import platform
import re
import sys
import time

try:  # optional: the third-party `regex` module has different behaviour
    import regex as _regex_module  # type: ignore
except Exception:  # pragma: no cover
    _regex_module = None

_FLAG_MAP = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "x": re.VERBOSE,
    "a": re.ASCII,
    "u": re.UNICODE,
    "l": re.LOCALE,
}

_MODULE_FLAG_MAP = {}
if _regex_module is not None:  # pragma: no cover
    _MODULE_FLAG_MAP = {
        "i": _regex_module.IGNORECASE,
        "m": _regex_module.MULTILINE,
        "s": _regex_module.DOTALL,
        "x": _regex_module.VERBOSE,
        "a": _regex_module.ASCII,
        "u": _regex_module.UNICODE,
    }


def _compile(pattern: str, flags: str, use_regex_module: bool):
    bits = 0
    mapping = _MODULE_FLAG_MAP if use_regex_module else _FLAG_MAP
    for ch in flags or "":
        bits |= mapping.get(ch, 0)
    module = _regex_module if use_regex_module else re
    return module.compile(pattern, bits)


def main() -> int:
    cache = {}
    engine = "python-regex" if _MODULE_FLAG_MAP else "python-re"
    version = platform.python_version()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError as exc:
            print(json.dumps({"status": "error", "error": f"bad request: {exc}"}), flush=True)
            continue
        pattern = request.get("pattern") or ""
        flags = request.get("flags") or ""
        use_regex_module = bool(request.get("use_regex_module", False)) and _regex_module is not None
        key = (pattern, flags, use_regex_module)
        response = {"engine": engine, "engine_version": version}
        try:
            compiled = cache.get(key)
            if compiled is None:
                compiled = _compile(pattern, flags, use_regex_module)
                if len(cache) < 128:
                    cache[key] = compiled
            if request.get("warmup"):
                response.update({"status": "ok"})
                print(json.dumps(response), flush=True)
                continue
            text = request.get("text") or ""
            started = time.perf_counter()
            compiled.search(text)
            elapsed = (time.perf_counter() - started) * 1000.0
            response.update({"status": "completed", "elapsed_ms": elapsed})
        except RecursionError as exc:
            response.update({"status": "error", "error": f"RecursionError: {exc}"})
        except MemoryError:
            response.update({"status": "error", "error": "MemoryError"})
        except Exception as exc:  # syntax errors, bad flags, ...
            response.update({"status": "error", "error": f"{type(exc).__name__}: {exc}"})
        print(json.dumps(response), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
