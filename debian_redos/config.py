"""Configuration loading with sane defaults.

The tool is dependency-free by design: if PyYAML is installed it is used,
otherwise a small YAML subset parser (mappings, lists, scalars) handles the
shipped ``config/scanners.yaml``.  ``config_hash`` is used to invalidate the
analysis cache when the effective configuration changes.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - optional dependency
    import yaml as _yaml  # type: ignore
except Exception:  # pragma: no cover
    _yaml = None


DEFAULT_CONFIG: Dict[str, Any] = {
    "languages": {
        "python": {
            "enabled": True,
            "extensions": [".py", ".pyw"],
            "static": ["heuristics"],
            "dynamic": ["python_worker"],
        },
        "ruby": {
            "enabled": True,
            "extensions": [".rb", ".rake", ".gemspec"],
            "static": ["heuristics"],
            "dynamic": ["ruby_worker"],
        },
        "php": {
            "enabled": True,
            "extensions": [".php", ".php5", ".phtml", ".inc"],
            "static": ["heuristics"],
            "dynamic": ["php_worker"],
        },
    },
    "limits": {
        "max_pattern_length": 4096,
        "max_input_length": 8192,
        "timeout_seconds": 2.0,
        "candidate_budget_seconds": 8.0,
        "max_memory_mb": 256,
        "max_file_size_kb": 2048,
        "max_files": 0,
    },
    "static": {
        "min_severity_to_report": "info",
        "max_alternation_depth": 3,
        "enable_external": False,
        "external": {
            "regexploit": {"command": "regexploit", "enabled": False},
            "redoshunter": {"command": "redoshunter", "enabled": False},
            "codeql": {"command": "codeql", "enabled": False, "database": None},
        },
    },
    "dynamic": {
        "enabled": True,
        "engines": {"python": "auto", "ruby": "auto", "php": "auto"},
        "php_docker_image": "php:8.2-cli",
        "use_docker_for_php": True,
        "max_candidates_per_finding": 4,
        "growth": {
            "noise_floor_ms": 0.5,
            "confirm_ratio": 2.5,
            "min_points": 3,
            "exponential_slope_delta": 0.8,
        },
        "sizes": {
            "exponential": [8, 10, 12, 14, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 96, 128],
            "polynomial": [32, 64, 128, 256, 512, 1024, 2048, 4096, 8192],
        },
    },
    "cache": {"enabled": True, "backend": "sqlite"},
    "discovery": {
        "unpack_dsc": False,
        "workdir": None,
        "max_depth": 12,
        "exclude_dirs": [
            ".git", ".svn", ".hg", "node_modules", "__pycache__", ".tox",
            ".venv", "venv", ".mypy_cache", ".pytest_cache", "build", "dist",
            ".eggs", ".pc",
        ],
        "follow_symlinks": False,
    },
    "output": {
        "dir": "reports",
        "json": True,
        "jsonl": True,
        "html": True,
        "sarif": True,
        "summary": True,
    },
    "severity": {
        "exit_code_on": "high",
        "report_min": "info",
    },
    "cve": {"db": None},
    "known": {
        "enabled": True,
        "db": None,
        "min_score": 0.78,
        "match_core": True,
        "match_packages": True,
        "max_matches": 5,
        "auto_assign_cve": False,
        "auto_assign_min_score": 0.95,
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


# ---------------------------------------------------------------------------
# minimal YAML fallback
# ---------------------------------------------------------------------------

def _coerce_scalar(text: str) -> Any:
    text = text.strip()
    if not text:
        return ""
    if text[0:1] in ("'", '"') and text[-1:] == text[0]:
        body = text[1:-1]
        if text[0] == '"':
            try:
                return json.loads(text)
            except Exception:
                return body
        return body.replace("''", "'")
    low = text.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "none", "~"):
        return None
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_coerce_scalar(part) for part in inner.split(",")]
    if text.startswith("{") and text.endswith("}"):
        try:
            return json.loads(text)
        except Exception:
            return {}
    try:
        return int(text, 10)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    return text


def _minimal_yaml(text: str) -> Dict[str, Any]:
    """Parse the YAML subset used by ``config/scanners.yaml``.

    Supported: nested mappings by indentation, ``- `` sequences, inline lists,
    quoted/plain scalars, ``#`` comments.  Anything else raises ValueError so
    the caller can report a clear error instead of silently misreading config.
    """
    root: Dict[str, Any] = {}
    stack: List[tuple] = [(-1, root)]
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        stripped = raw.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        if "\t" in stripped[:indent]:
            raise ValueError("tabs are not allowed for YAML indentation")
        content = stripped.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ValueError(f"bad indentation at line {i}: {raw!r}")
        container = stack[-1][1]
        if content.startswith("- "):
            if not isinstance(container, list):
                raise ValueError(f"unexpected sequence item at line {i}")
            item = content[2:].strip()
            if not item:
                child: Dict[str, Any] = {}
                container.append(child)
                stack.append((indent, child))
            elif ":" in item and not item.startswith(("'", '"', "[", "{")):
                key, _, value = item.partition(":")
                child = {key.strip(): _coerce_scalar(value) if value.strip() else None}
                container.append(child)
                stack.append((indent, child))
            else:
                container.append(_coerce_scalar(item))
            continue
        if ":" not in content:
            raise ValueError(f"expected 'key: value' at line {i}: {raw!r}")
        key, _, value = content.partition(":")
        key = key.strip().strip("'\"")
        if not isinstance(container, dict):
            raise ValueError(f"mapping key inside list at line {i}")
        if value.strip():
            container[key] = _coerce_scalar(value)
        else:
            nxt = None
            for j in range(i, len(lines)):
                probe = lines[j].split("#", 1)[0].rstrip()
                if probe.strip():
                    nxt = len(probe) - len(probe.lstrip(" "))
                    break
            if nxt is not None and nxt > indent:
                child = {}
                container[key] = child
                stack.append((indent, child))
            else:
                container[key] = {}
                stack.append((indent, container[key]))
    return root


def load_yaml(text: str) -> Dict[str, Any]:
    if _yaml is not None:
        data = _yaml.safe_load(text)
        return data or {}
    return _minimal_yaml(text)


def load_config(path: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> "Config":
    data: Dict[str, Any] = {}
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            data = load_yaml(fh.read())
        if not isinstance(data, dict):
            raise ValueError(f"{path}: top level must be a mapping")
        data = _fix_shorthand_lists(data)
    merged = _deep_merge(DEFAULT_CONFIG, data)
    if overrides:
        merged = _deep_merge(merged, overrides)
    return Config(merged)


def _fix_shorthand_lists(data: Dict[str, Any]) -> Dict[str, Any]:
    """Allow ``static: regexploit`` as shorthand for a one element list."""

    langs = data.get("languages") or {}
    for spec in langs.values():
        if isinstance(spec, dict):
            for key in ("static", "dynamic", "extensions"):
                value = spec.get(key)
                if isinstance(value, str):
                    spec[key] = [value]
    return data


class Config:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw

    # -- generic access -----------------------------------------------------
    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.raw
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    def to_dict(self) -> Dict[str, Any]:
        return copy.deepcopy(self.raw)

    @property
    def config_hash(self) -> str:
        # Only the parts that influence results take part in the hash.
        relevant = {
            "languages": self.raw.get("languages"),
            "limits": self.raw.get("limits"),
            "static": {k: v for k, v in (self.raw.get("static") or {}).items()
                       if k != "enable_external"},
            "dynamic": self.raw.get("dynamic"),
        }
        digest = hashlib.sha256(json.dumps(relevant, sort_keys=True, default=str).encode())
        return "sha256:" + digest.hexdigest()[:16]

    # -- typed helpers ------------------------------------------------------
    def language_enabled(self, language: str) -> bool:
        return bool(self.get(f"languages.{language}.enabled", True))

    def extensions(self, language: str) -> List[str]:
        return list(self.get(f"languages.{language}.extensions", []))

    def static_detectors(self, language: str) -> List[str]:
        return list(self.get(f"languages.{language}.static", ["heuristics"]))

    def dynamic_workers(self, language: str) -> List[str]:
        return list(self.get(f"languages.{language}.dynamic", []))

    def limit(self, name: str) -> Any:
        return self.get(f"limits.{name}")

    @property
    def cache_path(self) -> Optional[str]:
        if not self.get("cache.enabled", True):
            return None
        return self.get("cache.path")

    @property
    def output_dir(self) -> str:
        return self.get("output.dir", "reports")

    def ensure_dirs(self) -> None:
        out = self.output_dir
        if out:
            os.makedirs(out, exist_ok=True)
