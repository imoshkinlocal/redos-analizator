"""Debian source package discovery.

Accepted inputs:

* a ``.dsc`` file (optionally unpacked with ``dpkg-source -x``);
* an unpacked source tree (a directory containing ``debian/control``);
* a directory containing many unpacked trees (searched to a bounded depth);
* a plain directory or single file (used for tests/demos -- synthetic package).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import PackageInfo, SourceFile
from ..extractors.base import detect_language

_SOURCE_LINE = re.compile(r"^Source:\s*(\S+)", re.MULTILINE)
_PACKAGE_LINE = re.compile(r"^Package:\s*(\S+)", re.MULTILINE)
_MAINTAINER_LINE = re.compile(r"^Maintainer:\s*(.+)$", re.MULTILINE)
_VERSION_LINE = re.compile(r"^Version:\s*(\S+)", re.MULTILINE)
_CHANGELOG = re.compile(r"^(\S+)\s+\(([^)]+)\)")

DEFAULT_EXCLUDES = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", ".mypy_cache", ".pytest_cache", "build", "dist", ".eggs", ".pc",
}


@dataclass
class DiscoveryOptions:
    max_depth: int = 12
    exclude_dirs: Sequence[str] = field(default_factory=lambda: sorted(DEFAULT_EXCLUDES))
    follow_symlinks: bool = False
    unpack_dsc: bool = False
    workdir: Optional[str] = None
    max_file_size_kb: int = 2048
    max_files: int = 0
    extensions: Optional[Dict[str, List[str]]] = None

    @classmethod
    def from_config(cls, config) -> "DiscoveryOptions":
        languages = config.get("languages", {}) or {}
        extensions = {name: list(spec.get("extensions") or [])
                      for name, spec in languages.items()}
        return cls(
            max_depth=int(config.get("discovery.max_depth", 12) or 12),
            exclude_dirs=list(config.get("discovery.exclude_dirs", sorted(DEFAULT_EXCLUDES))),
            follow_symlinks=bool(config.get("discovery.follow_symlinks", False)),
            unpack_dsc=bool(config.get("discovery.unpack_dsc", False)),
            workdir=config.get("discovery.workdir"),
            max_file_size_kb=int(config.limit("max_file_size_kb") or 2048),
            max_files=int(config.limit("max_files") or 0),
            extensions=extensions,
        )


class Discoverer:
    def __init__(self, options: Optional[DiscoveryOptions] = None):
        self.options = options or DiscoveryOptions()
        self.notes: List[str] = []

    # -- entry point --------------------------------------------------------
    def discover(self, roots: Sequence[str]) -> List[PackageInfo]:
        if isinstance(roots, str):
            roots = [roots]
        packages: List[PackageInfo] = []
        seen = set()
        for root in roots:
            for package in self._discover_root(os.path.abspath(root)):
                if package.key in seen:
                    continue
                seen.add(package.key)
                packages.append(package)
        packages.sort(key=lambda p: (p.name, p.version))
        return packages

    def _discover_root(self, root: str) -> List[PackageInfo]:
        if not os.path.exists(root):
            self.notes.append(f"path does not exist: {root}")
            return []
        if os.path.isfile(root) and root.endswith(".dsc"):
            return self._from_dsc(root)
        if os.path.isfile(root):
            parent = os.path.dirname(root)
            return [self._synthetic(parent)]
        if self._is_source_tree(root):
            return [self._from_tree(root)]
        found: List[PackageInfo] = []
        for directory in self._walk_source_trees(root):
            found.append(self._from_tree(directory))
        if not found:
            # plain directory: synthetic package, useful for fixtures/demos
            names = {entry for entry in os.listdir(root) if not entry.startswith(".")}
            if len(names) == 1:
                child = os.path.join(root, next(iter(names)))
                if os.path.isdir(child):
                    return [self._synthetic(child)]
            return [self._synthetic(root)]
        return found

    # -- package metadata ---------------------------------------------------
    def _is_source_tree(self, directory: str) -> bool:
        return os.path.isfile(os.path.join(directory, "debian", "control"))

    def _walk_source_trees(self, root: str) -> Iterable[str]:
        root_depth = root.rstrip(os.sep).count(os.sep)
        for current, dirs, files in os.walk(root, followlinks=self.options.follow_symlinks):
            depth = current.rstrip(os.sep).count(os.sep) - root_depth
            if depth > self.options.max_depth:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if d not in self.options.exclude_dirs]
            if "control" in files and os.path.basename(current) == "debian":
                package_dir = os.path.dirname(current)
                yield package_dir
                dirs[:] = []

    def _from_tree(self, directory: str) -> PackageInfo:
        control = os.path.join(directory, "debian", "control")
        source = package = maintainer = None
        version = None
        try:
            with open(control, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read(65536)
            match = _SOURCE_LINE.search(text) or _PACKAGE_LINE.search(text)
            source = match.group(1) if match else None
            package = source or os.path.basename(directory)
            maintainer_match = _MAINTAINER_LINE.search(text)
            maintainer = maintainer_match.group(1).strip() if maintainer_match else None
        except OSError:
            package = os.path.basename(directory)
        changelog = os.path.join(directory, "debian", "changelog")
        try:
            with open(changelog, "r", encoding="utf-8", errors="replace") as fh:
                first = fh.readline().strip()
            match = _CHANGELOG.match(first)
            if match:
                version = match.group(2)
        except OSError:
            pass
        return PackageInfo(
            name=package or os.path.basename(directory),
            version=version or "unknown",
            directory=directory,
            kind="tree",
            source=source,
            maintainer=maintainer,
        )

    def _from_dsc(self, path: str) -> List[PackageInfo]:
        headers = _parse_dsc(path)
        source = headers.get("source") or os.path.basename(path).split("_")[0]
        version = headers.get("version") or "unknown"
        directory = ""
        notes: List[str] = []
        if self.options.unpack_dsc:
            directory = self._unpack_dsc(path, source, version, notes)
        else:
            notes.append("dsc recorded without unpacking (set discovery.unpack_dsc: true)")
        return [PackageInfo(name=source, version=version, directory=directory, kind="dsc",
                            source=source, dsc_path=path, notes=notes)]

    def _unpack_dsc(self, path: str, source: str, version: str, notes: List[str]) -> str:
        if not shutil.which("dpkg-source"):
            notes.append("dpkg-source not available, cannot unpack")
            return ""
        workdir = self.options.workdir or os.path.join(os.path.dirname(path), ".redos-work")
        os.makedirs(workdir, exist_ok=True)
        target = os.path.join(workdir, f"{source}-{version}")
        if os.path.isdir(target):
            return target
        try:
            proc = subprocess.run(["dpkg-source", "-x", "--no-copy", path, target],
                                  capture_output=True, text=True, timeout=600)
        except (OSError, subprocess.SubprocessError) as exc:
            notes.append(f"dpkg-source failed: {exc}")
            return ""
        if proc.returncode != 0:
            notes.append(f"dpkg-source failed: {proc.stderr.strip()[:300]}")
            return ""
        return target

    def _synthetic(self, directory: str) -> PackageInfo:
        name = os.path.basename(directory.rstrip(os.sep)) or "unknown"
        version = "unknown"
        changelog = os.path.join(directory, "debian", "changelog")
        if os.path.isfile(changelog):
            try:
                with open(changelog, "r", encoding="utf-8", errors="replace") as fh:
                    match = _CHANGELOG.match(fh.readline().strip())
                if match:
                    name, version = match.group(1), match.group(2)
            except OSError:
                pass
        return PackageInfo(name=name, version=version, directory=directory, kind="dir")

    # -- file enumeration ---------------------------------------------------
    def files(self, package: PackageInfo) -> List[SourceFile]:
        if not package.directory or not os.path.isdir(package.directory):
            return []
        extensions = self.options.extensions or {}
        by_extension: Dict[str, str] = {}
        for language, values in extensions.items():
            for extension in values:
                by_extension[extension.lower()] = language
        max_bytes = self.options.max_file_size_kb * 1024
        files: List[SourceFile] = []
        for current, dirs, names in os.walk(package.directory,
                                           followlinks=self.options.follow_symlinks):
            dirs[:] = [d for d in dirs if d not in self.options.exclude_dirs
                       and d != "debian"]
            for name in sorted(names):
                if name.startswith("."):
                    continue
                abspath = os.path.join(current, name)
                if os.path.islink(abspath) and not self.options.follow_symlinks:
                    continue
                language = by_extension.get(os.path.splitext(name)[1].lower())
                if language is None:
                    language = detect_language(abspath)
                if language is None:
                    continue
                try:
                    stat = os.stat(abspath)
                except OSError:
                    continue
                if stat.st_size > max_bytes:
                    continue
                digest = _sha256(abspath)
                if digest is None:
                    continue
                rel = os.path.relpath(abspath, package.directory)
                files.append(SourceFile(
                    package=package.name,
                    version=package.version,
                    path=rel.replace(os.sep, "/"),
                    abspath=abspath,
                    language=language,
                    sha256=digest,
                    size=stat.st_size,
                    lines=_count_lines(abspath),
                ))
                if self.options.max_files and len(files) >= self.options.max_files:
                    return files
        return files


def _parse_dsc(path: str) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    break
                if line[0] in " \t":
                    continue
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()
    except OSError:
        pass
    return headers


def _sha256(path: str) -> Optional[str]:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _count_lines(path: str) -> int:
    count = 0
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                count += chunk.count(b"\n")
    except OSError:
        return 0
    return count
