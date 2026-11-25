"""Package discovery and file enumeration tests."""

from __future__ import annotations

import os

from debian_redos.core.discovery import Discoverer, DiscoveryOptions


def test_discovers_unpacked_debian_tree(fixture_package):
    discoverer = Discoverer(DiscoveryOptions.from_config(_config()))
    packages = discoverer.discover([fixture_package])
    assert len(packages) == 1
    package = packages[0]
    assert package.name == "redos-fixture"
    assert package.version == "1.0-1"
    assert package.kind == "tree"
    assert package.maintainer == "Test Maintainer <test@example.com>"


def test_accepts_a_single_string_path(fixture_package):
    discoverer = Discoverer()
    packages = discoverer.discover(fixture_package)
    assert [p.name for p in packages] == ["redos-fixture"]


def test_enumerates_supported_files_and_skips_debian(fixture_package):
    discoverer = Discoverer(DiscoveryOptions.from_config(_config()))
    package = discoverer.discover([fixture_package])[0]
    files = discoverer.files(package)
    paths = {f.path for f in files}
    assert paths == {"app.py", "lib.rb", "web.php"}
    assert all(f.sha256 and f.size > 0 for f in files)
    assert all(f.language for f in files)
    assert all(not f.path.startswith("debian/") for f in files)


def test_file_hashes_are_stable_and_change_with_content(fixture_package, tmp_path):
    import shutil

    target = tmp_path / "pkg"
    shutil.copytree(fixture_package, target)
    discoverer = Discoverer(DiscoveryOptions.from_config(_config()))
    first = discoverer.files(discoverer.discover([str(target)])[0])
    before = {f.path: f.sha256 for f in first}
    (target / "app.py").write_text("import re\nre.match('^(a+)+$', 'x')\n")
    second = discoverer.files(discoverer.discover([str(target)])[0])
    after = {f.path: f.sha256 for f in second}
    assert before["lib.rb"] == after["lib.rb"]
    assert before["app.py"] != after["app.py"]


def test_synthetic_plain_directory(tmp_path):
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "script.py").write_text("import re\nre.match('a', 'a')\n")
    discoverer = Discoverer(DiscoveryOptions.from_config(_config()))
    packages = discoverer.discover([str(tmp_path / "demo")])
    assert len(packages) == 1
    assert packages[0].kind == "dir"
    assert packages[0].directory.endswith("demo")


def test_missing_path_is_reported_not_fatal(tmp_path):
    discoverer = Discoverer()
    packages = discoverer.discover([str(tmp_path / "nope")])
    assert packages == []
    assert any("does not exist" in note for note in discoverer.notes)


def test_dsc_is_recorded_without_unpacking(tmp_path):
    dsc = tmp_path / "demo_1.2-3.dsc"
    dsc.write_text(
        "Format: 3.0 (quilt)\n"
        "Source: demo\n"
        "Version: 1.2-3\n"
        "Maintainer: Someone <s@example.com>\n"
    )
    discoverer = Discoverer()
    packages = discoverer.discover([str(dsc)])
    assert packages[0].name == "demo"
    assert packages[0].version == "1.2-3"
    assert packages[0].kind == "dsc"
    assert packages[0].directory == ""
    assert packs_note_mentions_unpacking(packages[0].notes)


def packs_note_mentions_unpacking(notes) -> bool:
    return any("without unpacking" in note for note in notes)


def _config():
    from debian_redos.config import load_config
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    return load_config(str(root / "config" / "scanners.yaml"))
