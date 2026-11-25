"""Configuration loading and hashing tests."""

from __future__ import annotations

import copy

from debian_redos import config as config_module
from debian_redos.config import Config, DEFAULT_CONFIG, load_config, load_yaml


def test_shipped_config_loads(config_path):
    config = load_config(config_path)
    assert config.language_enabled("python")
    assert config.language_enabled("ruby")
    assert config.get("dynamic.sizes.exponential")[0] == 8
    assert isinstance(config.get("discovery.exclude_dirs"), list)
    assert config.get("static.enable_external") is False
    assert config.get("output.dir") == "reports"


def test_minimal_yaml_fallback(monkeypatch, config_path):
    monkeypatch.setattr(config_module, "_yaml", None)
    text = open(config_path, encoding="utf-8").read()
    data = load_yaml(text)
    assert data["languages"]["python"]["enabled"] is True
    assert data["limits"]["max_input_length"] == 8192
    assert data["dynamic"]["sizes"]["polynomial"][-1] == 8192
    assert "node_modules" in data["discovery"]["exclude_dirs"]
    assert data["cve"]["db"] is None

    config = load_config(config_path)
    assert config.get("dynamic.php_docker_image") == "php:8.2-cli"


def test_config_hash_ignores_output_but_tracks_limits(config_path):
    base = load_config(config_path)
    same = load_config(config_path)
    assert base.config_hash == same.config_hash

    changed = load_config(config_path)
    changed.raw["output"]["dir"] = "elsewhere"
    assert changed.config_hash == base.config_hash

    changed.raw["limits"]["timeout_seconds"] = 9.0
    assert changed.config_hash != base.config_hash


def test_overrides_are_deep_merged():
    config = load_config(None, overrides={"limits": {"timeout_seconds": 0.25}})
    assert config.limit("timeout_seconds") == 0.25
    assert config.limit("max_input_length") == DEFAULT_CONFIG["limits"]["max_input_length"]


def test_typed_helpers():
    config = Config(copy.deepcopy(DEFAULT_CONFIG))
    assert config.extensions("python") == [".py", ".pyw"]
    assert config.static_detectors("ruby") == ["heuristics"]
    assert config.dynamic_workers("php") == ["php_worker"]
    assert config.config_hash.startswith("sha256:")


def test_shorthand_lists(tmp_path):
    path = tmp_path / "short.yaml"
    path.write_text("languages:\n  python:\n    static: heuristics\n    dynamic: python_worker\n")
    config = load_config(str(path))
    assert config.static_detectors("python") == ["heuristics"]
    assert config.dynamic_workers("python") == ["python_worker"]
