"""Shared pytest fixtures and paths."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURE_PACKAGE = ROOT / "tests" / "fixtures" / "samplepkg"


@pytest.fixture()
def fixture_package() -> str:
    return str(FIXTURE_PACKAGE)


@pytest.fixture()
def config_path() -> str:
    return str(ROOT / "config" / "scanners.yaml")


@pytest.fixture()
def config(config_path):
    from debian_redos.config import load_config

    return load_config(config_path)
