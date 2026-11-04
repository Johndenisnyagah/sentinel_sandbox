"""Shared fixtures: every test gets a fresh SQLite file and a fresh app import."""

import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def app_module(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "test.db"))
    for name in [m for m in sys.modules if m == "main" or m.startswith("app")]:
        del sys.modules[name]
    return importlib.import_module("main")


@pytest.fixture
def client(app_module):
    with TestClient(app_module.app) as c:
        yield c
