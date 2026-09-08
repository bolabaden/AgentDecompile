"""Environment-backed dashboard runtime configuration contracts."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.dashboard import common

pytestmark = pytest.mark.unit

CONFIG_ENV = (
    "AGENT_DECOMPILE_CORPUS_ROOT",
    "AGENT_DECOMPILE_CORPUS_WORK_DIR",
    "AGENT_DECOMPILE_CORPUS_DB",
    "AGENT_DECOMPILE_KNOWLEDGE_DB",
    "AGENT_DECOMPILE_EXTERNAL_RECOVERY_ROOT",
    "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
    "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
    "AGENT_DECOMPILE_EXCLUDED_REPO_PATHS",
)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch):
    for name in CONFIG_ENV:
        monkeypatch.delenv(name, raising=False)
    importlib.reload(common)
    yield common
    importlib.reload(common)


def test_defaults_have_no_kotorxid_or_mizuchi_paths(clean_env) -> None:
    assert clean_env.ROOT is None
    assert clean_env.DB_PATH is None
    assert clean_env.KNOWLEDGE_DB is None
    assert clean_env.MIZUCHI_R is None
    assert (clean_env.GHIDRA_SERVER_HOST, clean_env.GHIDRA_SERVER_PORT) == ("127.0.0.1", 0)
    assert clean_env.DRM_EXCLUDED == ()
    assert "kotorxid.sqlite" not in str(clean_env.as_root())
    assert "MizuchiRE" not in str(clean_env.as_external())


def test_environment_overrides_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_ROOT", str(tmp_path))
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(tmp_path / "main.sqlite"))
    monkeypatch.setenv("AGENT_DECOMPILE_KNOWLEDGE_DB", "runtime/knowledge.sqlite")
    monkeypatch.setenv("AGENT_DECOMPILE_EXTERNAL_RECOVERY_ROOT", str(tmp_path / "corpus"))
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "ghidra.internal")
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "14444")
    monkeypatch.setenv("AGENT_DECOMPILE_EXCLUDED_REPO_PATHS", json.dumps(["/encrypted/a", "/encrypted/b"]))
    importlib.reload(common)
    assert common.DB_PATH == tmp_path / "main.sqlite"
    assert common.KNOWLEDGE_DB == tmp_path / "runtime" / "knowledge.sqlite"
    assert common.MIZUCHI_R == tmp_path / "corpus"
    assert (common.GHIDRA_SERVER_HOST, common.GHIDRA_SERVER_PORT) == ("ghidra.internal", 14444)
    assert common.DRM_EXCLUDED == ("/encrypted/a", "/encrypted/b")
    importlib.reload(common)


def test_invalid_ports_fall_back(monkeypatch: pytest.MonkeyPatch) -> None:
    for value in ("0", "65536", "-2", "not-a-port", ""):
        monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", value)
        importlib.reload(common)
        assert common.GHIDRA_SERVER_PORT == 0
    importlib.reload(common)


def test_invalid_paths_host_and_exclusions_fall_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", "   ")
    monkeypatch.setenv("AGENT_DECOMPILE_EXTERNAL_RECOVERY_ROOT", "   ")
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "bad\nname")
    importlib.reload(common)
    assert common.DB_PATH is None
    assert common.GHIDRA_SERVER_HOST == "127.0.0.1"
    for value in ("not-json", "{}", '["ok", 2]', '[""]'):
        monkeypatch.setenv("AGENT_DECOMPILE_EXCLUDED_REPO_PATHS", value)
        importlib.reload(common)
        assert common.DRM_EXCLUDED == common._DEFAULT_DRM_EXCLUDED
    importlib.reload(common)


def test_empty_exclusions_and_address_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_DECOMPILE_EXCLUDED_REPO_PATHS", "[]")
    importlib.reload(common)
    assert common.DRM_EXCLUDED == ()
    assert common.parse_address("00401080") == 0x401080
    assert common.format_address(0x401080, 32) == "0x00401080"
    importlib.reload(common)
