from __future__ import annotations

import os

import pytest

from agentdecompile_cli.server import _normalize_shared_server_env_aliases

pytestmark = pytest.mark.unit


_ENV_KEYS = [
    "AGENT_DECOMPILE_GHIDRA_SERVER_HOST",
    "AGENT_DECOMPILE_GHIDRA_SERVER_PORT",
    "AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME",
    "AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD",
    "AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY",
    "AGENTDECOMPILE_GHIDRA_SERVER_HOST",
    "AGENTDECOMPILE_GHIDRA_SERVER_PORT",
    "AGENTDECOMPILE_GHIDRA_SERVER_USERNAME",
    "AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD",
    "AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY",
    "AGENT_DECOMPILE_SERVER_HOST",
    "AGENT_DECOMPILE_SERVER_PORT",
    "AGENT_DECOMPILE_SERVER_USERNAME",
    "AGENT_DECOMPILE_SERVER_PASSWORD",
    "AGENTDECOMPILE_SERVER_HOST",
    "AGENTDECOMPILE_SERVER_PORT",
    "AGENTDECOMPILE_SERVER_USERNAME",
    "AGENTDECOMPILE_SERVER_PASSWORD",
    "AGENT_DECOMPILE_REPOSITORY",
    "AGENTDECOMPILE_REPOSITORY",
]


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_normalize_accepts_compact_ghidra_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)

    monkeypatch.setenv("AGENTDECOMPILE_GHIDRA_SERVER_HOST", "170.9.241.140")
    monkeypatch.setenv("AGENTDECOMPILE_GHIDRA_SERVER_PORT", "13100")
    monkeypatch.setenv("AGENTDECOMPILE_GHIDRA_SERVER_USERNAME", "th3w1zard1")
    monkeypatch.setenv("AGENTDECOMPILE_GHIDRA_SERVER_PASSWORD", "c3ll0h3r0327")
    monkeypatch.setenv("AGENTDECOMPILE_GHIDRA_SERVER_REPOSITORY", "Odyssey")

    _normalize_shared_server_env_aliases()

    assert os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_HOST"] == "170.9.241.140"
    assert os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_PORT"] == "13100"
    assert os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_USERNAME"] == "th3w1zard1"
    assert os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_PASSWORD"] == "c3ll0h3r0327"
    assert os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_REPOSITORY"] == "Odyssey"

    # Bridge/proxy compatibility aliases should also be hydrated.
    assert os.environ["AGENT_DECOMPILE_SERVER_HOST"] == "170.9.241.140"
    assert os.environ["AGENT_DECOMPILE_SERVER_PORT"] == "13100"
    assert os.environ["AGENT_DECOMPILE_SERVER_USERNAME"] == "th3w1zard1"
    assert os.environ["AGENT_DECOMPILE_SERVER_PASSWORD"] == "c3ll0h3r0327"


def test_normalize_does_not_override_existing_canonical_values(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)

    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_HOST", "canonical.host")
    monkeypatch.setenv("AGENTDECOMPILE_GHIDRA_SERVER_HOST", "alias.host")
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_SERVER_PORT", "13101")
    monkeypatch.setenv("AGENTDECOMPILE_GHIDRA_SERVER_PORT", "13100")

    _normalize_shared_server_env_aliases()

    assert os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_HOST"] == "canonical.host"
    assert os.environ["AGENT_DECOMPILE_GHIDRA_SERVER_PORT"] == "13101"
    assert os.environ["AGENT_DECOMPILE_SERVER_HOST"] == "canonical.host"
    assert os.environ["AGENT_DECOMPILE_SERVER_PORT"] == "13101"
