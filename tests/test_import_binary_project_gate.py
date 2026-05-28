from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider


@pytest.mark.unit
@pytest.mark.asyncio
async def test_import_binary_fails_without_open_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"\x90" * 16)

    monkeypatch.delenv("AGENT_DECOMPILE_PROJECT_PATH", raising=False)
    monkeypatch.delenv("AGENTDECOMPILE_PROJECT_PATH", raising=False)

    provider = ImportExportToolProvider()
    provider._manager = cast(Any, SimpleNamespace(ghidra_project=None))

    result = await provider._handle_import({"path": str(binary)})
    payload = json.loads(result[0].text)

    assert payload["success"] is False
    assert "No Ghidra project is open" in payload["error"]
    assert any("open" in step.lower() for step in payload.get("nextSteps", []))
