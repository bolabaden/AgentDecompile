"""Unit tests for shared MCP tool-seq executor."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from agentdecompile_recovery.mcp_tool_seq import (
    bootstrap_local_program_steps,
    resolve_import_binary_path,
    resolve_program_path,
    run_tool_seq,
)

pytestmark = pytest.mark.unit


def test_run_tool_seq_empty_steps(tmp_path: Path) -> None:
    result = run_tool_seq([], work_dir=tmp_path)
    assert result["status"] == "skipped:empty"


def test_run_tool_seq_success(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()

    def fake_run(cmd, *, timeout):
        return subprocess.CompletedProcess(cmd, 0, stdout='{"success": true}', stderr="")

    with patch("agentdecompile_recovery.mcp_tool_seq.shutil.which", return_value="/usr/bin/uv"):
        result = run_tool_seq(
            [{"name": "rename-function", "arguments": {"addressOrSymbol": "0x401000", "name": "Foo"}}],
            work_dir=work,
            server_url="http://127.0.0.1:8080",
            program_path="game.exe",
            run_subprocess=fake_run,
        )
    assert result["status"] == "complete"
    assert result["toolsInvoked"] == ["rename-function"]
    assert (work / "state" / "mcp-tool-seq-last.json").is_file()


def test_run_tool_seq_conflict(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()

    def fake_run(cmd, *, timeout):
        return subprocess.CompletedProcess(cmd, 1, stdout="## Modification conflict\nconflictId abc", stderr="")

    with patch("agentdecompile_recovery.mcp_tool_seq.shutil.which", return_value="/usr/bin/uv"):
        result = run_tool_seq(
            [{"name": "rename-function", "arguments": {}}],
            work_dir=work,
            run_subprocess=fake_run,
        )
    assert result["status"] == "conflict"


def test_resolve_import_binary_path_prefers_analysis_image(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    original = work / "swkotor.exe"
    unpacked = work / "swkotor.exe.unpacked.exe"
    original.write_bytes(b"pe")
    unpacked.write_bytes(b"pe2")
    (work / "analysis-target.json").write_text(
        json.dumps(
            {
                "originalBinaryPath": str(original),
                "analysisBinaryPath": str(unpacked),
            }
        ),
        encoding="utf-8",
    )
    assert resolve_import_binary_path(work) == str(unpacked)
    assert resolve_program_path(work) == "swkotor.exe.unpacked.exe"


def test_bootstrap_local_program_steps_prepends_open_project(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    binary = work / "game.exe"
    binary.write_bytes(b"pe")
    (work / "target.json").write_text(json.dumps({"binaryPath": str(binary)}), encoding="utf-8")

    steps = bootstrap_local_program_steps(work)
    assert len(steps) == 2
    assert steps[0]["name"] == "open-project"
    assert steps[1]["name"] == "analyze-program"
    assert steps[0]["arguments"]["path"] == str(binary)


def test_run_tool_seq_local_prepends_open_project(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    binary = work / "game.exe"
    binary.write_bytes(b"pe")
    (work / "target.json").write_text(json.dumps({"binaryPath": str(binary)}), encoding="utf-8")
    captured: dict[str, Any] = {}

    def fake_run(cmd, *, timeout):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout='{"success": true}', stderr="")

    with patch("agentdecompile_recovery.mcp_tool_seq.shutil.which", return_value="/usr/bin/uv"):
        result = run_tool_seq(
            [{"name": "rename-function", "arguments": {"addressOrSymbol": "0x401000", "name": "Foo"}}],
            work_dir=work,
            run_subprocess=fake_run,
        )
    assert result["status"] == "complete"
    assert result["bootstrapSteps"] == 2
    payload = json.loads(captured["cmd"][-1])
    assert payload[0]["name"] == "open-project"
    assert payload[0]["arguments"]["path"] == str(binary)
    assert "programPath" not in payload[0]["arguments"]
    assert payload[1]["name"] == "analyze-program"
    assert payload[2]["name"] == "rename-function"
    assert payload[2]["arguments"]["programPath"] == "game.exe"
