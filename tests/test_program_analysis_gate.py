"""Unit tests for blocking program analysis coordination."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agentdecompile_cli.mcp_utils import program_analysis as pa


@pytest.mark.unit
def test_analysis_gate_exempt_tools() -> None:
    assert pa.analysis_gate_exempt_tool("open") is True
    assert pa.analysis_gate_exempt_tool("importbinary") is True
    assert pa.analysis_gate_exempt_tool("getfunction") is False


@pytest.mark.unit
def test_program_needs_analysis_when_state_not_done() -> None:
    program = MagicMock()
    state = MagicMock()
    state.isDone.return_value = False
    program.getAnalysisState.return_value = state
    assert pa.program_needs_analysis(program) is True


@pytest.mark.unit
def test_program_needs_analysis_skips_when_state_done() -> None:
    program = MagicMock()
    state = MagicMock()
    state.isDone.return_value = True
    program.getAnalysisState.return_value = state
    assert pa.program_needs_analysis(program) is False


@pytest.mark.unit
def test_blocking_ensure_skips_when_already_analyzed(monkeypatch: pytest.MonkeyPatch) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/bin.exe"
    program.getDomainFile.return_value = df
    state = MagicMock()
    state.isDone.return_value = True
    program.getAnalysisState.return_value = state
    run_mock = MagicMock()
    monkeypatch.setattr(pa, "run_analysis", run_mock)

    info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)
    result = pa.blocking_ensure_analyzed(program, info, program_path="/bin.exe")

    assert result.get("skipped") is True
    run_mock.assert_not_called()
    assert info.ghidra_analysis_complete is True


@pytest.mark.unit
def test_blocking_ensure_runs_analysis_when_needed(monkeypatch: pytest.MonkeyPatch) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/bin.exe"
    program.getDomainFile.return_value = df
    state = MagicMock()
    state.isDone.side_effect = [False, True]
    program.getAnalysisState.return_value = state

    with patch.object(pa, "program_needs_analysis", return_value=True):
        run_mock = MagicMock()
        monkeypatch.setattr(pa, "run_analysis", run_mock)
        info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)
        result = pa.blocking_ensure_analyzed(program, info, program_path="/bin.exe")

    assert result.get("ran") is True
    run_mock.assert_called_once_with(program, force_analysis=False)
    assert info.ghidra_analysis_complete is True
