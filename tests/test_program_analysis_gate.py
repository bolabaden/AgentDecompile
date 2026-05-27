"""Unit tests for blocking program analysis coordination."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agentdecompile_cli.mcp_utils import program_analysis as pa


@pytest.mark.unit
@pytest.mark.parametrize(
    "tool_name",
    sorted(pa._ANALYSIS_GATE_EXEMPT_TOOLS),
)
def test_analysis_gate_exempt_tools(tool_name: str) -> None:
    assert pa.analysis_gate_exempt_tool(tool_name) is True


@pytest.mark.unit
@pytest.mark.parametrize("tool_name", ["getfunction", "listfunctions", "decompilefunction"])
def test_analysis_gate_non_exempt_tools(tool_name: str) -> None:
    assert pa.analysis_gate_exempt_tool(tool_name) is False


@pytest.mark.unit
def test_wait_for_program_analysis_ready_marks_complete_only_when_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/bin.exe"
    program.getDomainFile.return_value = df
    info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)

    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", lambda *_a, **_k: None)
    with patch.object(pa, "program_needs_analysis", side_effect=[True, True, False]):
        run_mock = MagicMock()
        monkeypatch.setattr(pa, "_run_auto_analysis", run_mock)
        pa.wait_for_program_analysis_ready(program, info, program_path="/bin.exe")

    run_mock.assert_called_once()
    assert info.ghidra_analysis_complete is True


@pytest.mark.unit
def test_wait_for_program_analysis_ready_raises_when_still_needs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/bin.exe"
    program.getDomainFile.return_value = df
    info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)

    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", lambda *_a, **_k: None)
    with (
        patch.object(pa, "program_needs_analysis", return_value=True),
        patch.object(pa, "_run_auto_analysis", MagicMock()),
        pytest.raises(pa.ProgramAnalysisTimeout, match="did not complete"),
    ):
        pa.wait_for_program_analysis_ready(program, info, program_path="/bin.exe")

    assert info.ghidra_analysis_complete is False


@pytest.mark.unit
def test_program_needs_analysis_false_for_stub_without_analysis_state() -> None:
    class _StubProgram:
        def getName(self) -> str:
            return "stub"

    assert pa.program_needs_analysis(_StubProgram()) is False  # type: ignore[arg-type]


@pytest.mark.unit
def test_wait_for_ready_marks_stub_without_analysis_state_complete() -> None:
    class _StubProgram:
        def getName(self) -> str:
            return "stub"

    info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)
    pa.wait_for_program_analysis_ready(_StubProgram(), info)  # type: ignore[arg-type]
    assert info.ghidra_analysis_complete is True
    assert not pa._LOCKS


@pytest.mark.unit
def test_blocking_ensure_skips_stub_without_analysis_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _StubProgram:
        def getName(self) -> str:
            return "stub"

    run_mock = MagicMock()
    monkeypatch.setattr(pa, "run_analysis", run_mock)
    info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)
    result = pa.blocking_ensure_analyzed(_StubProgram(), info)  # type: ignore[arg-type]

    run_mock.assert_not_called()
    assert result.get("skipped") is True
    assert result.get("reason") == "already-analyzed"
    assert info.ghidra_analysis_complete is True
    assert not pa._LOCKS


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

    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", lambda *_a, **_k: None)
    with patch.object(pa, "program_needs_analysis", side_effect=[True, False]):
        run_mock = MagicMock()
        monkeypatch.setattr(pa, "run_analysis", run_mock)
        info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)
        result = pa.blocking_ensure_analyzed(program, info, program_path="/bin.exe")

    assert result.get("ran") is True
    run_mock.assert_called_once_with(program, force_analysis=False)
    assert info.ghidra_analysis_complete is True


@pytest.mark.unit
def test_wait_for_program_analysis_idle_raises_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = MagicMock()
    state = MagicMock()
    state.isDone.return_value = False
    program.getAnalysisState.return_value = state

    tick = iter([0.0, 5.0, 10.0])
    monkeypatch.setattr(pa.time, "time", lambda: next(tick))
    monkeypatch.setattr(pa.time, "sleep", lambda _sec: None)

    with patch.object(pa, "_program_analysis_still_running", return_value=True):
        with pytest.raises(pa.ProgramAnalysisTimeout):
            pa.wait_for_program_analysis_idle(program, max_wait_sec=10.0)


@pytest.mark.unit
def test_blocking_ensure_raises_when_still_needs_after_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/bin.exe"
    program.getDomainFile.return_value = df

    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", lambda *_a, **_k: None)
    with (
        patch.object(pa, "program_needs_analysis", return_value=True),
        pytest.raises(pa.ProgramAnalysisTimeout, match="did not complete"),
    ):
        run_mock = MagicMock()
        monkeypatch.setattr(pa, "run_analysis", run_mock)
        info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)
        pa.blocking_ensure_analyzed(program, info, program_path="/bin.exe")

    run_mock.assert_called_once()
    assert info.ghidra_analysis_complete is False


@pytest.mark.unit
def test_wait_for_ready_skips_when_session_marked_and_ghidra_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/session-done.exe"
    program.getDomainFile.return_value = df
    info = SimpleNamespace(ghidra_analysis_complete=True, analysis_complete=True)

    idle_mock = MagicMock()
    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", idle_mock)
    with patch.object(pa, "program_needs_analysis", return_value=False):
        pa.wait_for_program_analysis_ready(program, info, program_path="/session-done.exe")

    idle_mock.assert_not_called()


@pytest.mark.unit
def test_wait_for_ready_skips_work_when_ghidra_already_analyzed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/already-done.exe"
    program.getDomainFile.return_value = df
    info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)

    idle_mock = MagicMock()
    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", idle_mock)
    with patch.object(pa, "program_needs_analysis", return_value=False):
        pa.wait_for_program_analysis_ready(program, info, program_path="/already-done.exe")

    idle_mock.assert_not_called()
    assert info.ghidra_analysis_complete is True


@pytest.mark.unit
def test_wait_for_ready_releases_lock_on_idle_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/wait-timeout.exe"
    program.getDomainFile.return_value = df

    monkeypatch.setattr(
        pa,
        "wait_for_program_analysis_idle",
        lambda *_a, **_k: (_ for _ in ()).throw(pa.ProgramAnalysisTimeout("idle timeout")),
    )
    with (
        patch.object(pa, "program_needs_analysis", return_value=True),
        pytest.raises(pa.ProgramAnalysisTimeout),
    ):
        pa.wait_for_program_analysis_ready(program, program_path="/wait-timeout.exe")

    assert "/wait-timeout.exe" not in pa._LOCKS


@pytest.mark.unit
def test_blocking_ensure_releases_lock_on_analysis_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/release-on-error.exe"
    program.getDomainFile.return_value = df
    info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)

    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", lambda *_a, **_k: None)

    def _boom(*_a, **_k):
        raise RuntimeError("analysis failed")

    monkeypatch.setattr(pa, "run_analysis", _boom)
    with patch.object(pa, "program_needs_analysis", return_value=True):
        with pytest.raises(RuntimeError, match="analysis failed"):
            pa.blocking_ensure_analyzed(program, info, program_path="/release-on-error.exe")

    assert "/release-on-error.exe" not in pa._LOCKS


@pytest.mark.unit
def test_blocking_ensure_releases_lock_after_run(monkeypatch: pytest.MonkeyPatch) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/release-after-ensure.exe"
    program.getDomainFile.return_value = df
    info = SimpleNamespace(ghidra_analysis_complete=False, analysis_complete=False)

    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", lambda *_a, **_k: None)
    with patch.object(pa, "program_needs_analysis", side_effect=[True, False]):
        monkeypatch.setattr(pa, "run_analysis", MagicMock())
        pa.blocking_ensure_analyzed(program, info, program_path="/release-after-ensure.exe")

    assert "/release-after-ensure.exe" not in pa._LOCKS


@pytest.mark.unit
def test_blocking_ensure_skips_idle_wait_when_session_already_analyzed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/bin.exe"
    program.getDomainFile.return_value = df
    info = SimpleNamespace(ghidra_analysis_complete=True, analysis_complete=True)

    idle_mock = MagicMock()
    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", idle_mock)
    with patch.object(pa, "program_needs_analysis", return_value=False):
        result = pa.blocking_ensure_analyzed(program, info, program_path="/bin.exe")

    idle_mock.assert_not_called()
    assert result.get("skipped") is True
    assert result.get("programKey") == "/bin.exe"
    assert "/bin.exe" not in pa._LOCKS


@pytest.mark.unit
def test_blocking_ensure_prelock_skip_when_session_marked_and_ghidra_done(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = MagicMock()
    df = MagicMock()
    df.getPathname.return_value = "/prelock-skip.exe"
    program.getDomainFile.return_value = df
    info = SimpleNamespace(ghidra_analysis_complete=True, analysis_complete=True)

    idle_mock = MagicMock()
    monkeypatch.setattr(pa, "wait_for_program_analysis_idle", idle_mock)
    with patch.object(pa, "program_needs_analysis", return_value=False):
        result = pa.blocking_ensure_analyzed(program, info, program_path="/prelock-skip.exe")

    idle_mock.assert_not_called()
    assert result == {
        "skipped": True,
        "reason": "already-analyzed",
        "programKey": "/prelock-skip.exe",
    }
    assert "/prelock-skip.exe" not in pa._LOCKS


@pytest.mark.unit
def test_wait_for_program_analysis_idle_uses_adaptive_polling() -> None:
    program = MagicMock()
    sleeps: list[float] = []
    with (
        patch.object(pa.time, "time", side_effect=[0.0, 0.0, 0.1, 10.0]),
        patch.object(pa.time, "sleep", side_effect=lambda sec: sleeps.append(sec)),
        patch.object(pa, "_program_analysis_still_running", side_effect=[True, False]),
    ):
        pa.wait_for_program_analysis_idle(program, max_wait_sec=600.0)

    assert len(sleeps) == 1
    assert sleeps[0] == pa._POLL_INTERVAL_MIN_SEC


@pytest.mark.unit
def test_release_program_lock_prunes_idle_entry() -> None:
    key = "/prune-test.exe"
    lock = pa._lock_for_key(key)
    assert key in pa._LOCKS
    pa._release_program_lock(key, lock)
    assert key not in pa._LOCKS


@pytest.mark.unit
def test_release_program_lock_keeps_locked_entry() -> None:
    key = "/locked-test.exe"
    lock = pa._lock_for_key(key)
    lock.acquire()
    try:
        pa._release_program_lock(key, lock)
        assert key in pa._LOCKS
    finally:
        lock.release()
    pa._release_program_lock(key, lock)
    assert key not in pa._LOCKS


@pytest.mark.unit
def test_program_analysis_module_exports_public_api() -> None:
    expected = {
        "ProgramAnalysisTimeout",
        "analysis_gate_exempt_tool",
        "blocking_ensure_analyzed",
        "mark_program_analysis_complete",
        "program_needs_analysis",
        "wait_for_program_analysis_idle",
        "wait_for_program_analysis_ready",
    }
    assert set(pa.__all__) == expected
    for name in pa.__all__:
        assert hasattr(pa, name), f"missing export: {name}"
