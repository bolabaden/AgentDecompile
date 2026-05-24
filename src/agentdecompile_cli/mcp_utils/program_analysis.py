"""Blocking per-program auto-analysis coordination for MCP tools."""

from __future__ import annotations

import logging
import threading
import time
from typing import TYPE_CHECKING, Any

from ghidrecomp.utility import analyze_program as run_analysis

if TYPE_CHECKING:
    from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingModuleSource]

    from agentdecompile_cli.context import ProgramInfo

logger = logging.getLogger(__name__)


class ProgramAnalysisTimeout(TimeoutError):
    """Ghidra auto-analysis did not become idle within the allowed wait."""


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()

# Tools that manage analysis themselves or do not need an analyzed program yet.
_ANALYSIS_GATE_EXEMPT_TOOLS: frozenset[str] = frozenset(
    {
        "open",
        "importbinary",
        "analyzeprogram",
        "listprojectfiles",
        "listtools",
        "connectsharedproject",
        "syncproject",
        "svradmin",
        "debuginfo",
        "getcurrentprogram",
    },
)


def analysis_gate_exempt_tool(norm_tool_name: str) -> bool:
    """Return True when call_tool should not wait on program analysis."""
    return norm_tool_name in _ANALYSIS_GATE_EXEMPT_TOOLS


def _program_lock_key(program: GhidraProgram, program_path: str | None = None) -> str:
    try:
        df = program.getDomainFile()
        if df is not None:
            return str(df.getPathname()).strip().replace("\\", "/").lower()
    except Exception:
        pass
    if program_path:
        return program_path.strip().replace("\\", "/").lower()
    try:
        return f"program:{int(program.hashCode())}"
    except Exception:
        return f"program:{id(program)}"


def _lock_for_key(key: str) -> threading.Lock:
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _LOCKS[key] = lock
        return lock


def _analysis_state_done(program: GhidraProgram) -> bool | None:
    try:
        st = program.getAnalysisState()
        if st is not None and hasattr(st, "isDone"):
            return bool(st.isDone())
    except Exception:
        pass
    return None


def program_needs_analysis(program: GhidraProgram, *, force: bool = False) -> bool:
    """True when Ghidra indicates analysis should run (incremental or full)."""
    if program is None:
        return False
    if force:
        return True
    state_done = _analysis_state_done(program)
    if state_done is False:
        return True
    if state_done is True:
        return False
    try:
        from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource]

        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            return True
        return not bool(GhidraProgramUtilities.isAnalyzed(program))
    except Exception:
        return True


def _program_analysis_still_running(program: GhidraProgram) -> bool:
    state_done = _analysis_state_done(program)
    if state_done is True:
        return False
    if state_done is False:
        return True
    try:
        from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource]

        return bool(GhidraProgramUtilities.shouldAskToAnalyze(program))
    except Exception:
        return state_done is not True


def wait_for_program_analysis_idle(program: GhidraProgram, *, max_wait_sec: float = 600.0) -> None:
    """Poll Ghidra analysis state until idle or raise ProgramAnalysisTimeout."""
    if program is None or max_wait_sec <= 0:
        return
    deadline = time.time() + max_wait_sec
    while time.time() < deadline:
        if not _program_analysis_still_running(program):
            return
        time.sleep(0.25)
    if _program_analysis_still_running(program):
        raise ProgramAnalysisTimeout(f"Ghidra analysis did not finish within {max_wait_sec}s")


def mark_program_analysis_complete(program_info: ProgramInfo | None) -> None:
    if program_info is None:
        return
    program_info.ghidra_analysis_complete = True
    if hasattr(program_info, "analysis_complete"):
        program_info.analysis_complete = True


def _run_auto_analysis(program: GhidraProgram, *, force: bool) -> None:
    run_analysis(program, force_analysis=force)
    wait_for_program_analysis_idle(program)


def blocking_ensure_analyzed(
    program: GhidraProgram,
    program_info: ProgramInfo | None = None,
    *,
    program_path: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Run incremental analysis under a per-program lock; skip when already complete."""
    if program is None:
        return {"skipped": True, "reason": "no-program"}

    key = _program_lock_key(program, program_path)
    lock = _lock_for_key(key)
    with lock:
        wait_for_program_analysis_idle(program)
        if not program_needs_analysis(program, force=force):
            mark_program_analysis_complete(program_info)
            return {"skipped": True, "reason": "already-analyzed", "programKey": key}

        logger.info("program_analysis_start key=%s force=%s", key, force)
        _run_auto_analysis(program, force=force)
        if not program_needs_analysis(program):
            mark_program_analysis_complete(program_info)
        logger.info("program_analysis_done key=%s", key)
        return {"ran": True, "programKey": key, "force": force}


def wait_for_program_analysis_ready(
    program: GhidraProgram,
    program_info: ProgramInfo | None = None,
    *,
    program_path: str | None = None,
    max_wait_sec: float = 600.0,
) -> None:
    """Block until analysis is complete; run incremental ensure if still needed."""
    if program is None:
        return
    if program_info is not None and bool(getattr(program_info, "ghidra_analysis_complete", False)):
        if not program_needs_analysis(program):
            return
    key = _program_lock_key(program, program_path)
    lock = _lock_for_key(key)
    with lock:
        wait_for_program_analysis_idle(program, max_wait_sec=max_wait_sec)
        if program_needs_analysis(program):
            logger.info("program_analysis_wait_ensure key=%s", key)
            _run_auto_analysis(program, force=False)
            wait_for_program_analysis_idle(program, max_wait_sec=max_wait_sec)
        if not program_needs_analysis(program):
            mark_program_analysis_complete(program_info)
