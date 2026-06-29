"""Blocking per-program auto-analysis coordination for MCP tools."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from ghidrecomp.utility import analyze_program as run_analysis

if TYPE_CHECKING:
    from ghidra.program.model.listing import Program as GhidraProgram  # pyright: ignore[reportMissingModuleSource]

    from agentdecompile_cli.context import ProgramInfo

logger = logging.getLogger(__name__)

__all__ = [
    "ProgramAnalysisTimeout",
    "analysis_gate_exempt_tool",
    "blocking_ensure_analyzed",
    "mark_program_analysis_complete",
    "program_needs_analysis",
    "wait_for_program_analysis_idle",
    "wait_for_program_analysis_ready",
]


class ProgramAnalysisTimeout(TimeoutError):
    """Ghidra auto-analysis did not become idle within the allowed wait."""


_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()
# Cap entries on long-lived MCP servers; idle locks are dropped after each ensure/wait.
_MAX_PROGRAM_LOCKS = 512
# Idle polling: quick checks when analysis finishes early; backoff while Ghidra is busy.
_POLL_INTERVAL_MIN_SEC = 0.05
_POLL_INTERVAL_MAX_SEC = 1.0
_POLL_BACKOFF_FACTOR = 1.5

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
        # Version-control lifecycle tools do not require an analyzed listing yet.
        "checkoutprogram",
        "checkinprogram",
        "checkoutstatus",
    },
)


def analysis_gate_exempt_tool(norm_tool_name: str) -> bool:
    """Return True when call_tool should not wait on program analysis."""
    return norm_tool_name in _ANALYSIS_GATE_EXEMPT_TOOLS


def _program_supports_analysis_observation(program: GhidraProgram) -> bool:
    """Return False for test doubles and other objects that are not Ghidra programs."""
    return callable(getattr(program, "getAnalysisState", None))


def _program_lock_key(program: GhidraProgram, program_path: str | None = None) -> str:
    try:
        df = program.getDomainFile()
        if df is not None:
            return str(df.getPathname()).strip().replace("\\", "/").lower()
    except Exception:
        # Best-effort lookup: some Program implementations may not expose a domain file.
        # Fall back to program_path/hashCode/id below to keep lock-key generation robust.
        logger.debug("Unable to derive lock key from program domain file; using fallback key", exc_info=True)
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


@contextmanager
def _program_analysis_lock(
    program: GhidraProgram,
    program_path: str | None = None,
) -> Iterator[str]:
    """Acquire per-program lock; always prune idle entry on exit (including errors)."""
    key = _program_lock_key(program, program_path)
    lock = _lock_for_key(key)
    try:
        with lock:
            yield key
    finally:
        _release_program_lock(key, lock)


def _release_program_lock(key: str, lock: threading.Lock) -> None:
    """Remove an idle per-program lock so the map does not grow without bound."""
    if lock.locked():
        return
    with _LOCKS_GUARD:
        if _LOCKS.get(key) is not lock or lock.locked():
            return
        _LOCKS.pop(key, None)
        if len(_LOCKS) <= _MAX_PROGRAM_LOCKS:
            return
        for other_key, other_lock in list(_LOCKS.items()):
            if len(_LOCKS) <= _MAX_PROGRAM_LOCKS:
                break
            if not other_lock.locked():
                _LOCKS.pop(other_key, None)


def _analysis_state_done(program: GhidraProgram) -> bool | None:
    try:
        st = program.getAnalysisState()
        if st is not None and hasattr(st, "isDone"):
            return bool(st.isDone())
    except Exception:
        logger.debug("Unable to read analysis state; treating as unknown", exc_info=True)
    return None


def _ghidra_utilities_pending(program: GhidraProgram) -> bool | None:
    """True when Ghidra utilities say analysis is pending; False when analyzed; None if unknown."""
    try:
        from ghidra.program.util import GhidraProgramUtilities  # pyright: ignore[reportMissingModuleSource]

        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            return True
        return not bool(GhidraProgramUtilities.isAnalyzed(program))
    except Exception:
        return None


def program_needs_analysis(program: GhidraProgram, *, force: bool = False) -> bool:
    """True when Ghidra indicates analysis should run (incremental or full)."""
    if program is None:
        return False
    if not _program_supports_analysis_observation(program):
        return False
    if force:
        return True
    state_done = _analysis_state_done(program)
    if state_done is False:
        return True
    if state_done is True:
        return False
    pending = _ghidra_utilities_pending(program)
    if pending is None:
        return True
    return pending


def _program_analysis_still_running(program: GhidraProgram) -> bool:
    state_done = _analysis_state_done(program)
    if state_done is True:
        return False
    if state_done is False:
        return True
    pending = _ghidra_utilities_pending(program)
    if pending is None:
        return state_done is not True
    return pending


def wait_for_program_analysis_idle(program: GhidraProgram, *, max_wait_sec: float = 600.0) -> None:
    """Poll Ghidra analysis state until idle or raise ProgramAnalysisTimeout."""
    if program is None or max_wait_sec <= 0 or not _program_supports_analysis_observation(program):
        return
    deadline = time.time() + max_wait_sec
    interval = _POLL_INTERVAL_MIN_SEC
    while time.time() < deadline:
        if not _program_analysis_still_running(program):
            return
        time.sleep(interval)
        interval = min(_POLL_INTERVAL_MAX_SEC, interval * _POLL_BACKOFF_FACTOR)
    if _program_analysis_still_running(program):
        raise ProgramAnalysisTimeout(f"Ghidra analysis did not finish within {max_wait_sec}s")


def mark_program_analysis_complete(program_info: ProgramInfo | None) -> None:
    if program_info is None:
        return
    program_info.ghidra_analysis_complete = True
    try:
        program_info.analysis_complete = True
    except AttributeError:
        # Some ProgramInfo implementations expose analysis_complete as a
        # read-only property derived from ghidra_analysis_complete.
        pass


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

    if program_info is not None and bool(getattr(program_info, "ghidra_analysis_complete", False)):
        if not program_needs_analysis(program, force=force):
            key = _program_lock_key(program, program_path)
            mark_program_analysis_complete(program_info)
            return {"skipped": True, "reason": "already-analyzed", "programKey": key}

    result: dict[str, Any]
    with _program_analysis_lock(program, program_path) as key:
        session_marked_done = program_info is not None and bool(
            getattr(program_info, "ghidra_analysis_complete", False)
        )
        if not (session_marked_done and not program_needs_analysis(program, force=force)):
            wait_for_program_analysis_idle(program)
        if not program_needs_analysis(program, force=force):
            mark_program_analysis_complete(program_info)
            result = {"skipped": True, "reason": "already-analyzed", "programKey": key}
        else:
            logger.info("program_analysis_start key=%s force=%s", key, force)
            _run_auto_analysis(program, force=force)
            if program_needs_analysis(program):
                raise ProgramAnalysisTimeout(
                    f"Ghidra auto-analysis did not complete for program (key={key})"
                )
            mark_program_analysis_complete(program_info)
            logger.info("program_analysis_done key=%s", key)
            result = {"ran": True, "programKey": key, "force": force}
    return result


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
    if not _program_supports_analysis_observation(program):
        mark_program_analysis_complete(program_info)
        return
    if program_info is not None and bool(getattr(program_info, "ghidra_analysis_complete", False)):
        if not program_needs_analysis(program):
            return
    with _program_analysis_lock(program, program_path) as key:
        if not program_needs_analysis(program):
            mark_program_analysis_complete(program_info)
            return
        wait_for_program_analysis_idle(program, max_wait_sec=max_wait_sec)
        if program_needs_analysis(program):
            logger.info("program_analysis_wait_ensure key=%s", key)
            _run_auto_analysis(program, force=False)
            wait_for_program_analysis_idle(program, max_wait_sec=max_wait_sec)
        if program_needs_analysis(program):
            raise ProgramAnalysisTimeout(
                f"Ghidra auto-analysis did not complete for program (key={key})"
            )
        mark_program_analysis_complete(program_info)
