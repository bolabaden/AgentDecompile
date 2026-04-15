"""Shared Ghidra DecompInterface setup for MCP providers and DecompileTool."""

from __future__ import annotations

from dataclasses import dataclass
import logging
from threading import Lock, RLock
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompInterface as GhidraDecompInterface,
        DecompiledFunction as GhidraDecompiledFunction,
        DecompileResults as GhidraDecompileResults,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Program as GhidraProgram,
    )

logger = logging.getLogger(__name__)

_DECOMPILER_LOCKS_GUARD = Lock()
_DECOMPILER_LOCKS: dict[int, RLock] = {}


def _dispose_decompiler_quietly(decompiler: GhidraDecompInterface) -> None:
    try:
        decompiler.dispose()
    except Exception:
        pass


def _describe_program(program: GhidraProgram) -> str:
    try:
        domain_file = program.getDomainFile()
        if domain_file is not None:
            pathname = domain_file.getPathname()
            if pathname:
                return str(pathname)
    except Exception:
        pass
    try:
        name = program.getName()
        if name:
            return str(name)
    except Exception:
        pass
    return "unknown"


def _extract_decompiler_open_detail(decompiler: GhidraDecompInterface, exc: Exception | None = None) -> str:
    parts: list[str] = []
    if exc is not None:
        parts.append(f"{exc.__class__.__name__}: {exc}")
    try:
        message = decompiler.getLastMessage() or ""
    except Exception:
        message = ""
    if message:
        parts.append(str(message))
    return "; ".join(part for part in parts if part) or "no error message from DecompInterface"


def _try_open_configured_decompiler(decompiler: GhidraDecompInterface, program: GhidraProgram) -> str | None:
    try:
        if decompiler.openProgram(program):
            return None
        return _extract_decompiler_open_detail(decompiler)
    except Exception as exc:
        return _extract_decompiler_open_detail(decompiler, exc)


@dataclass
class DecompilerLease:
    """Tracks a borrowed decompiler interface and how it should be released."""

    decompiler: GhidraDecompInterface
    owns_dispose: bool
    reused_session: bool
    _release: Callable[[], None] | None = None

    def close(self) -> None:
        """Dispose or unlock the leased interface."""
        dispose_error: Exception | None = None
        try:
            if self.owns_dispose:
                self.decompiler.dispose()
        except Exception as exc:
            dispose_error = exc
        finally:
            release = self._release
            self._release = None
            if release is not None:
                release()
        if dispose_error is not None:
            raise dispose_error

    def __enter__(self) -> DecompilerLease:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


def _get_decompiler_lock(decompiler: GhidraDecompInterface) -> RLock:
    key = id(decompiler)
    with _DECOMPILER_LOCKS_GUARD:
        lock = _DECOMPILER_LOCKS.get(key)
        if lock is None:
            lock = RLock()
            _DECOMPILER_LOCKS[key] = lock
        return lock


def _configure_decompiler_for_program(decompiler: GhidraDecompInterface, program: GhidraProgram) -> None:
    from ghidra.app.decompiler import DecompileOptions  # pyright: ignore[reportMissingModuleSource]

    prog_options = DecompileOptions()
    prog_options.grabFromProgram(program)
    prog_options.setMaxPayloadMBytes(100)
    decompiler.setOptions(prog_options)


def programs_same_decompiler_context(bound: GhidraProgram | None, program: GhidraProgram | None) -> bool:
    """True when ``bound`` is the same Ghidra program as ``program`` for DecompInterface reuse."""
    logger.debug("diag.enter %s", "mcp_utils/decompiler_util.py:programs_same_decompiler_context")
    if bound is None or program is None:
        return False
    if bound is program:
        return True
    try:
        return bool(bound == program)
    except Exception:
        pass
    return False


def resolve_decompiler_for_program(session_decomp: GhidraDecompInterface | None, program: GhidraProgram) -> tuple[GhidraDecompInterface, bool]:
    """Return ``(DecompInterface, owns_dispose)``.

    Reuses ``session_decomp`` only when it is already opened on ``program``.
    Otherwise opens a new interface; caller must ``dispose()`` when ``owns_dispose`` is True.
    """
    logger.debug("diag.enter %s", "mcp_utils/decompiler_util.py:resolve_decompiler_for_program")
    if session_decomp is not None:
        try:
            bound = session_decomp.getProgram()
        except Exception:
            bound = None
        if programs_same_decompiler_context(bound, program):
            try:
                _configure_decompiler_for_program(session_decomp, program)
            except Exception:
                pass
            return session_decomp, False
    decomp = open_decompiler_for_program(program)
    return decomp, True


def acquire_decompiler_for_program(session_decomp: GhidraDecompInterface | None, program: GhidraProgram) -> DecompilerLease:
    """Return a leased decompiler for ``program``.

    Shared session decompilers are serialized with a re-entrant lock so concurrent
    requests do not race the same native DecompInterface. When the session
    decompiler is not already bound to the exact ``Program`` object, a fresh
    ephemeral interface is opened instead.
    """
    logger.debug("diag.enter %s", "mcp_utils/decompiler_util.py:acquire_decompiler_for_program")
    if session_decomp is not None:
        lock = _get_decompiler_lock(session_decomp)
        lock.acquire()
        try:
            try:
                bound = session_decomp.getProgram()
            except Exception:
                bound = None
            if programs_same_decompiler_context(bound, program):
                try:
                    _configure_decompiler_for_program(session_decomp, program)
                except Exception:
                    pass
                return DecompilerLease(
                    decompiler=session_decomp,
                    owns_dispose=False,
                    reused_session=True,
                    _release=lock.release,
                )
        except Exception:
            lock.release()
            raise
        lock.release()

    return DecompilerLease(
        decompiler=open_decompiler_for_program(program),
        owns_dispose=True,
        reused_session=False,
    )


def get_decompiled_function_from_results(decompile_results: GhidraDecompileResults | None) -> GhidraDecompiledFunction | None:
    """Return Ghidra ``DecompiledFunction`` from ``DecompileResults`` (JPype/PyGhidra-safe).

    Prefer ``getDecompiledFunction()``; fall back to ``decompiledFunction`` when the
    property is populated but the method returns null (seen with some bindings).
    """
    logger.debug("diag.enter %s", "mcp_utils/decompiler_util.py:get_decompiled_function_from_results")
    if decompile_results is None:
        return None
    try:
        getter = getattr(decompile_results, "getDecompiledFunction", None)
        if callable(getter):
            df = getter()
            if df is not None:
                return df
    except Exception:
        logger.debug("getDecompiledFunction_failed", exc_info=True)
    try:
        return getattr(decompile_results, "decompiledFunction", None)
    except Exception:
        return None


def merge_decompile_dict_keys(data: dict[str, Any]) -> dict[str, Any]:
    """Ensure ``code`` and ``decompilation`` both carry pseudocode when either is set.

    Tool payloads use mixed keys (Pydantic ``code`` vs API ``decompilation``); this
    keeps JSON and markdown renderers consistent.
    """
    logger.debug("diag.enter %s", "mcp_utils/decompiler_util.py:merge_decompile_dict_keys")
    out = dict(data)
    c_raw = out.get("code")
    d_raw = out.get("decompilation")
    sc = c_raw if isinstance(c_raw, str) else ""
    sd = d_raw if isinstance(d_raw, str) else ""
    text = sc.strip() or sd.strip()
    if text:
        out["code"] = sc.strip() or text
        out["decompilation"] = sd.strip() or text
    return out


def open_decompiler_for_program(program: GhidraProgram) -> GhidraDecompInterface:
    """Create a DecompInterface opened on ``program`` with options from the program (matches launcher/setup_decompiler)."""
    from ghidra.app.decompiler import DecompInterface, DecompileOptions  # pyright: ignore[reportMissingModuleSource]

    prog_options = DecompileOptions()
    prog_options.grabFromProgram(program)
    prog_options.setMaxPayloadMBytes(100)
    last_detail = "no error message from DecompInterface"
    program_name = _describe_program(program)

    for attempt in range(2):
        decomp = DecompInterface()
        decomp.setOptions(prog_options)
        detail = _try_open_configured_decompiler(decomp, program)
        if detail is None:
            if attempt > 0:
                logger.warning(
                    "decompiler_open_program_recovered program=%s attempt=%s",
                    program_name,
                    attempt + 1,
                )
            return decomp

        last_detail = detail
        logger.warning(
            "decompiler_open_program_failed program=%s attempt=%s detail=%s",
            program_name,
            attempt + 1,
            detail,
        )
        _dispose_decompiler_quietly(decomp)

    raise RuntimeError(f"Failed to open DecompInterface for program: {last_detail}")
