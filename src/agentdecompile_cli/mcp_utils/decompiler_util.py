"""Shared Ghidra DecompInterface setup for MCP providers and DecompileTool."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

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


def programs_same_decompiler_context(bound: GhidraProgram | None, program: GhidraProgram | None) -> bool:
    """True when ``bound`` is the same Ghidra program as ``program`` for DecompInterface reuse."""
    logger.debug("diag.enter %s", "mcp_utils/decompiler_util.py:programs_same_decompiler_context")
    if bound is None or program is None:
        return False
    if bound is program:
        return True
    try:
        if bound == program:
            return True
    except Exception:
        pass
    try:
        df_a = bound.getDomainFile()
        df_b = program.getDomainFile()
        if df_a is not None and df_b is not None:
            return str(df_a.getPathname()) == str(df_b.getPathname())
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
            from ghidra.app.decompiler import DecompileOptions  # pyright: ignore[reportMissingModuleSource]

            try:
                options = DecompileOptions()
                options.grabFromProgram(program)
                session_decomp.setOptions(options)
            except Exception:
                pass
            return session_decomp, False
    decomp = open_decompiler_for_program(program)
    return decomp, True


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
    decomp = DecompInterface()
    decomp.setOptions(prog_options)
    decomp.openProgram(program)
    return decomp
