"""Inventory programs: format, architecture, compiler spec, function-name sources.

Named ``program_inventory`` because recovery already owns ``inventory.py``.
"""

from __future__ import annotations

import json
from pathlib import Path


def summarize(program) -> dict:
    from ghidra.program.model.symbol import SourceType

    lang = program.getLanguage()
    ldesc = lang.getLanguageDescription()
    mem = program.getMemory()

    fm = program.getFunctionManager()
    counts = {
        "total": 0,
        "external": 0,
        "thunk": 0,
        "default_named": 0,
        "user_named": 0,
        "imported_named": 0,
        "analysis_named": 0,
        "with_namespace": 0,
        "with_custom_sig": 0,
        "with_plate_comment": 0,
    }
    by_source: dict[str, int] = {}
    for func in fm.getFunctions(True):
        counts["total"] += 1
        if func.isExternal():
            counts["external"] += 1
        if func.isThunk():
            counts["thunk"] += 1
        sym = func.getSymbol()
        st = str(sym.getSource()) if sym is not None else "NONE"
        by_source[st] = by_source.get(st, 0) + 1
        name = str(func.getName())
        if name.startswith(("FUN_", "thunk_FUN_", "SUB_", "UndefinedFunction_")):
            counts["default_named"] += 1
        if sym is not None:
            if sym.getSource() == SourceType.USER_DEFINED:
                counts["user_named"] += 1
            elif sym.getSource() == SourceType.IMPORTED:
                counts["imported_named"] += 1
            elif sym.getSource() == SourceType.ANALYSIS:
                counts["analysis_named"] += 1
        ns = func.getParentNamespace()
        if ns is not None and not ns.isGlobal():
            counts["with_namespace"] += 1
        if func.hasCustomVariableStorage() or func.getSignatureSource() == SourceType.USER_DEFINED:
            counts["with_custom_sig"] += 1
        if func.getComment():
            counts["with_plate_comment"] += 1

    st = program.getSymbolTable()
    dtm = program.getDataTypeManager()
    blocks = []
    for block in mem.getBlocks():
        blocks.append(
            {
                "name": str(block.getName()),
                "start": f"0x{block.getStart().getOffset():x}",
                "size": int(block.getSize()),
                "x": bool(block.isExecute()),
                "init": bool(block.isInitialized()),
            }
        )

    props = {}
    opts = program.getOptions("Program Information")
    for key in opts.getOptionNames():
        try:
            props[str(key)] = str(opts.getValueAsString(key))
        except Exception:
            pass

    return {
        "name": str(program.getName()),
        "language_id": str(ldesc.getLanguageID()),
        "processor": str(ldesc.getProcessor()),
        "endian": str(ldesc.getEndian()),
        "size_bits": int(ldesc.getSize()),
        "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID()),
        "executable_format": str(program.getExecutableFormat()),
        "executable_path": str(program.getExecutablePath()),
        "executable_md5": str(program.getExecutableMD5()),
        "image_base": f"0x{program.getImageBase().getOffset():x}",
        "min_addr": f"0x{mem.getMinAddress().getOffset():x}" if mem.getMinAddress() else None,
        "max_addr": f"0x{mem.getMaxAddress().getOffset():x}" if mem.getMaxAddress() else None,
        "functions": counts,
        "function_symbol_sources": by_source,
        "symbols_total": int(st.getNumSymbols()),
        "datatypes": int(dtm.getDataTypeCount(True)),
        "blocks": blocks,
        "program_info": props,
    }


def write_inventory(results: list[dict], dest: Path | str) -> Path:
    path = Path(dest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, indent=1), encoding="utf-8")
    return path


def inventory_programs(records: list[dict], dest: Path | str, *, open_program=None) -> list[dict]:
    """Inventory caller-supplied programs. *dest* is required. Skips when no opener/program."""
    results = []
    for rec in records:
        path = rec["path"]
        info: dict = {"repo_path": path, "repo_version": rec.get("version")}
        if open_program is None:
            info["skipped"] = "no-program"
            results.append(info)
            continue
        try:
            with open_program(path) as prog:
                if prog is None:
                    info["skipped"] = "no-program"
                else:
                    info.update(summarize(prog))
        except Exception as exc:
            info["error"] = str(exc)
        results.append(info)
    write_inventory(results, dest)
    return results
