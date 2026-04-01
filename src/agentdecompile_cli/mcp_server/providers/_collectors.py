"""Shared data collectors used by multiple tool providers.

These functions iterate over Ghidra APIs (FunctionManager, Listing, SymbolTable,
etc.) and return lists or dicts of serializable data. Used by list-functions,
manage-symbols, search-everything, manage-comments, and others to avoid duplicating
iteration and mapping logic. iter_items() normalizes Java iterators and Python
iterables to a single yield-based interface.
"""

from __future__ import annotations

import logging

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        DecompInterface as GhidraDecompInterface,
        DecompileResults as GhidraDecompileResults,
        DecompiledFunction as GhidraDecompiledFunction,
    )
    from ghidra.program.model.address import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        Address as GhidraAddress,
        AddressSet as GhidraAddressSet,
        AddressSetView as GhidraAddressSetView,
    )
    from ghidra.program.model.data import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        DataType as GhidraDataType,
        DataTypeManager as GhidraDataTypeManager,
        StringDataInstance as GhidraStringDataInstance,
        Structure as GhidraStructure,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        Bookmark as GhidraBookmark,
        BookmarkManager as GhidraBookmarkManager,
        CodeUnit as GhidraCodeUnit,
        CodeUnitIterator as GhidraCodeUnitIterator,
        Data as GhidraData,
        DataIterator as GhidraDataIterator,
        Function as GhidraFunction,
        FunctionIterator as GhidraFunctionIterator,
        FunctionManager as GhidraFunctionManager,
        FunctionTag as GhidraFunctionTag,
        InstructionIterator as GhidraInstructionIterator,
        Listing as GhidraListing,
        Program as GhidraProgram,
        Variable as GhidraVariable,
    )
    from ghidra.program.model.mem import Memory as GhidraMemory  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    from ghidra.program.model.symbol import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        Symbol as GhidraSymbol,
        SymbolIterator as GhidraSymbolIterator,
        SymbolTable as GhidraSymbolTable,
        SymbolType as GhidraSymbolType,
    )
    from ghidra.program.util import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]  # noqa: F401
        DefinedDataIterator as GhidraDefinedDataIterator,
        ProgramMemoryUtil as GhidraProgramMemoryUtil,  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
    )

logger = logging.getLogger(__name__)

# Ghidra CodeUnit comment type (name, code): eol=end-of-line, pre/post=block, plate=header, repeatable=ref
_COMMENT_TYPES: tuple[tuple[str, int], ...] = (
    ("eol", 0),
    ("pre", 1),
    ("post", 2),
    ("plate", 3),
    ("repeatable", 4),
)


def iter_items(source: Any) -> Any:
    """Yield items from a Java iterator (hasNext/next) or Python iterable so providers can use one loop style."""
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:iter_items")
    if source is None:
        return
    if hasattr(source, "hasNext") and hasattr(source, "next"):
        while source.hasNext():
            yield source.next()
        return
    for item in source:
        yield item


def collect_function_comments(program: GhidraProgram, func: GhidraFunction) -> dict[str, str]:
    """Collect all comment types (eol, pre, post, plate, repeatable) at the function's entry point."""
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_function_comments")
    listing: GhidraListing = program.getListing()
    address: GhidraAddress = func.getEntryPoint()
    comments: dict[str, str] = {}
    code_unit: GhidraCodeUnit = listing.getCodeUnitAt(address)
    if code_unit is None:
        return comments
    for label, code in _COMMENT_TYPES:
        value = code_unit.getComment(code)
        if value:
            comments[label] = str(value)
    return comments


def collect_function_tags(func: GhidraFunction) -> list[str]:
    """Return list of tag names attached to this function (e.g. crypto, network)."""
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_function_tags")
    values: list[str] = []
    tag: GhidraFunctionTag
    for tag in list(func.getTags()):
        tag_name = str(tag.getName() or "")
        if tag_name:
            values.append(tag_name)
    return values


def make_task_monitor() -> Any:
    """Return a no-op TaskMonitor for Ghidra API calls that require a non-null monitor.

    getCallingFunctions(None) and getCalledFunctions(None) return empty sets in
    Ghidra < 12.0.3 because null was not supported until that release.  Always
    passing a real (non-null) monitor fixes the behaviour across all versions.

    Fallback chain (tried in order):
    1. TaskMonitor.DUMMY          — Ghidra 12.x and most v11 builds
    2. TaskMonitorAdapter.DUMMY_MONITOR — older Ghidra internal adapters (v11/jHidra)
    3. ConsoleTaskMonitor()       — available in almost all released Ghidra versions
    4. None                       — non-Ghidra environments (unit tests only)
    """
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:make_task_monitor")
    # 1. Preferred: TaskMonitor.DUMMY (Ghidra 12.x, most Ghidra 11.x builds)
    try:
        from ghidra.util.task import TaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        dummy = getattr(TaskMonitor, "DUMMY", None)
        if dummy is not None:
            return dummy
    except Exception:
        pass
    # 2. Fallback: TaskMonitorAdapter.DUMMY_MONITOR (some older Ghidra/jHidra variants)
    try:
        from ghidra.util.task import TaskMonitorAdapter  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        dummy = getattr(TaskMonitorAdapter, "DUMMY_MONITOR", None)
        if dummy is not None:
            return dummy
    except Exception:
        pass
    # 3. Fallback: construct a ConsoleTaskMonitor (available in virtually all versions)
    try:
        from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        return ConsoleTaskMonitor()
    except Exception:
        pass
    # 4. Last resort: None — only reached in non-Ghidra test environments
    return None


def collect_function_call_counts(func: GhidraFunction) -> dict[str, int]:
    """Return callerCount and calleeCount for a function (number of callers and called functions)."""
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_function_call_counts")
    monitor = make_task_monitor()
    caller_count: int = 0
    callee_count: int = 0
    try:
        caller_count = len(list(func.getCallingFunctions(monitor)))
    except Exception:
        caller_count = 0
    try:
        callee_count = len(list(func.getCalledFunctions(monitor)))
    except Exception:
        callee_count = 0
    return {"callerCount": caller_count, "calleeCount": callee_count}


def _get_function_list(fm: GhidraFunctionManager) -> list[GhidraFunction]:
    """Return a list of functions from FunctionManager; try multiple strategies for PyGhidra/JPype iterator quirks."""
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:_get_function_list")
    count: int = fm.getFunctionCount() if hasattr(fm, "getFunctionCount") else 0
    out: list[GhidraFunction] = []

    # Strategy 1: direct Python for-loop (works when Java iterable implements __iter__)
    try:
        for f in fm.getFunctions(True):
            out.append(f)
        if out:
            return out
    except Exception:
        pass
    # Strategy 2: iter_items (hasNext/next) for Java Iterator
    try:
        it: GhidraFunctionIterator = fm.getFunctions(True)
        out = list(iter_items(it))
        if out:
            return out
    except Exception:
        pass

    if count > 0:
        # Strategy 2b: consume iterator on Java side via ArrayList (PyGhidra/JPype often break on Java iterators in Python)
        try:
            from java.util import ArrayList as JavaArrayList  # noqa: PLC0415  # type: ignore[reportMissingImports]

            it = fm.getFunctions(True)
            arr = JavaArrayList()
            while it.hasNext():
                arr.add(it.next())
            out = [arr.get(i) for i in range(arr.size())]
            if out:
                logger.debug("_get_function_list: collected %d functions via Java ArrayList", len(out))
                return out
        except Exception as e:
            logger.debug("_get_function_list: ArrayList fallback failed: %s", e)

        # Strategy 2c: getFunctions(AddressSetView, forward) over full memory (sometimes different iterator impl)
        try:
            program: GhidraProgram = fm.getProgram() if hasattr(fm, "getProgram") else None
            if program is not None and hasattr(program, "getMemory"):
                mem: GhidraProgramMemoryUtil = program.getMemory()
                if hasattr(mem, "getAddressSet"):
                    addr_set: GhidraAddressSet = mem.getAddressSet()
                    if addr_set is not None:
                        it = fm.getFunctions(addr_set, True)
                        out = list(iter_items(it))
                        if not out:
                            from java.util import ArrayList as JavaArrayList  # noqa: PLC0415  # type: ignore[reportMissingImports]

                            it2 = fm.getFunctions(addr_set, True)
                            arr = JavaArrayList()
                            while it2.hasNext():
                                arr.add(it2.next())
                            out = [arr.get(i) for i in range(arr.size())]
                        if out:
                            logger.debug("_get_function_list: collected %d functions via getFunctions(AddressSet)", len(out))
                            return out
        except Exception as e:
            logger.debug("_get_function_list: getFunctions(AddressSet) failed: %s", e)

        try:
            out = []
            for f in fm.getFunctions(False):
                out.append(f)
            if out:
                return out
        except Exception:
            pass
        try:
            out = list(iter_items(fm.getFunctions(False)))
            if out:
                return out
        except Exception:
            pass
        try:
            raw = list(fm.getFunctions(True))
            if raw:
                return raw
        except Exception:
            pass

        # Strategy 3: getFunctionAt/getFunctionAfter walk when iterators fail (e.g. PyGhidra/JPype)
        try:
            program: GhidraProgram = fm.getProgram() if hasattr(fm, "getProgram") else None
            if program is not None and hasattr(program, "getMemory") and hasattr(fm, "getFunctionAfter"):
                mem = program.getMemory()
                min_addr = mem.getMinAddress() if hasattr(mem, "getMinAddress") else None
                if min_addr is not None:
                    out = []
                    func: GhidraFunction | None = fm.getFunctionAt(min_addr) if hasattr(fm, "getFunctionAt") else None
                    if func is None:
                        func = fm.getFunctionAfter(min_addr)
                    max_iters = count + 1000 if count else 10000
                    while func is not None and len(out) < max_iters:
                        out.append(func)
                        entry = func.getEntryPoint() if hasattr(func, "getEntryPoint") else None
                        if entry is None:
                            break
                        func = fm.getFunctionAfter(entry)
                    if out:
                        logger.debug("_get_function_list: collected %d functions via getFunctionAfter walk", len(out))
                        return out
        except Exception as e:
            logger.debug("_get_function_list: getFunctionAfter fallback failed: %s", e)

        if count > 0:
            logger.warning("_get_function_list: functionCount=%d but all strategies returned empty list", count)
    return []


def collect_functions(program: GhidraProgram, *, limit: int | None = None) -> list[dict[str, Any]]:
    """Single pass over all functions: name, address, signature, params, comments, tags, caller/callee counts. Used by list-functions and others."""
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_functions")
    fm: GhidraFunctionManager = program.getFunctionManager()
    results: list[dict[str, Any]] = []
    func_list: list[GhidraFunction] = _get_function_list(fm)

    for func in func_list:
        if not hasattr(func, "getName"):
            continue
        params: list[dict[str, Any]] = []
        for p in list(func.getParameters() if hasattr(func, "getParameters") else []):  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            params.append(
                {
                    "name": str(p.getName() or ""),
                    "type": str(p.getDataType() or ""),
                    "ordinal": int(p.getOrdinal()),
                },
            )

        row: dict[str, Any] = {
            "name": str(func.getName()),  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "address": str(func.getEntryPoint()),  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "signature": str(func.getSignature()),  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "size": int(func.getBody().getNumAddresses()) if func.getBody() else 0,  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "isExternal": bool(func.isExternal()),  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "isThunk": bool(func.isThunk()),  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "parameterCount": int(func.getParameterCount()),  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "parameters": params,
            "returnType": str(func.getReturnType()),  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "callingConvention": str(func.getCallingConventionName() or ""),  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "hasVarArgs": bool(func.hasVarArgs()),  # pyright: ignore[reportAttributeAccessIssue, reportOptionalMemberAccess]
            "comments": collect_function_comments(program, func),
            "tags": collect_function_tags(func),
        }
        row.update(collect_function_call_counts(func))
        results.append(row)
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_bookmarks(program: GhidraProgram, *, limit: int | None = None) -> list[dict[str, Any]]:
    """Single pass over bookmarks: address, type, category, comment. Used by manage-bookmarks list/search."""
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_bookmarks")
    bm_mgr: GhidraBookmarkManager = program.getBookmarkManager()
    results: list[dict[str, Any]] = []
    bm: GhidraBookmark
    for bm in iter_items(bm_mgr.getBookmarksIterator()):
        results.append(
            {
                "address": str(bm.getAddress()),
                "type": str(bm.getTypeString()),
                "category": str(bm.getCategory()),
                "comment": str(bm.getComment() or ""),
            },
        )
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_comments(program: GhidraProgram, *, limit: int | None = None) -> list[dict[str, Any]]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_comments")
    listing: GhidraListing = program.getListing()
    mem: GhidraMemory = program.getMemory()
    fm: GhidraFunctionManager = program.getFunctionManager()
    results: list[dict[str, Any]] = []

    cu_iter: GhidraCodeUnitIterator = listing.getCodeUnits(mem, True)
    while cu_iter.hasNext():
        cu: GhidraCodeUnit = cu_iter.next()
        address: GhidraAddress = cu.getAddress()
        container = fm.getFunctionContaining(address)
        function_name = str(container.getName()) if container else ""
        function_address = str(container.getEntryPoint()) if container else ""
        for comment_type, code in _COMMENT_TYPES:
            comment_text = cu.getComment(code)
            if not comment_text:
                continue
            results.append(
                {
                    "address": str(address),
                    "commentType": comment_type,
                    "comment": str(comment_text),
                    "function": function_name,
                    "functionAddress": function_address,
                },
            )
            if limit is not None and len(results) >= limit:
                return results
    return results


def collect_symbols(
    program: GhidraProgram,
    *,
    symbol_type: GhidraSymbolType | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_symbols")
    st: GhidraSymbolTable = program.getSymbolTable()
    iterator: GhidraSymbolIterator = st.getAllSymbols(True) if hasattr(st, "getAllSymbols") else st.getSymbolIterator()
    results: list[dict[str, Any]] = []
    sym: GhidraSymbol
    for sym in iter_items(iterator):
        if symbol_type is not None and sym.getSymbolType() != symbol_type:
            continue
        results.append(
            {
                "name": str(sym.getName()),
                "address": str(sym.getAddress()),
                "symbolType": str(sym.getSymbolType()),
                "namespace": str(sym.getParentNamespace()),
                "source": str(sym.getSource()),
                "isPrimary": bool(sym.isPrimary()) if hasattr(sym, "isPrimary") else False,
                "isExternalEntryPoint": bool(sym.isExternalEntryPoint()) if hasattr(sym, "isExternalEntryPoint") else False,
            },
        )
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_imports(program: GhidraProgram, *, limit: int | None = None) -> list[dict[str, Any]]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_imports")
    st: GhidraSymbolTable = program.getSymbolTable()
    results: list[dict[str, Any]] = []
    sym: GhidraSymbol
    for sym in iter_items(st.getExternalSymbols() if hasattr(st, "getExternalSymbols") else []):
        results.append(
            {
                "name": str(sym.getName()),
                "address": str(sym.getAddress()),
                "namespace": str(sym.getParentNamespace()),
                "library": str(sym.getParentNamespace()),
            },
        )
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_exports(
    program: GhidraProgram,
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_exports")
    st: GhidraSymbolTable = program.getSymbolTable()
    results: list[dict[str, Any]] = []
    sym: GhidraSymbol
    for sym in iter_items(st.getAllSymbols(True) if hasattr(st, "getAllSymbols") else []):
        if not sym.isExternalEntryPoint():
            continue
        results.append(
            {
                "name": str(sym.getName()),
                "address": str(sym.getAddress()),
                "namespace": str(sym.getParentNamespace()),
            },
        )
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_strings(
    program: GhidraProgram,
    *,
    min_len: int = 1,
    limit: int | None = None,
    ghidra_tools: Any | None = None,
) -> list[dict[str, Any]]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_strings")
    if ghidra_tools is not None:
        try:
            result = ghidra_tools.get_all_strings()
            if isinstance(result, list):
                normalized: list[dict[str, Any]] = []
                for item in result:
                    if isinstance(item, dict):
                        value = str(item.get("value", ""))
                        if len(value) < min_len:
                            continue
                        normalized.append(
                            {
                                "address": str(item.get("address", "")),
                                "value": value,
                                "length": int(item.get("length", len(value))),
                                "dataType": str(item.get("dataType", "")),
                            },
                        )
                    else:
                        value = str(getattr(item, "value", ""))
                        if len(value) < min_len:
                            continue
                        normalized.append(
                            {
                                "address": str(getattr(item, "address", "")),
                                "value": value,
                                "length": len(value),
                                "dataType": str(getattr(item, "dataType", "")),
                            },
                        )
                if limit is None:
                    return normalized
                return normalized[:limit]
        except Exception as e:
            logger.warning("GhidraTools.get_all_strings failed: %s", e)
            # Fallback to direct iterator access below

    # Fallback 1: Try direct DefinedDataIterator access
    results: list[dict[str, Any]] = []
    try:
        from ghidra.program.util import DefinedDataIterator as GhidraDefinedDataIterator  # pyright: ignore[reportMissingImports,reportMissingModuleSource]

        data: GhidraData
        for data in GhidraDefinedDataIterator.definedStrings(program):
            value = str(data.getValue() or "")
            if len(value) < min_len:
                continue
            results.append(
                {
                    "address": str(data.getAddress()),
                    "value": value,
                    "length": len(value),
                    "dataType": str(data.getDataType()),
                },
            )
            if limit is not None and len(results) >= limit:
                break
        return results
    except Exception as e:
        logger.warning(f"String iteration via DefinedDataIterator failed: {e.__class__.__name__}: {e}")

    # Fallback 2: Listing-based traversal for environments where iterators are unavailable
    # This provides coverage for shared-server/proxy contexts
    try:
        listing: GhidraListing = program.getListing()
        memory: GhidraMemory = program.getMemory()

        # Iterate through all data in the program
        data_iter: GhidraDataIterator = listing.getDefinedData(memory, True)
        while data_iter.hasNext() if hasattr(data_iter, "hasNext") else len(results) < (limit or 10000):
            if not hasattr(data_iter, "hasNext"):
                break
            try:
                data = data_iter.next()
                data_type = data.getDataType()
                # Check if it's a string-like type
                if data_type and hasattr(data_type, "getName"):
                    type_name = str(data_type.getName()).lower()
                    if "string" in type_name or "unicode" in type_name:
                        value = str(data.getValue() or "")
                        if len(value) >= min_len:
                            results.append(
                                {
                                    "address": str(data.getAddress()),
                                    "value": value,
                                    "length": len(value),
                                    "dataType": str(data_type),
                                },
                            )
                            if limit is not None and len(results) >= limit:
                                break
            except Exception:
                # Skip individual items that fail
                continue

        if results:
            logger.info(f"String collection via listing-based fallback found {len(results)} strings")
            return results
    except Exception as e:
        logger.warning(f"Listing-based string fallback failed: {e.__class__.__name__}: {e}")

    # If all fallback paths failed and we have no results, log a clear diagnostic
    if not results:
        logger.error(
            "All string collection methods failed. This program context may not support string enumeration (e.g., shared-server checkout without iterator support).",
        )

    return results


def collect_data_types(program: GhidraProgram, *, limit: int | None = None) -> list[dict[str, Any]]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_data_types")
    dtm = program.getDataTypeManager()
    iterator = dtm.getAllDataTypes() if hasattr(dtm, "getAllDataTypes") else []
    results: list[dict[str, Any]] = []
    dt: GhidraDataType
    for dt in iter_items(iterator):
        results.append(
            {
                "name": str(dt.getName() or ""),
                "displayName": str(dt.getDisplayName() or ""),
                "categoryPath": str(dt.getCategoryPath()),
                "description": str(dt.getDescription() or ""),
                "length": int(dt.getLength()) if hasattr(dt, "getLength") else 0,
            },
        )
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_data_type_archives(program: GhidraProgram, *, limit: int | None = None) -> list[dict[str, Any]]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_data_type_archives")
    dtm = program.getDataTypeManager()
    results: list[dict[str, Any]] = []
    try:
        program_archive = dtm.getLocalSourceArchive()
        if program_archive is not None:
            results.append(
                {
                    "name": str(program_archive.getName()),
                    "type": "program",
                    "id": str(program_archive.getSourceArchiveID()),
                    "categoryCount": int(dtm.getCategoryCount()),
                    "dataTypeCount": int(dtm.getDataTypeCount(True)),
                },
            )
    except Exception:
        pass

    archive: GhidraDataTypeManager
    for archive in iter_items(dtm.getSourceArchives() if hasattr(dtm, "getSourceArchives") else []):
        results.append(
            {
                "name": str(archive.getName() or ""),
                "type": "source",
                "id": str(archive.getSourceArchiveID()),
            },
        )
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_structures(program: GhidraProgram, *, limit: int | None = None) -> list[dict[str, Any]]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_structures")
    dtm: GhidraDataTypeManager = program.getDataTypeManager()
    results: list[dict[str, Any]] = []
    struct: GhidraStructure
    for struct in iter_items(dtm.getAllStructures()):
        results.append(
            {
                "name": str(struct.getName() or ""),
                "categoryPath": str(struct.getCategoryPath()),
                "description": str(struct.getDescription() or ""),
                "length": int(struct.getLength()),
                "numComponents": int(struct.getNumComponents()),
                "isUnion": bool(struct.isUnion()) if hasattr(struct, "isUnion") else False,
                "structure": struct,
            },
        )
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_structure_fields(structure: GhidraStructure) -> list[dict[str, Any]]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_structure_fields")
    fields: list[dict[str, Any]] = []
    for index in range(structure.getNumComponents()):
        component = structure.getComponent(index)
        fields.append(
            {
                "offset": int(component.getOffset()),
                "name": str(component.getFieldName() or ""),
                "type": str(component.getDataType() or ""),
                "length": int(component.getLength()) if hasattr(component, "getLength") else 0,
                "comment": str(component.getComment() or ""),
            },
        )
    return fields


def collect_constants(
    program: GhidraProgram,
    *,
    value_filter: Callable[[int], bool] | None = None,
    max_instructions: int = 2_000_000,
    samples_per_constant: int = 5,
) -> tuple[list[dict[str, Any]], int]:
    logger.debug("diag.enter %s", "mcp_server/providers/_collectors.py:collect_constants")
    listing: GhidraListing = program.getListing()
    predicate: Callable[[int], bool] = value_filter or (lambda _v: True)

    constants: dict[int, list[dict[str, Any]]] = {}
    instr_count = 0
    try:
        instr_iter: GhidraInstructionIterator = listing.getInstructions(True)
        while instr_iter.hasNext() and instr_count < max_instructions:
            instr = instr_iter.next()
            instr_count += 1
            num_ops = instr.getNumOperands()
            for i in range(num_ops):
                for obj in instr.getOpObjects(i):
                    try:
                        scalar_val = obj.getValue() if hasattr(obj, "getValue") else None
                        if scalar_val is None:
                            continue
                        val = int(scalar_val)
                        if val == 0 or not predicate(val):
                            continue
                        if val not in constants:
                            constants[val] = []
                        if len(constants[val]) < samples_per_constant:
                            constants[val].append(
                                {
                                    "address": str(instr.getAddress()),
                                    "instruction": str(instr),
                                },
                            )
                    except Exception:
                        continue
    except Exception as e:
        logger.warning("Instruction scan error: %s", e)

    sorted_vals = sorted(constants.keys(), key=lambda v: len(constants[v]), reverse=True)
    all_results: list[dict[str, Any]] = []
    for val in sorted_vals:
        all_results.append(
            {
                "value": val,
                "hex": hex(val),
                "occurrences": len(constants[val]),
                "samples": constants[val],
            },
        )

    return all_results, instr_count
