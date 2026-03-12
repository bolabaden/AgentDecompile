"""Shared data collectors used by multiple tool providers.

These functions iterate over Ghidra APIs (FunctionManager, Listing, SymbolTable,
etc.) and return lists or dicts of serializable data. Used by list-functions,
manage-symbols, search-everything, manage-comments, and others to avoid duplicating
iteration and mapping logic. iter_items() normalizes Java iterators and Python
iterables to a single yield-based interface.
"""

from __future__ import annotations

import logging

from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)

_COMMENT_TYPES: tuple[tuple[str, int], ...] = (
    ("eol", 0),
    ("pre", 1),
    ("post", 2),
    ("plate", 3),
    ("repeatable", 4),
)


def iter_items(source: Any):
    if source is None:
        return
    if hasattr(source, "hasNext") and hasattr(source, "next"):
        while source.hasNext():
            yield source.next()
        return
    for item in source:
        yield item


def collect_function_comments(program: Any, func: Any) -> dict[str, str]:
    listing = program.getListing()
    address = func.getEntryPoint()
    comments: dict[str, str] = {}
    code_unit = listing.getCodeUnitAt(address)
    if code_unit is None:
        return comments
    for label, code in _COMMENT_TYPES:
        value = code_unit.getComment(code)
        if value:
            comments[label] = str(value)
    return comments


def collect_function_tags(func: Any) -> list[str]:
    values: list[str] = []
    for tag in list(func.getTags()):
        tag_name = str(tag.getName() or "")
        if tag_name:
            values.append(tag_name)
    return values


def collect_function_call_counts(func: Any) -> dict[str, int]:
    caller_count = 0
    callee_count = 0
    try:
        caller_count = len(list(func.getCallingFunctions(None)))
    except Exception:
        caller_count = 0
    try:
        callee_count = len(list(func.getCalledFunctions(None)))
    except Exception:
        callee_count = 0
    return {"callerCount": caller_count, "calleeCount": callee_count}


def collect_functions(program: Any, *, limit: int | None = None) -> list[dict[str, Any]]:
    fm = program.getFunctionManager()
    results: list[dict[str, Any]] = []
    for func in fm.getFunctions(True):
        params = []
        for p in list(func.getParameters()):
            params.append(
                {
                    "name": str(p.getName() or ""),
                    "type": str(p.getDataType() or ""),
                    "ordinal": int(p.getOrdinal()),
                },
            )

        row: dict[str, Any] = {
            "name": str(func.getName()),
            "address": str(func.getEntryPoint()),
            "signature": str(func.getSignature()),
            "size": int(func.getBody().getNumAddresses()) if func.getBody() else 0,
            "isExternal": bool(func.isExternal()),
            "isThunk": bool(func.isThunk()),
            "parameterCount": int(func.getParameterCount()),
            "parameters": params,
            "returnType": str(func.getReturnType()),
            "callingConvention": str(func.getCallingConventionName() or ""),
            "hasVarArgs": bool(func.hasVarArgs()),
            "comments": collect_function_comments(program, func),
            "tags": collect_function_tags(func),
        }
        row.update(collect_function_call_counts(func))
        results.append(row)
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_bookmarks(program: Any, *, limit: int | None = None) -> list[dict[str, Any]]:
    bm_mgr = program.getBookmarkManager()
    results: list[dict[str, Any]] = []
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


def collect_comments(program: Any, *, limit: int | None = None) -> list[dict[str, Any]]:
    listing = program.getListing()
    mem = program.getMemory()
    fm = program.getFunctionManager()
    results: list[dict[str, Any]] = []

    cu_iter = listing.getCodeUnits(mem, True)
    while cu_iter.hasNext():
        cu = cu_iter.next()
        address = cu.getAddress()
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


def collect_symbols(program: Any, *, symbol_type: Any | None = None, limit: int | None = None) -> list[dict[str, Any]]:
    st = program.getSymbolTable()
    iterator = st.getAllSymbols(True) if hasattr(st, "getAllSymbols") else st.getSymbolIterator()
    results: list[dict[str, Any]] = []
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


def collect_imports(program: Any, *, limit: int | None = None) -> list[dict[str, Any]]:
    st = program.getSymbolTable()
    results: list[dict[str, Any]] = []
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


def collect_exports(program: Any, *, limit: int | None = None) -> list[dict[str, Any]]:
    st = program.getSymbolTable()
    results: list[dict[str, Any]] = []
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


def collect_strings(program: Any, *, min_len: int = 1, limit: int | None = None, ghidra_tools: Any | None = None) -> list[dict[str, Any]]:
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
            logger.warning(f"GhidraTools.get_all_strings failed: {e}")
            # Fallback to direct iterator access below

    # Fallback 1: Try direct DefinedDataIterator access
    results: list[dict[str, Any]] = []
    try:
        from ghidra.program.util import DefinedDataIterator  # pyright: ignore[reportMissingImports,reportMissingModuleSource]

        for data in DefinedDataIterator.definedStrings(program):
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
        listing = program.getListing()
        memory = program.getMemory()

        # Iterate through all data in the program
        data_iter = listing.getDefinedData(memory, True)
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
            except Exception as item_exc:
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


def collect_data_types(program: Any, *, limit: int | None = None) -> list[dict[str, Any]]:
    dtm = program.getDataTypeManager()
    iterator = dtm.getAllDataTypes() if hasattr(dtm, "getAllDataTypes") else []
    results: list[dict[str, Any]] = []
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


def collect_data_type_archives(program: Any, *, limit: int | None = None) -> list[dict[str, Any]]:
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


def collect_structures(program: Any, *, limit: int | None = None) -> list[dict[str, Any]]:
    dtm = program.getDataTypeManager()
    results: list[dict[str, Any]] = []
    for struct in iter_items(dtm.getAllStructures()):
        results.append(
            {
                "name": str(struct.getName() or ""),
                "categoryPath": str(struct.getCategoryPath()),
                "description": str(struct.getDescription() or ""),
                "length": int(struct.getLength()),
                "numComponents": int(struct.getNumComponents()),
                "isUnion": bool(struct.isUnion()),
                "structure": struct,
            },
        )
        if limit is not None and len(results) >= limit:
            break
    return results


def collect_structure_fields(structure: Any) -> list[dict[str, Any]]:
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
    program: Any,
    *,
    value_filter: Callable[[int], bool] | None = None,
    max_instructions: int = 2_000_000,
    samples_per_constant: int = 5,
) -> tuple[list[dict[str, Any]], int]:
    listing = program.getListing()
    predicate = value_filter or (lambda _v: True)

    constants: dict[int, list[dict[str, Any]]] = {}
    instr_count = 0
    try:
        instr_iter = listing.getInstructions(True)
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
        logger.warning(f"Instruction scan error: {e}")

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
