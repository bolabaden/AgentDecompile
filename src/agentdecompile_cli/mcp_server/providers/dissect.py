"""Dissect Function Tool Provider – dissect-function.

All-in-one deep inspection of a single function. Returns decompilation,
disassembly, comments, labels, callers, callees, cross-references, tags,
bookmarks, stack frame / local variables, namespace, and memory block info
in a single MCP tool call.
"""

from __future__ import annotations

import logging

from typing import Any, ClassVar

from mcp import types

from agentdecompile_cli.mcp_server.providers._collectors import (
    collect_function_comments,
    collect_function_tags,
)
from agentdecompile_cli.registry import ToolName
from agentdecompile_cli.mcp_server.tool_providers import (
    DEFAULT_TIMEOUT_SECONDS,
    ToolProvider,
    create_success_response,
)

logger = logging.getLogger(__name__)


class DissectFunctionToolProvider(ToolProvider):
    """AIO provider that returns everything knowable about a single function."""

    HANDLERS: ClassVar[dict[str, str]] = {
        "dissectfunction": "_handle",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name=ToolName.DISSECT_FUNCTION.value,
                description=(
                    "Deep, all-in-one inspection of a single function. "
                    "Returns every available detail in one call: decompiled C code, "
                    "disassembly with raw bytes, all comment types (EOL/pre/post/plate/repeatable), "
                    "labels and symbols inside the function body, callers (who calls it), "
                    "callees (what it calls), inbound cross-references, function tags, "
                    "bookmarks, stack frame with local variables, namespace path, "
                    "and the memory block the function resides in. "
                    "Use this instead of chaining multiple tools when you need a complete "
                    "picture of what a function is, does, and how it connects to the rest "
                    "of the binary."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {
                            "type": "string",
                            "description": "Path to the program in the project.",
                        },
                        "function": {
                            "type": "string",
                            "description": "Name or hex address of the function to dissect (e.g. 'main', '0x401000').",
                        },
                        "addressOrSymbol": {
                            "type": "string",
                            "description": "Alternative way to identify the function by address or symbol.",
                        },
                        "functionIdentifier": {
                            "type": "string",
                            "description": "Another alternative for the function identifier.",
                        },
                        "timeout": {
                            "type": "integer",
                            "default": 60,
                            "description": "Maximum seconds for the decompiler before aborting, default 60; omit unless needed.",
                        },
                        "maxInstructions": {
                            "type": "integer",
                            "default": 2000,
                            "description": "Cap on disassembly instructions returned, default 2000; omit unless needed.",
                        },
                        "maxRefs": {
                            "type": "integer",
                            "default": 200,
                            "description": "Cap on cross-references returned, default 200; omit unless needed.",
                        },
                    },
                    "required": [],
                },
            ),
        ]

    # ------------------------------------------------------------------
    # Main handler
    # ------------------------------------------------------------------

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        self._require_program()

        func_id = self._get_address_or_symbol(args)
        if not func_id:
            func_id = self._get_str(args, "function", "functionidentifier", "identifier", "name", "symbol")
        if not func_id:
            raise ValueError("function, addressOrSymbol, or functionIdentifier required")

        timeout = self._get_int(args, "timeout", default=DEFAULT_TIMEOUT_SECONDS)
        max_instructions = self._get_int(args, "maxinstructions", "maxinsns", default=2000)
        max_refs = self._get_int(args, "maxrefs", "maxreferences", default=200)

        program = getattr(self.program_info, "program", None)
        if program is None:
            raise ValueError("No program loaded")

        target = self._resolve_function(func_id, program=program)
        if target is None:
            raise ValueError(f"Function not found: {func_id}")

        entry = target.getEntryPoint()
        body = target.getBody()

        result: dict[str, Any] = {
            "tool": "dissect-function",
            "name": target.getName(),
            "address": str(entry),
            "signature": str(target.getSignature()),
        }

        # --- Metadata ---
        result["metadata"] = self._collect_metadata(target)

        # --- Namespace ---
        result["namespace"] = self._collect_namespace(target)

        # --- Decompilation ---
        result["decompilation"] = self._decompile(target, program, timeout)

        # --- Disassembly ---
        result["disassembly"] = self._disassemble(target, program, max_instructions)

        # --- Comments (all types across function body) ---
        result["comments"] = self._collect_all_comments(target, program, body)

        # --- Labels / symbols inside function body ---
        result["labels"] = self._collect_labels(program, body)

        # --- Callers & callees ---
        result["callers"] = self._collect_callers(target)
        result["callees"] = self._collect_callees(target)

        # --- Inbound cross-references ---
        result["crossReferences"] = self._collect_xrefs(program, entry, max_refs)

        # --- Tags ---
        result["tags"] = collect_function_tags(target)

        # --- Bookmarks inside function body ---
        result["bookmarks"] = self._collect_bookmarks(program, body)

        # --- Stack frame / local variables ---
        result["stackFrame"] = self._collect_stack_frame(target)

        # --- Memory block info ---
        result["memoryBlock"] = self._collect_memory_block(program, entry)

        return create_success_response(result)

    # ------------------------------------------------------------------
    # Collectors (private)
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_metadata(func: Any) -> dict[str, Any]:
        body = func.getBody()
        return {
            "size": int(body.getNumAddresses()) if body else 0,
            "isExternal": bool(func.isExternal()),
            "isThunk": bool(func.isThunk()),
            "parameterCount": int(func.getParameterCount()),
            "parameters": [
                {
                    "name": str(p.getName()),
                    "type": str(p.getDataType()),
                    "ordinal": int(p.getOrdinal()),
                    "storage": str(p.getVariableStorage()) if hasattr(p, "getVariableStorage") else "",
                }
                for p in func.getParameters()
            ],
            "returnType": str(func.getReturnType()),
            "callingConvention": str(func.getCallingConventionName() or ""),
            "hasVarArgs": bool(func.hasVarArgs()),
            "hasCustomStorage": bool(func.hasCustomVariableStorage()) if hasattr(func, "hasCustomVariableStorage") else False,
            "isInline": bool(func.isInline()) if hasattr(func, "isInline") else False,
            "isNoReturn": bool(func.hasNoReturn()) if hasattr(func, "hasNoReturn") else False,
        }

    @staticmethod
    def _collect_namespace(func: Any) -> dict[str, Any]:
        ns = func.getParentNamespace()
        parts: list[str] = []
        while ns is not None and hasattr(ns, "getName"):
            name = str(ns.getName() or "")
            if name and name.lower() != "global":
                parts.append(name)
            parent = getattr(ns, "getParentNamespace", None)
            ns = parent() if parent else None
        parts.reverse()
        return {
            "path": "::".join(parts) if parts else "(global)",
            "segments": parts,
        }

    def _decompile(self, func: Any, program: Any, timeout: int) -> str:
        try:
            from ghidra.app.decompiler import DecompInterface, DecompileOptions
            from ghidra.util.task import ConsoleTaskMonitor

            monitor = ConsoleTaskMonitor()

            session_decomp = getattr(self.program_info, "decompiler", None)
            decomp = session_decomp
            owns = False

            if decomp is None:
                decomp = DecompInterface()
                opts = DecompileOptions()
                opts.grabFromProgram(program)
                decomp.setOptions(opts)
                decomp.openProgram(program)
                owns = True
            else:
                try:
                    opts = DecompileOptions()
                    opts.grabFromProgram(program)
                    decomp.setOptions(opts)
                except Exception:
                    pass

            dr = decomp.decompileFunction(func, timeout, monitor)
            if dr and dr.decompileCompleted():
                df = dr.getDecompiledFunction()
                code = df.getC() if df else None
                if code:
                    if owns:
                        decomp.dispose()
                    return str(code)

            # Retry with fresh interface if session decomp failed
            if session_decomp is not None:
                retry = DecompInterface()
                retry_opts = DecompileOptions()
                retry_opts.grabFromProgram(program)
                retry.setOptions(retry_opts)
                retry.openProgram(program)
                retry_dr = retry.decompileFunction(func, timeout, monitor)
                if retry_dr and retry_dr.decompileCompleted():
                    retry_df = retry_dr.getDecompiledFunction()
                    code = retry_df.getC() if retry_df else None
                    retry.dispose()
                    if code:
                        if owns:
                            decomp.dispose()
                        return str(code)
                retry.dispose()

            if owns:
                decomp.dispose()

        except ImportError:
            pass
        except Exception as exc:
            logger.debug("Decompiler error in dissect-function: %s", exc)

        return self._build_decompile_fallback(program, func, "decompiler unavailable", max_instructions=400)

    @staticmethod
    def _disassemble(func: Any, program: Any, max_insns: int) -> dict[str, Any]:
        listing = program.getListing()
        body = func.getBody()
        instructions: list[dict[str, Any]] = []
        if body:
            it = listing.getInstructions(body, True)
            while it.hasNext() and len(instructions) < max_insns:
                instr = it.next()
                instructions.append({
                    "address": str(instr.getAddress()),
                    "mnemonic": str(instr.getMnemonicString()),
                    "operands": str(instr),
                    "bytes": " ".join(f"{b:02x}" for b in instr.getBytes()),
                })
        return {
            "instructions": instructions,
            "count": len(instructions),
            "truncated": len(instructions) >= max_insns,
        }

    @staticmethod
    def _collect_all_comments(func: Any, program: Any, body: Any) -> dict[str, Any]:
        """Collect entry-point comments + inline comments across the function body."""
        listing = program.getListing()
        _TYPES = (
            ("eol", 0),
            ("pre", 1),
            ("post", 2),
            ("plate", 3),
            ("repeatable", 4),
        )

        # Entry-point comments
        entry_comments = collect_function_comments(program, func)

        # Inline comments at every code unit in the function body
        inline: list[dict[str, Any]] = []
        if body:
            cu_iter = listing.getCodeUnits(body, True)
            while cu_iter.hasNext():
                cu = cu_iter.next()
                addr = str(cu.getAddress())
                for label, code in _TYPES:
                    val = cu.getComment(code)
                    if val:
                        inline.append({
                            "address": addr,
                            "type": label,
                            "text": str(val),
                        })

        return {
            "entryPoint": entry_comments,
            "inline": inline,
            "inlineCount": len(inline),
        }

    @staticmethod
    def _collect_labels(program: Any, body: Any) -> list[dict[str, Any]]:
        """Collect all symbols/labels within the function address range."""
        st = program.getSymbolTable()
        labels: list[dict[str, Any]] = []
        if body is None:
            return labels
        sym_iter = st.getSymbolIterator(body.getMinAddress(), True)
        while sym_iter.hasNext():
            sym = sym_iter.next()
            addr = sym.getAddress()
            if body.contains(addr):
                labels.append({
                    "name": str(sym.getName()),
                    "address": str(addr),
                    "type": str(sym.getSymbolType()),
                    "isPrimary": bool(sym.isPrimary()),
                    "source": str(sym.getSource()) if hasattr(sym, "getSource") else "",
                })
            else:
                break  # past the body
        return labels

    @staticmethod
    def _collect_callers(func: Any) -> list[dict[str, Any]]:
        return [
            {"name": c.getName(), "address": str(c.getEntryPoint())}
            for c in func.getCallingFunctions(None)
        ]

    @staticmethod
    def _collect_callees(func: Any) -> list[dict[str, Any]]:
        return [
            {"name": c.getName(), "address": str(c.getEntryPoint())}
            for c in func.getCalledFunctions(None)
        ]

    @staticmethod
    def _collect_xrefs(program: Any, entry: Any, max_refs: int) -> list[dict[str, Any]]:
        """Inbound cross-references to the function entry point."""
        ref_mgr = program.getReferenceManager()
        refs: list[dict[str, Any]] = []
        for ref in ref_mgr.getReferencesTo(entry):
            if len(refs) >= max_refs:
                break
            refs.append({
                "fromAddress": str(ref.getFromAddress()),
                "toAddress": str(ref.getToAddress()),
                "type": str(ref.getReferenceType()),
                "isCall": bool(ref.getReferenceType().isCall()) if hasattr(ref.getReferenceType(), "isCall") else False,
                "isData": bool(ref.getReferenceType().isData()) if hasattr(ref.getReferenceType(), "isData") else False,
            })
        return refs

    @staticmethod
    def _collect_bookmarks(program: Any, body: Any) -> list[dict[str, Any]]:
        """Bookmarks within the function's address range."""
        bm_mgr = program.getBookmarkManager()
        bookmarks: list[dict[str, Any]] = []
        if body is None:
            return bookmarks
        it = bm_mgr.getBookmarksIterator(body.getMinAddress(), True)
        while it.hasNext():
            bm = it.next()
            addr = bm.getAddress()
            if body.contains(addr):
                bookmarks.append({
                    "address": str(addr),
                    "type": str(bm.getTypeString()),
                    "category": str(bm.getCategory()),
                    "comment": str(bm.getComment() or ""),
                })
            else:
                break
        return bookmarks

    @staticmethod
    def _collect_stack_frame(func: Any) -> dict[str, Any]:
        """Stack frame layout: local variables, parameters, and frame size."""
        frame = func.getStackFrame()
        if frame is None:
            return {"variables": [], "frameSize": 0}
        variables: list[dict[str, Any]] = []
        for var in frame.getStackVariables():
            variables.append({
                "name": str(var.getName()),
                "offset": int(var.getStackOffset()),
                "size": int(var.getLength()),
                "dataType": str(var.getDataType()),
                "comment": str(var.getComment() or ""),
                "isParameter": var.getStackOffset() >= 0,  # heuristic: positive offsets = params on many ABIs
            })
        return {
            "variables": variables,
            "frameSize": int(frame.getFrameSize()),
            "parameterOffset": int(frame.getParameterOffset()),
            "returnAddressOffset": int(frame.getReturnAddressOffset()) if hasattr(frame, "getReturnAddressOffset") else None,
            "localSize": int(frame.getLocalSize()) if hasattr(frame, "getLocalSize") else None,
            "parameterSize": int(frame.getParameterSize()) if hasattr(frame, "getParameterSize") else None,
        }

    @staticmethod
    def _collect_memory_block(program: Any, address: Any) -> dict[str, Any] | None:
        """Info about the memory block containing the function entry point."""
        mem = program.getMemory()
        block = mem.getBlock(address)
        if block is None:
            return None
        return {
            "name": str(block.getName()),
            "start": str(block.getStart()),
            "end": str(block.getEnd()),
            "size": int(block.getSize()),
            "permissions": {
                "read": bool(block.isRead()),
                "write": bool(block.isWrite()),
                "execute": bool(block.isExecute()),
            },
            "isInitialized": bool(block.isInitialized()),
            "sourceInfo": str(block.getSourceName()) if hasattr(block, "getSourceName") else "",
        }
