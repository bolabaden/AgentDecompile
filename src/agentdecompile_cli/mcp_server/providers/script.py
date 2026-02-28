"""Script Tool Provider – execute-script.

Executes arbitrary Ghidra/PyGhidra Python code in the JVM context.
The entire Ghidra API is available via pre-populated namespace variables:
  currentProgram, flatApi, monitor, state, decompiler, …
"""

from __future__ import annotations

import io
import logging
import sys
import traceback

from contextlib import redirect_stderr, redirect_stdout
from typing import Any

from mcp import types

from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_error_response,
    create_success_response,
)

logger = logging.getLogger(__name__)


class ScriptToolProvider(ToolProvider):
    HANDLERS = {
        "executescript": "_handle_execute",
    }

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="execute-script",
                description=(
                    "Execute arbitrary Ghidra/PyGhidra Python code. "
                    "The full Ghidra API is available (currentProgram, flatApi, monitor, "
                    "state, decompiler, Transaction, AddressFactory, etc.). "
                    "Returns stdout/stderr output and the value of the last expression (stored as __result__)."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": (
                                "Python code to execute in the Ghidra JVM context. "
                                "Assign to __result__ to return a value."
                            ),
                        },
                        "programPath": {
                            "type": "string",
                            "description": "Program path (optional in GUI mode, required headless)",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Max execution time in seconds (default: 30)",
                            "default": 30,
                        },
                    },
                    "required": ["code"],
                },
            ),
        ]

    # ------------------------------------------------------------------

    def _build_namespace(self) -> dict[str, Any]:
        """Build the execution namespace with Ghidra globals.

        Mirrors what a Ghidra script normally sees:
          currentProgram, state, monitor, flatApi / flat_api,
          getAddress, toAddr, getFunction, getMemory, …
        """
        ns: dict[str, Any] = {"__builtins__": __builtins__}

        program = None
        flat_api = None
        decompiler = None

        if self.program_info is not None:
            program = getattr(self.program_info, "program", None)
            flat_api = getattr(self.program_info, "flat_api", None)
            decompiler = getattr(self.program_info, "decompiler", None)

        # Core Ghidra script variables
        ns["currentProgram"] = program
        ns["flat_api"] = flat_api
        ns["flatApi"] = flat_api
        ns["state"] = None  # GhidraState (not always available headless)
        ns["monitor"] = None
        ns["decompiler"] = decompiler

        # Try to get a real monitor
        try:
            from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import-not-found]
            ns["monitor"] = ConsoleTaskMonitor()
        except Exception:
            pass

        # Convenience accessors from the program
        if program is not None:
            ns["getMemory"] = program.getMemory
            ns["getListing"] = program.getListing
            ns["getFunctionManager"] = program.getFunctionManager
            ns["getSymbolTable"] = program.getSymbolTable
            ns["getReferenceManager"] = program.getReferenceManager
            ns["getDataTypeManager"] = program.getDataTypeManager
            ns["getLanguage"] = program.getLanguage
            ns["getCompilerSpec"] = program.getCompilerSpec
            ns["getAddressFactory"] = program.getAddressFactory
            ns["getBookmarkManager"] = program.getBookmarkManager
            ns["getEquateTable"] = program.getEquateTable
            ns["getExternalManager"] = program.getExternalManager
            ns["getNamespaceManager"] = getattr(program, "getNamespaceManager", None)
            ns["getRegister"] = program.getRegister
            ns["getProgramContext"] = program.getProgramContext

            # Address helpers
            try:
                af = program.getAddressFactory()
                ns["toAddr"] = lambda s: af.getAddress(str(s))
                ns["getAddress"] = lambda s: af.getAddress(str(s))
            except Exception:
                pass

        # FlatProgramAPI helpers
        if flat_api is not None:
            for name in (
                "getFirstFunction", "getFunctionAfter", "getFunctionAt",
                "getFunctionBefore", "getFunctionContaining", "getGlobalFunctions",
                "getInstructionAt", "getInstructionAfter", "getInstructionBefore",
                "getDataAt", "getDataAfter", "getDataBefore", "getDataContaining",
                "getBytes", "getByte", "getShort", "getInt", "getLong",
                "setBytes", "setByte", "setShort", "setInt", "setLong",
                "createFunction", "disassemble", "clearListing",
                "createData", "createLabel", "removeDataAt",
                "findBytes", "find", "getReferencesTo", "getReferencesFrom",
                "getSymbolAt", "getSymbolsAt",
                "createBookmark", "removeBookmark",
                "start", "end", "analyzeAll", "analyzeChanges",
                "openProgram", "closeProgram",
                "toAddr",
            ):
                fn = getattr(flat_api, name, None)
                if fn is not None:
                    ns.setdefault(name, fn)

        # Common Ghidra imports (best-effort)
        _safe_imports = [
            ("ghidra.program.model.symbol", ["SourceType", "SymbolType", "RefType"]),
            ("ghidra.program.model.data", [
                "DataType", "PointerDataType", "ArrayDataType",
                "StructureDataType", "CategoryPath", "DataTypeConflictHandler",
            ]),
            ("ghidra.program.model.listing", ["CodeUnit", "Function", "Program", "Instruction"]),
            ("ghidra.program.model.address", ["Address", "AddressSet", "AddressSpace"]),
            ("ghidra.program.model.mem", ["MemoryAccessException"]),
            ("ghidra.program.model.pcode", ["PcodeOp", "Varnode", "HighFunction"]),
            ("ghidra.app.decompiler", ["DecompInterface", "DecompileResults", "ClangTokenGroup"]),
            ("ghidra.util.task", ["ConsoleTaskMonitor", "TaskMonitor"]),
            ("ghidra.app.util.bin.format.elf", []),  # ELF helpers
            ("java.lang", ["String", "Integer", "Long", "System"]),
        ]
        for module_path, names in _safe_imports:
            try:
                mod = __import__(module_path, fromlist=names or ["__name__"])
                if names:
                    for name in names:
                        obj = getattr(mod, name, None)
                        if obj is not None:
                            ns.setdefault(name, obj)
                else:
                    short = module_path.rsplit(".", 1)[-1]
                    ns.setdefault(short, mod)
            except Exception:
                pass

        return ns

    # ------------------------------------------------------------------

    async def _handle_execute(self, args: dict[str, Any]) -> list[types.TextContent]:
        code = self._require_str(args, "code", "script", "expression", "source", name="code")
        timeout = self._get_int(args, "timeout", default=30)

        ns = self._build_namespace()
        ns["__result__"] = None

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                # Try eval first (single expression) for convenience
                try:
                    result = eval(code, ns)  # noqa: S307
                    if result is not None:
                        ns["__result__"] = result
                except SyntaxError:
                    # Not a single expression – exec the code block
                    exec(code, ns)  # noqa: S102
                    result = ns.get("__result__")
        except Exception:
            tb = traceback.format_exc()
            stderr_capture.write(tb)
            result = None

        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        # Serialize the result
        result_value = ns.get("__result__", result)
        result_str = ""
        if result_value is not None:
            try:
                result_str = _serialize_result(result_value)
            except Exception as e:
                result_str = repr(result_value)

        response: dict[str, Any] = {"success": not bool(stderr_text and not stdout_text and result_str == "")}
        if stdout_text:
            response["stdout"] = stdout_text
        if stderr_text:
            response["stderr"] = stderr_text
        if result_str:
            response["result"] = result_str
        if not stdout_text and not stderr_text and not result_str:
            response["result"] = "None"

        return create_success_response(response)


def _serialize_result(obj: Any, max_depth: int = 3, max_items: int = 200) -> str:
    """Best-effort serialization of Ghidra/Java objects to readable text."""
    if obj is None:
        return "None"

    # Primitives
    if isinstance(obj, (str, int, float, bool)):
        return str(obj)

    # Byte arrays
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()

    # Lists / tuples
    if isinstance(obj, (list, tuple)):
        items = []
        for i, item in enumerate(obj):
            if i >= max_items:
                items.append(f"... ({len(obj) - max_items} more)")
                break
            items.append(_serialize_result(item, max_depth - 1, max_items) if max_depth > 0 else repr(item))
        return "[" + ", ".join(items) + "]"

    # Dicts
    if isinstance(obj, dict):
        items = []
        for i, (k, v) in enumerate(obj.items()):
            if i >= max_items:
                items.append(f"... ({len(obj) - max_items} more)")
                break
            val = _serialize_result(v, max_depth - 1, max_items) if max_depth > 0 else repr(v)
            items.append(f"{k}: {val}")
        return "{" + ", ".join(items) + "}"

    # Java iterators / iterables – consume into list
    try:
        if hasattr(obj, "hasNext"):
            items = []
            it = obj
            while it.hasNext() and len(items) < max_items:
                items.append(_serialize_result(it.next(), max_depth - 1, max_items) if max_depth > 0 else repr(it.next()))
            return "[" + ", ".join(items) + "]"
    except Exception:
        pass

    # Python iterables (generators, etc.)
    try:
        if hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes)):
            items = []
            for i, item in enumerate(obj):
                if i >= max_items:
                    items.append("...")
                    break
                items.append(_serialize_result(item, max_depth - 1, max_items) if max_depth > 0 else repr(item))
            return "[" + ", ".join(items) + "]"
    except Exception:
        pass

    # Java .toString()
    try:
        s = str(obj)
        if s and not s.startswith("<"):
            return s
    except Exception:
        pass

    return repr(obj)
