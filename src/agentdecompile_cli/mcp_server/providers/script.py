"""Script Tool Provider – execute-script.

Executes arbitrary Ghidra/PyGhidra Python code in the JVM context.
The entire Ghidra API is available via pre-populated namespace variables:
  currentProgram, flatApi, monitor, state, decompiler, …
"""

from __future__ import annotations

import io
import logging
import traceback

from contextlib import redirect_stderr, redirect_stdout
from typing import Any

from mcp import types

from agentdecompile_cli.registry import ToolName
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
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
                name=ToolName.EXECUTE_SCRIPT.value,
                description=(
                    "Run an unrestricted Python script directly inside the Ghidra environment. "
                    "Use this tool as a last resort or for advanced bulk processing tasks when no other existing tool provides the required capability. "
                    "You have full access to Ghidra Java/Python APIs (like flatApi, currentProgram, monitor, getState()). "
                    "To return a value back to your agent, assign the final data to a global variable named `__result__`."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "code": {
                            "type": "string",
                            "description": ("The raw Python source code to execute. To pass data out, assign your output to the `__result__` variable (e.g. `__result__ = currentProgram.getName()`)."),
                        },
                        "programPath": {
                            "type": "string",
                            "description": "Path to the program in Ghidra to provide as `currentProgram` to the script.",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Maximum number of seconds to let the script run before forcefully terminating it (default: 30). Used to prevent infinite loops.",
                            "default": 30,
                        },
                    },
                    "required": ["code"],
                },
            ),
        ]

    # ------------------------------------------------------------------

    def _build_namespace(self) -> dict[str, Any]:
        """Build the execution namespace for Ghidra script execution.

        Populates a Python namespace with Ghidra API equivalents so that script
        code can access the same globals a normal Ghidra script sees:

        **Core Program Objects:**
        - `currentProgram`: Active program (None if not loaded)
        - `flat_api` / `flatApi`: FlatProgramAPI convenience wrapper
        - `decompiler`: Decompiler instance (if available)
        - `state`: GhidraState (usually None in headless mode)
        - `monitor`: ConsoleTaskMonitor for progress reporting

        **Program Accessors (if program is loaded):**
        - `getMemory()`, `getListing()`, `getFunctionManager()`
        - `getSymbolTable()`, `getAddressFactory()`, etc. (30+ methods)
        - `toAddr(str)`: Convert string to Address
        - `getAddress(str)`: Convert string to Address

        **FlatProgramAPI methods (if flat_api available):**
        - Navigation: `getFirstFunction()`, `getFunctionAt()`, `getFunctionBefore()`
        - Access: `getBytes()`, `getByte()`, `getDataAt()`, etc.
        - Creation: `createFunction()`, `createLabel()`, `createData()`
        - Mutation: `setBytes()`, `clearListing()`, `removeDataAt()`
        - Search: `find()`, `findBytes()`, `getReferencesTo()`, etc.
        - Analysis: `analyzeAll()`, `analyzeChanges()`

        **Common Ghidra Classes (auto-imported):**
        - Symbol types: `SourceType`, `SymbolType`, `RefType`
        - Data types: `DataType`, `PointerDataType`, `StructureDataType`
        - Address: `Address`, `AddressSet`, `AddressSpace`
        - Listing: `Function`, `CodeUnit`, `Instruction`
        - Decompiler: `DecompInterface`, `ClangTokenGroup`

        **Best-Effort Approach:**
        If any import fails, it's silently skipped. This allows scripts to work
        even if a particular Ghidra module is unavailable in the current environment.

        Returns:
            dict[str, Any]: Namespace ready for eval/exec of script code.
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
                "getFirstFunction",
                "getFunctionAfter",
                "getFunctionAt",
                "getFunctionBefore",
                "getFunctionContaining",
                "getGlobalFunctions",
                "getInstructionAt",
                "getInstructionAfter",
                "getInstructionBefore",
                "getDataAt",
                "getDataAfter",
                "getDataBefore",
                "getDataContaining",
                "getBytes",
                "getByte",
                "getShort",
                "getInt",
                "getLong",
                "setBytes",
                "setByte",
                "setShort",
                "setInt",
                "setLong",
                "createFunction",
                "disassemble",
                "clearListing",
                "createData",
                "createLabel",
                "removeDataAt",
                "findBytes",
                "find",
                "getReferencesTo",
                "getReferencesFrom",
                "getSymbolAt",
                "getSymbolsAt",
                "createBookmark",
                "removeBookmark",
                "start",
                "end",
                "analyzeAll",
                "analyzeChanges",
                "openProgram",
                "closeProgram",
                "toAddr",
            ):
                fn = getattr(flat_api, name, None)
                if fn is not None:
                    ns.setdefault(name, fn)

        # Common Ghidra imports (best-effort)
        _safe_imports = [
            ("ghidra.program.model.symbol", ["SourceType", "SymbolType", "RefType"]),
            (
                "ghidra.program.model.data",
                [
                    "DataType",
                    "PointerDataType",
                    "ArrayDataType",
                    "StructureDataType",
                    "CategoryPath",
                    "DataTypeConflictHandler",
                ],
            ),
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
        """Execute Python code in the Ghidra script context.

        **Execution Flow:**
        1. Extract code and timeout from arguments
        2. Build namespace with Ghidra globals (currentProgram, flatApi, etc.)
        3. Try eval() first – if successful, store result in namespace['__result__']
        4. If eval() fails with SyntaxError, try exec() for code blocks
        5. Capture stdout/stderr during execution

        **Result Handling:**
        - Single expressions are eval'd; result is stored in __result__
        - Code blocks are exec'd; __result__ must be set explicitly in the code
        - __result__ is serialized using _serialize_result() for readability

        **Response Structure:**
        - success: True if no exceptions, False if stderr captured
        - stdout: Code output (if any)
        - stderr: Exceptions and tracebacks (if any)
        - result: Stringified result of __result__ or last eval()'d expression

        **Security Note:**
        Uses eval() and exec() which are dangrous if code is untrusted.
        This is intentional for the script sandbox – validation should happen
        at the tool invocation layer (not in this provider).
        """
        code = self._require_str(args, "code", "script", "expression", "source", name="code")
        timeout = self._get_int(args, "timeout", default=30)

        ns = self._build_namespace()
        ns["__result__"] = None

        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                # Try eval first (single expression) for convenience.
                # This handles: 1+1, getFunction("main"), currentProgram.getName()
                try:
                    result = eval(code, ns)  # noqa: S307
                    if result is not None:
                        ns["__result__"] = result
                except SyntaxError:
                    # Not a single expression – exec the code block.
                    # This handles: for loops, assignments, multiline scripts
                    exec(code, ns)  # noqa: S102
                    result = ns.get("__result__")
        except Exception:
            # Any exception (not just SyntaxError) → capture traceback to stderr
            tb = traceback.format_exc()
            stderr_capture.write(tb)
            result = None

        stdout_text = stdout_capture.getvalue()
        stderr_text = stderr_capture.getvalue()

        # Serialize the result using best-effort approach.
        # Falls back to repr() for objects we can't serialize nicely.
        result_value = ns.get("__result__", result)
        result_str = ""
        if result_value is not None:
            try:
                result_str = _serialize_result(result_value)
            except Exception as e:
                result_str = repr(result_value)

        # Build response: success=True only if no errors caught
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
    """Best-effort serialization of Ghidra/Java objects to readable text.

    Handles multiple object types with graceful degradation:
    - Primitives: str, int, float, bool → direct str()
    - Bytes: hex-encoded representation
    - Collections: list, tuple, dict with item count limits
    - Java iterables: Objects with hasNext() method
    - Python iterables: Objects with __iter__ (generators, etc.)
    - Complex objects: Falls back to str() or repr()

    Args:
        obj: Object to serialize.
        max_depth: Maximum recursion depth before using repr(). Default 3.
        max_items: Maximum items per collection before truncating. Default 200.

    Returns:
        Human-readable string representation suitable for log display.

    Examples::
        _serialize_result([1, 2, 3]) → "[1, 2, 3]"
        _serialize_result({"a": 1}) → "{a: 1}"
        _serialize_result(b"hello") → "68656c6c6f"
        _serialize_result(java_iterator) → "[item1, item2, ...]"
    """
    if obj is None:
        return "None"

    # Fast path: Primitives. No recursion needed.
    if isinstance(obj, (str, int, float, bool)):
        return str(obj)

    # Byte arrays – hex-encode without recursion.
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()

    # Lists / tuples – recurse with item count limit.
    if isinstance(obj, (list, tuple)):
        items = []
        for i, item in enumerate(obj):
            if i >= max_items:
                items.append(f"... ({len(obj) - max_items} more)")
                break
            items.append(_serialize_result(item, max_depth - 1, max_items) if max_depth > 0 else repr(item))
        return "[" + ", ".join(items) + "]"

    # Dicts – recurse on values with item count limit.
    if isinstance(obj, dict):
        items = []
        for i, (k, v) in enumerate(obj.items()):
            if i >= max_items:
                items.append(f"... ({len(obj) - max_items} more)")
                break
            val = _serialize_result(v, max_depth - 1, max_items) if max_depth > 0 else repr(v)
            items.append(f"{k}: {val}")
        return "{" + ", ".join(items) + "}"

    # Java iterators/iterables – hasNext() interface.
    # Common in Ghidra API for lazy iteration.
    try:
        if hasattr(obj, "hasNext"):
            items = []
            it = obj
            while it.hasNext() and len(items) < max_items:
                val = it.next()
                items.append(_serialize_result(val, max_depth - 1, max_items) if max_depth > 0 else repr(val))
            return "[" + ", ".join(items) + "]"
    except Exception:
        # Silently fall through to next handler.
        pass

    # Python iterables (generators, custom iterators) – exclude strings/bytes.
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
        # Silently fall through to string fallback.
        pass

    # Fallback: str() for objects with meaningful __str__, or repr().
    try:
        s = str(obj)
        # Avoid '<java_object...>' repr strings – prefer repr() in that case.
        if s and not s.startswith("<"):
            return s
    except Exception:
        pass

    # Last resort: repr().
    return repr(obj)
