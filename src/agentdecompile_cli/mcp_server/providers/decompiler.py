"""Decompiler Tool Provider - decompile-function.

Resolves one or more functions by name/address, decompiles them with Ghidra's
DecompInterface, and optionally enriches results with callees, strings, and xrefs.
"""

from __future__ import annotations

import json
import logging

from typing import TYPE_CHECKING, Any

from mcp import types

from agentdecompile_cli.mcp_server.constants import DEFAULT_TIMEOUT_SECONDS  # pyright: ignore[reportMissingImports]
from agentdecompile_cli.mcp_server.tool_providers import (
    ToolProvider,
    create_success_response,
)
from agentdecompile_cli.mcp_utils.decompiler_util import (
    DecompilerLease,
    acquire_decompiler_for_program,
    get_decompiled_function_from_results,
    merge_decompile_dict_keys,
    open_decompiler_for_program,
)
from agentdecompile_cli.registry import Tool

if TYPE_CHECKING:
    from ghidra.app.decompiler import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        DecompInterface as GhidraDecompInterface,
        DecompileResults as GhidraDecompileResults,
    )
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]
        Function as GhidraFunction,
        Program as GhidraProgram,
    )
    from ghidra.util.task import TaskMonitor as GhidraTaskMonitor  # pyright: ignore[reportMissingImports, reportMissingModuleSource, reportMissingTypeStubs]

    from agentdecompile_cli.launcher import ProgramInfo

logger = logging.getLogger(__name__)


class DecompilerToolProvider(ToolProvider):
    HANDLERS = {
        "decompile": "_handle",
        "decompilefunction": "_handle",
    }

    def __init__(self, program_info: ProgramInfo | None = None):  # noqa: F821
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider.__init__")
        super().__init__(program_info)

    def list_tools(self) -> list[types.Tool]:
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider.list_tools")
        return [
            types.Tool(
                name=Tool.DECOMPILE_FUNCTION.value,
                description="Convert machine code representing a function into high-level, human-readable C-like pseudocode. Use this tool to easily read and understand what a function does without having to read assembly instructions.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "programPath": {"type": "string", "description": "The path to the program containing the function to be decompiled."},
                        "function": {"type": "string", "description": "The name or address of the function you want to decompile (e.g. 'main', '0x1000')."},
                        "addressOrSymbol": {"type": "string", "description": "Alternative way to specify the function by its exact address or symbol name."},
                        "functionIdentifier": {"type": "string", "description": "Another alternative to specify the target function's identifier."},
                        "nameOrAddress": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}},
                            ],
                            "description": "Function name/address or a batch of names/addresses to decompile.",
                        },
                        "functions": {
                            "oneOf": [
                                {"type": "string"},
                                {"type": "array", "items": {"type": "string"}},
                            ],
                            "description": "Compatibility batch input for one or more function identifiers.",
                        },
                        "timeout": {"type": "integer", "default": 60, "description": "Maximum time in seconds to wait for the decompiler to finish before aborting."},
                        "includeCallees": {"type": "boolean", "default": False, "description": "Include callee function summaries."},
                        "includeStrings": {"type": "boolean", "default": False, "description": "Include referenced string literals when available."},
                        "includeXrefs": {"type": "boolean", "default": False, "description": "Include inbound cross-references to the function entry."},
                    },
                    "required": [],
                },
            ),
        ]

    async def _handle(self, args: dict[str, Any]) -> list[types.TextContent]:
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._handle")
        self._require_program()
        timeout: int = self._get_int(args, "timeout", default=DEFAULT_TIMEOUT_SECONDS)  # pyright: ignore[reportAssignmentType]
        assert self.program_info is not None  # for type checker
        program = self.program_info.program
        targets = self._get_targets(args)
        if not targets:
            raise ValueError("function, addressOrSymbol, functionIdentifier, nameOrAddress, or functions required")

        include_callees = self._get_bool(args, "includecallees", default=False)
        include_strings = self._get_bool(args, "includestrings", default=False)
        include_xrefs = self._get_bool(args, "includexrefs", "includerefs", default=False)

        results: list[dict[str, Any]] = []
        for target in targets:
            try:
                target_func = self._resolve_function(target, program=program)
                if target_func is None:
                    raise ValueError(f"Function not found: {target}")
                results.append(
                    self.decompile_function_payload(
                        target_func,
                        program,
                        timeout,
                        include_callees=include_callees,
                        include_strings=include_strings,
                        include_xrefs=include_xrefs,
                    )
                )
            except Exception as exc:
                results.append(
                    merge_decompile_dict_keys(
                        {
                            "name": target,
                            "function": target,
                            "code": "",
                            "decompilation": "",
                            "signature": None,
                            "error": str(exc),
                        }
                    )
                )

        if len(results) == 1 and len(targets) == 1:
            return create_success_response(results[0])
        return create_success_response({"results": results, "count": len(results)})

    def _get_targets(self, args: dict[str, Any]) -> list[str]:
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._get_targets")
        targets: list[str] = []
        for key in ("nameoraddress", "name_or_address", "functionnameoraddress", "functions"):
            raw_list = self._get_list(args, key)
            if raw_list:
                targets.extend(str(v).strip() for v in raw_list if str(v).strip())
                break
        if not targets:
            single = self._get_address_or_symbol(args)
            if single:
                targets.append(single.strip())
        return targets

    def decompile_function_payload(
        self,
        target_func: GhidraFunction,
        program: GhidraProgram,
        timeout: int,
        *,
        include_callees: bool = False,
        include_strings: bool = False,
        include_xrefs: bool = False,
    ) -> dict[str, Any]:
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider.decompile_function_payload")
        response = self._decompile_with_ghidra_api(target_func, program, timeout)
        payload: dict[str, Any] = {}
        if response:
            try:
                parsed = json.loads(response[0].text)
                if isinstance(parsed, dict):
                    payload = parsed
            except Exception:
                payload = {}
        if not payload:
            payload = {
                "function": target_func.getName(),
                "name": target_func.getName(),
                "address": str(target_func.getEntryPoint()),
                "signature": str(target_func.getSignature()),
                "code": "",
                "decompilation": "",
            }

        if include_callees:
            payload["callees"] = self._collect_callees(target_func)
        if include_strings:
            payload["referencedStrings"] = self._collect_referenced_strings(program, target_func)
            payload["referenced_strings"] = payload["referencedStrings"]
        if include_xrefs:
            payload["xrefs"] = self._collect_xrefs(program, target_func)
        return merge_decompile_dict_keys(payload)

    @staticmethod
    def _collect_callees(target_func: GhidraFunction) -> list[dict[str, str]]:
        try:
            from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingModuleSource]

            monitor = ConsoleTaskMonitor()
            return [{"name": str(func.getName()), "address": str(func.getEntryPoint())} for func in target_func.getCalledFunctions(monitor)]
        except Exception:
            return []

    @staticmethod
    def _collect_xrefs(program: GhidraProgram, target_func: GhidraFunction) -> list[dict[str, str]]:
        try:
            refs = program.getReferenceManager().getReferencesTo(target_func.getEntryPoint())
            return [
                {
                    "from": str(ref.getFromAddress()),
                    "to": str(ref.getToAddress()),
                    "type": str(ref.getReferenceType()),
                }
                for ref in refs
            ]
        except Exception:
            return []

    @staticmethod
    def _collect_referenced_strings(program: GhidraProgram, target_func: GhidraFunction) -> list[dict[str, str]]:
        try:
            listing = program.getListing()
            references = program.getReferenceManager()
            strings: list[dict[str, str]] = []
            seen: set[str] = set()
            for instruction in listing.getInstructions(target_func.getBody(), True):
                for ref in references.getReferencesFrom(instruction.getAddress()):
                    to_addr = ref.getToAddress()
                    data = listing.getDataAt(to_addr)
                    if data is None:
                        continue
                    data_type = str(data.getDataType())
                    if "string" not in data_type.lower():
                        continue
                    key = str(to_addr)
                    if key in seen:
                        continue
                    seen.add(key)
                    strings.append({"address": key, "value": str(data.getValue())})
            return strings
        except Exception:
            return []

    def _decompile_with_ghidra_api(
        self,
        target_func: GhidraFunction,
        program: GhidraProgram,
        timeout: int,
    ) -> list[types.TextContent]:
        """Decompile a function using Ghidra's DecompInterface."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._decompile_with_ghidra_api")
        try:
            from ghidra.util.task import ConsoleTaskMonitor  # pyright: ignore[reportMissingModuleSource]

            monitor = ConsoleTaskMonitor()
            session_decomp = getattr(self.program_info, "decompiler", None)

            with self._setup_decompiler(session_decomp, program) as lease:
                result = self._perform_decompilation(lease, target_func, timeout, monitor, session_decomp, program)
                if isinstance(result, dict):
                    result = merge_decompile_dict_keys(result)
                return create_success_response(result)

        except ImportError as exc:
            raise RuntimeError("Ghidra DecompInterface is not available (PyGhidra / Ghidra classpath)") from exc

    def _setup_decompiler(
        self,
        session_decomp: GhidraDecompInterface | None,
        program: GhidraProgram,
    ) -> DecompilerLease:
        """Set up the decompiler interface and return a managed lease."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._setup_decompiler")
        return acquire_decompiler_for_program(session_decomp, program)

    def _perform_decompilation(
        self,
        lease: DecompilerLease,
        target_func: GhidraFunction,
        timeout: int,
        monitor: GhidraTaskMonitor,
        session_decomp: GhidraDecompInterface | None,
        program: GhidraProgram | None = None,
    ) -> dict[str, Any]:  # pyright: ignore[reportReturnType]
        """Perform the actual decompilation with retry logic."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._perform_decompilation")
        decomp = lease.decompiler
        dr: GhidraDecompileResults = decomp.decompileFunction(target_func, timeout, monitor)

        if dr and dr.decompileCompleted():
            return self._extract_successful_decompilation(dr, target_func)

        # Try retry with fresh interface if session decomp failed
        if session_decomp is not None and lease.reused_session:
            retry_result = self._try_retry_decompilation(target_func, timeout, monitor, decomp, program)
            if retry_result:
                return retry_result

        self._handle_decompilation_failure(dr, decomp, target_func, program)

    def _extract_successful_decompilation(
        self,
        dr: GhidraDecompileResults,
        target_func: GhidraFunction,
    ) -> dict[str, Any]:
        """Extract results from a successful decompilation."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._extract_successful_decompilation")
        df = get_decompiled_function_from_results(dr)
        if df is None:
            raise RuntimeError("Decompilation completed but Ghidra returned no DecompiledFunction")
        c_code = df.getC()
        if not (c_code or "").strip():
            raise RuntimeError("Decompilation completed but C output was empty")
        sig = df.getSignature()

        return merge_decompile_dict_keys(
            {
                "function": target_func.getName(),
                "address": str(target_func.getEntryPoint()),
                "signature": sig,
                "decompilation": c_code,
            },
        )

    def _try_retry_decompilation(
        self,
        target_func: GhidraFunction,
        timeout: int,
        monitor: GhidraTaskMonitor,
        original_decomp: GhidraDecompInterface,
        program: GhidraProgram | None = None,
    ) -> dict[str, Any] | None:
        """Try decompilation again with a fresh DecompInterface."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._try_retry_decompilation")
        try:
            if program is None:
                program = original_decomp.getProgram()

            # If we still don't have a program, we can't retry
            if program is None:
                return None

            retry = open_decompiler_for_program(program)

            retry_dr = retry.decompileFunction(target_func, timeout, monitor)
            if retry_dr and retry_dr.decompileCompleted():
                result = self._extract_successful_decompilation(retry_dr, target_func)
                retry.dispose()
                return result

            retry.dispose()
        except Exception:
            pass

        return None

    def _handle_decompilation_failure(
        self,
        dr: GhidraDecompileResults | None,
        decomp: GhidraDecompInterface,
        target_func: GhidraFunction,
        program: GhidraProgram | None = None,
    ) -> None:
        """Raise with Ghidra decompiler diagnostics when decompilation does not complete."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._handle_decompilation_failure")
        err_msg: str = self._extract_error_message(dr, decomp)
        if program is None:
            try:
                program = decomp.getProgram()
            except Exception:
                program = None

        extras: list[str] = []
        if dr is not None:
            for attr in ("timedOut", "isTimedOut", "wasCancelled", "isCancelled"):
                if hasattr(dr, attr):
                    try:
                        fn = getattr(dr, attr)
                        flag = fn() if callable(fn) else fn
                        if bool(flag):
                            extras.append(f"{attr}=true")
                            break
                    except Exception:
                        pass
            try:
                if not dr.decompileCompleted():
                    extras.append("decompileCompleted=false")
            except Exception:
                pass

        name = target_func.getName()
        addr = str(target_func.getEntryPoint())
        parts = [p for p in [err_msg, " ".join(extras)] if p]
        detail = "; ".join(parts) if parts else "no error message from DecompInterface"
        if program is None:
            detail = f"{detail} (program handle unavailable on DecompInterface)"
        raise RuntimeError(f"Decompilation failed for {name} @ {addr}: {detail}")

    def _extract_error_message(self, dr: GhidraDecompileResults | None, decomp: GhidraDecompInterface) -> str:
        """Extract error message from decompilation result."""
        logger.debug("diag.enter %s", "mcp_server/providers/decompiler.py:DecompilerToolProvider._extract_error_message")
        err_msg = ""
        if dr is not None:
            try:
                err_msg = dr.getErrorMessage() or ""
            except Exception:
                err_msg = ""

        if not err_msg:
            try:
                err_msg = decomp.getLastMessage() or ""
            except Exception:
                err_msg = ""

        return str(err_msg)
