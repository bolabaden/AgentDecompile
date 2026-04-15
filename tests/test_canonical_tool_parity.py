from __future__ import annotations

from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, ClassVar, cast

import agentdecompile_cli.mcp_server.providers.dissect as dissect_module
import pytest

from agentdecompile_cli.bridge import AgentDecompileMcpClient, ClientError
from agentdecompile_cli.mcp_server.providers.dataflow import DataFlowToolProvider
from agentdecompile_cli.mcp_server.providers.dissect import GetFunctionAioToolProvider
from agentdecompile_cli.mcp_server.providers.script import ScriptToolProvider
from agentdecompile_cli.mcp_server.providers.search_everything import SearchEverythingToolProvider
from agentdecompile_cli.mcp_server.response_formatter import _render_execute_script, _render_get_function
from agentdecompile_cli.mcp_server.tool_providers import ToolProvider, ToolProviderManager, create_success_response
from mcp import types

if TYPE_CHECKING:
    from ghidra.program.model.listing import (  # pyright: ignore[reportMissingTypeStubs, reportMissingImports, reportMissingModuleSource]  # noqa: F401, E408
        Function as GhidraFunction,
        Program as GhidraProgram,
    )
    from agentdecompile_cli.launcher import ProgramInfo  # pyright: ignore[reportMissingImports]


class DummyResponseFormatProvider(ToolProvider):
    HANDLERS: ClassVar[dict[str, str]] = {"dummyresponseformat": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="dummy-response-format",
                description="Test helper tool",
                inputSchema={"type": "object", "properties": {}},
            )
        ]

    async def _handle(self, args: dict[str, object]) -> list[types.TextContent]:
        return create_success_response({"success": True, "payload": {"value": 7}})


class DummyGetFunctionProvider(ToolProvider):
    HANDLERS: ClassVar[dict[str, str]] = {"getfunction": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="get-function",
                description="Test helper get-function tool",
                inputSchema={"type": "object", "properties": {}},
            )
        ]

    async def _handle(self, args: dict[str, object]) -> list[types.TextContent]:
        return create_success_response(
            {
                "tool": "get-function",
                "name": "entry",
                "address": "1000004b0",
                "signature": "void entry(void)",
                "metadata": {"sizeBytes": 1},
                "decompilation": "void entry(void) { }",
                "disassembly": {"instructions": [], "count": 0, "truncated": False},
                "callers": [],
                "callees": [],
                "crossReferences": [],
                "outboundReferences": [],
                "comments": {},
                "labels": [],
                "bookmarks": [],
                "stackFrame": {},
                "memoryBlock": {},
                "namespace": "Global",
                "targetFunction": {"name": "entry", "address": "1000004b0"},
                "callGraphTree": {"callers": [], "callees": []},
                "callerDetails": [],
                "calleeDetails": [],
            }
        )


class DummyRequestedProgramProvider(ToolProvider):
    HANDLERS: ClassVar[dict[str, str]] = {"dummyrequestedprogram": "_handle"}

    def list_tools(self) -> list[types.Tool]:
        return [
            types.Tool(
                name="dummy-requested-program",
                description="Test helper requested-program tool",
                inputSchema={"type": "object", "properties": {"programPath": {"type": "string"}}},
            )
        ]

    async def _handle(self, args: dict[str, object]) -> list[types.TextContent]:
        program_info = self.program_info
        return create_success_response(
            {
                "success": True,
                "programPath": str(getattr(program_info, "file_path", "")),
                "programName": str(getattr(program_info, "name", "")),
            }
        )


class FakeProgram:
    def __init__(self, name: str) -> None:
        self._name: str = name

    def getName(self) -> str:
        return self._name

    def getMemory(self):
        return None

    def getListing(self):
        return None

    def getFunctionManager(self):
        return None

    def getSymbolTable(self):
        return None

    def getReferenceManager(self):
        return None

    def getDataTypeManager(self):
        return None

    def getLanguage(self):
        return None

    def getCompilerSpec(self):
        return None

    def getAddressFactory(self):
        return None

    def getBookmarkManager(self):
        return None

    def getEquateTable(self):
        return None

    def getExternalManager(self):
        return None

    def getRegister(self):
        return None

    def getProgramContext(self):
        return None


class FakeFunction:
    def __init__(self, name: str = "entry", entry: str = "1400019b0") -> None:
        self._name: str = name
        self._entry: str = entry

    def getEntryPoint(self) -> str:
        return self._entry

    def getName(self) -> str:
        return self._name

    def getSignature(self) -> str:
        return f"undefined {self._name}(void)"

    def getBody(self) -> object:
        return object()


class FakeFunctionManager:
    def __init__(self, entry: str, func: FakeFunction) -> None:
        self._entry: str = entry
        self._func: FakeFunction = func

    def getFunctionContaining(self, addr: str) -> FakeFunction | None:
        if addr == self._entry:
            return self._func
        return None


@pytest.mark.asyncio
async def test_analyze_data_flow_falls_back_to_resolved_function_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    entry: str = "1400019b0"
    func: FakeFunction = FakeFunction(entry=entry)
    provider: DataFlowToolProvider = DataFlowToolProvider(program_info=SimpleNamespace(program=object(), decompiler=None))  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(provider, "_require_program", lambda: None)
    monkeypatch.setattr(provider, "_get_function_manager", lambda program: FakeFunctionManager(entry, func))
    monkeypatch.setattr(provider, "_resolve_address", lambda value, program=None: None)
    monkeypatch.setattr(provider, "_resolve_function", lambda value, program=None: func)

    captured: dict[str, object] = {}

    async def fake_dispatch_handler(args, direction: str, dispatch: object, **kwargs):
        captured.update(kwargs)
        return ["ok"]

    monkeypatch.setattr(provider, "_dispatch_handler", fake_dispatch_handler)

    result: list[str] | Any = await provider._handle({"addressorsymbol": "entry", "direction": "backward"})

    assert result == ["ok"], "Expected to get result from fake_dispatch_handler"
    assert captured["addr"] == entry, "Expected to fall back to function entry address"
    assert captured["func"] is func, "Expected to use resolved function for data flow analysis"


def test_get_function_data_flow_uses_entry_when_seed_address_cannot_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    entry: str = "1400019b0"
    func: GhidraFunction = cast("GhidraFunction", FakeFunction(entry=entry))
    provider: GetFunctionAioToolProvider = GetFunctionAioToolProvider(program_info=SimpleNamespace(program=None, decompiler=None)) # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(provider, "_resolve_address", lambda value, program=None: None)
    monkeypatch.setattr(provider, "_collect_metadata", lambda current_func: {"size": 1, "returnType": "undefined", "callingConvention": "unknown"})
    monkeypatch.setattr(provider, "_collect_callers", lambda current_func, limit: [])
    monkeypatch.setattr(provider, "_collect_callees", lambda current_func, limit: [])
    monkeypatch.setattr(provider, "_collect_namespace", lambda current_func: {})
    monkeypatch.setattr(provider, "_collect_all_comments", lambda program, body, view: {})
    monkeypatch.setattr(provider, "_collect_labels", lambda program, body: [])
    monkeypatch.setattr(provider, "_collect_xrefs", lambda program, entry_point, limit: [])
    monkeypatch.setattr(provider, "_collect_outbound_refs", lambda program, body, limit: [])
    monkeypatch.setattr(provider, "_collect_bookmarks", lambda program, body: [])
    monkeypatch.setattr(provider, "_collect_stack_frame", lambda current_func: {})
    monkeypatch.setattr(provider, "_collect_memory_block", lambda program, entry_point: {"name": ".text", "start": entry, "end": entry, "size": 1, "permissions": {}})
    monkeypatch.setattr(dissect_module, "collect_function_tags", lambda current_func: [])

    captured: dict[str, object] = {}

    def fake_collect_function_data_flow(program, current_func, seed_address, **kwargs):
        captured["seed_address"] = seed_address
        return {
            "direction": kwargs["direction"],
            "address": str(seed_address),
            "seedCount": 0,
            "analysisDepth": kwargs["max_depth"],
            "pcode": [],
            "note": "No P-code operations mapped directly to the requested address",
        }

    monkeypatch.setattr(dissect_module, "collect_function_data_flow", fake_collect_function_data_flow)

    details = provider._collect_function_details(
        func,
        cast("GhidraProgram", object()),
        timeout=30,
        max_instructions=20,
        max_refs=10,
        max_callers=5,
        max_callees=5,
        data_flow_direction="backward",
        data_flow_address="missing-symbol",
        data_flow_max_ops=25,
        data_flow_max_depth=4,
        include_code=False,
    )

    assert captured["seed_address"] == entry, "Expected to fall back to function entry address"
    assert details["dataFlow"]["address"] == entry, "Expected data flow address to match function entry"


def test_search_everything_maps_vtable_aliases_to_vtables_scope() -> None:
    provider = SearchEverythingToolProvider()

    scopes = provider._collect_scopes({"scopes": ["vtable", "vftable", "vtables"]})

    assert scopes == ["vtables"]


def test_render_get_function_includes_data_flow_section() -> None:
    rendered = _render_get_function(
        {
            "name": "entry",
            "address": "1400019b0",
            "signature": "undefined entry(void)",
            "metadata": {"size": 1, "returnType": "undefined", "callingConvention": "unknown"},
            "decompilation": "",
            "disassembly": {"instructions": [], "count": 0, "truncated": False},
            "comments": {},
            "labels": [],
            "callers": [],
            "callees": [],
            "crossReferences": [],
            "outboundReferences": [],
            "tags": [],
            "bookmarks": [],
            "stackFrame": {},
            "memoryBlock": {},
            "dataFlow": {
                "direction": "backward",
                "address": "1400019b0",
                "seedCount": 0,
                "analysisDepth": 4,
                "pcode": [],
                "note": "No P-code operations mapped directly to the requested address",
            },
        }
    )

    assert "### Data flow (backward)" in rendered
    assert "**Seed address:** `1400019b0`" in rendered


@pytest.mark.asyncio
async def test_tool_provider_manager_honors_response_format_json() -> None:
    manager = ToolProviderManager()
    manager._register(DummyResponseFormatProvider())

    result = await manager.call_tool("dummy-response-format", {"responseFormat": "json"})

    assert len(result) == 1
    assert result[0].text == '{"success": true, "payload": {"value": 7}}'


@pytest.mark.asyncio
async def test_get_function_honors_response_format_json() -> None:
    manager = ToolProviderManager()
    manager._register(DummyGetFunctionProvider())

    result = await manager.call_tool("get-function", {"responseFormat": "json"})

    assert len(result) == 1
    assert result[0].text.startswith('{"tool": "get-function"')
    assert not result[0].text.startswith("## Function:")


@pytest.mark.asyncio
async def test_execute_script_reports_executed_program_in_json() -> None:
    provider: ScriptToolProvider = ScriptToolProvider(
        program_info=SimpleNamespace(
            program=cast("ProgramInfo", FakeProgram("k2_win_gog_aspyr_swkotor2.exe")),
            flat_api=None,
            decompiler=None,
            name="k2_win_gog_aspyr_swkotor2.exe",
            file_path="/TSL/k2_win_gog_aspyr_swkotor2.exe",
        )
    )

    result = await provider._handle_execute({"code": "__result__ = currentProgram.getName()", "programPath": "/TSL/k2_win_gog_aspyr_swkotor2.exe"})

    assert len(result) == 1
    assert '"executedProgram": {"path": "/TSL/k2_win_gog_aspyr_swkotor2.exe", "name": "k2_win_gog_aspyr_swkotor2.exe"}' in result[0].text
    assert '"result": "k2_win_gog_aspyr_swkotor2.exe"' in result[0].text


def test_render_execute_script_includes_executed_program() -> None:
    rendered: str = _render_execute_script(
        {
            "success": True,
            "result": "[]",
            "executedProgram": {
                "name": "k2_win_gog_aspyr_swkotor2.exe",
                "path": "/TSL/k2_win_gog_aspyr_swkotor2.exe",
            },
        }
    )

    assert "**Executed Program:** `k2_win_gog_aspyr_swkotor2.exe`" in rendered
    assert "**Program Path:** `/TSL/k2_win_gog_aspyr_swkotor2.exe`" in rendered


@pytest.mark.asyncio
async def test_tool_provider_manager_uses_requested_program_for_provider_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    manager: ToolProviderManager = ToolProviderManager()
    provider: DummyRequestedProgramProvider = DummyRequestedProgramProvider()
    manager._register(provider)
    manager.set_program_info(
        SimpleNamespace(
            program=cast("GhidraProgram", FakeProgram("JadeEmpire_pc_2005.exe")),
            flat_api=None,
            decompiler=None,
            name="JadeEmpire_pc_2005.exe",
            file_path="/JE/JadeEmpire_pc_2005.exe",
        )
    )

    requested_program_info: SimpleNamespace = SimpleNamespace(
        program=cast("GhidraProgram", FakeProgram("k1_win_gog_swkotor.exe")),
        flat_api=None,
        decompiler=None,
        name="k1_win_gog_swkotor.exe",
        file_path="/K1/k1_win_gog_swkotor.exe",
    )

    async def _fake_activate(session_id: str, program_path: str) -> SimpleNamespace:
        return requested_program_info

    monkeypatch.setattr(manager, "_activate_requested_program", _fake_activate)

    result = await manager.call_tool(
        "dummy-requested-program",
        {"programPath": "/K1/k1_win_gog_swkotor.exe", "responseFormat": "json"},
    )

    assert len(result) == 1
    assert '"programPath": "/K1/k1_win_gog_swkotor.exe"' in result[0].text
    assert '"programName": "k1_win_gog_swkotor.exe"' in result[0].text


def test_extract_result_uses_text_from_model_like_error_content() -> None:
    client = AgentDecompileMcpClient(url="http://127.0.0.1:8080/mcp/message")

    with pytest.raises(ClientError, match="program-resolution-failed"):
        client._extract_result(
            {
                "isError": True,
                "content": [SimpleNamespace(text="program-resolution-failed: requested program path was not found")],
            }
        )
