from __future__ import annotations

from types import SimpleNamespace

import pytest

import agentdecompile_cli.mcp_server.providers.dissect as dissect_module
from agentdecompile_cli.mcp_server.providers.dataflow import DataFlowToolProvider
from agentdecompile_cli.mcp_server.providers.dissect import GetFunctionAioToolProvider
from agentdecompile_cli.mcp_server.providers.search_everything import SearchEverythingToolProvider
from agentdecompile_cli.mcp_server.response_formatter import _render_get_function


class FakeFunction:
    def __init__(self, name: str = "entry", entry: str = "1400019b0") -> None:
        self._name = name
        self._entry = entry

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
        self._entry = entry
        self._func = func

    def getFunctionContaining(self, addr: str) -> FakeFunction | None:
        if addr == self._entry:
            return self._func
        return None


@pytest.mark.asyncio
async def test_analyze_data_flow_falls_back_to_resolved_function_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = "1400019b0"
    func = FakeFunction(entry=entry)
    provider = DataFlowToolProvider(program_info=SimpleNamespace(program=object(), decompiler=None))

    monkeypatch.setattr(provider, "_require_program", lambda: None)
    monkeypatch.setattr(provider, "_get_function_manager", lambda program: FakeFunctionManager(entry, func))
    monkeypatch.setattr(provider, "_resolve_address", lambda value, program=None: None)
    monkeypatch.setattr(provider, "_resolve_function", lambda value, program=None: func)

    captured: dict[str, object] = {}

    async def fake_dispatch_handler(args, direction, dispatch, **kwargs):
        captured.update(kwargs)
        return ["ok"]

    monkeypatch.setattr(provider, "_dispatch_handler", fake_dispatch_handler)

    result = await provider._handle({"addressorsymbol": "entry", "direction": "backward"})

    assert result == ["ok"]
    assert captured["addr"] == entry
    assert captured["func"] is func


def test_get_function_data_flow_uses_entry_when_seed_address_cannot_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    entry = "1400019b0"
    func = FakeFunction(entry=entry)
    provider = GetFunctionAioToolProvider(program_info=SimpleNamespace(program=None, decompiler=None))

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
        object(),
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

    assert captured["seed_address"] == entry
    assert details["dataFlow"]["address"] == entry


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