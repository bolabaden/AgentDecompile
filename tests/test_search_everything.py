from __future__ import annotations

import json
import sys

from contextlib import nullcontext
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest

import agentdecompile_cli.mcp_server.providers.search_everything as search_module
from agentdecompile_cli.mcp_server.providers.search_everything import SearchEverythingToolProvider


def test_match_text_bounds_fuzzy_similarity_to_small_segments(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()
    compared_lengths: list[int] = []

    class RecordingMatcher:
        def __init__(self, _junk: object, _query: str, candidate: str) -> None:
            compared_lengths.append(len(candidate))

        def ratio(self) -> float:
            return 0.0

    monkeypatch.setattr(search_module.difflib, "SequenceMatcher", RecordingMatcher)

    provider._match_text(
        text=("int sub_401000(void) {\n" + "value = field + offset;\n" * 4000 + "}\n") * 2,
        queries=["ReadFieldCResRef"],
        mode="auto",
        case_sensitive=False,
        threshold=0.7,
        compiled_regexes={},
    )

    assert compared_lengths
    assert max(compared_lengths) <= search_module._MAX_FUZZY_SEGMENT_CHARS


def test_match_text_reuses_prepared_fuzzy_candidates_for_multiple_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()
    prepare_calls: list[str] = []

    def fake_prepare(text: str, case_sensitive: bool) -> list[str]:
        prepare_calls.append(f"{len(text)}:{case_sensitive}")
        return ["alpha token", "beta token"]

    monkeypatch.setattr(provider, "_prepare_fuzzy_candidates", fake_prepare)

    result = provider._match_text(
        text="x" * 2000,
        queries=["alpha token", "beta token"],
        mode="fuzzy",
        case_sensitive=False,
        threshold=0.1,
        compiled_regexes={},
    )

    assert result is not None
    assert len(prepare_calls) == 1


def test_match_text_stops_after_perfect_literal_match(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()
    fuzzy_calls: list[str] = []

    def fake_fuzzy(*args: object, **kwargs: object) -> float:
        fuzzy_calls.append("called")
        return 0.0

    monkeypatch.setattr(provider, "_fuzzy_similarity", fake_fuzzy)

    result = provider._match_text(
        text="exact token present",
        queries=["exact token", "something expensive", "another expensive"],
        mode="auto",
        case_sensitive=False,
        threshold=0.7,
        compiled_regexes={},
    )

    assert result is not None
    assert result["matchType"] == "literal"
    assert fuzzy_calls == []


def test_resolve_text_match_mode_maps_literal_to_auto() -> None:
    provider = SearchEverythingToolProvider()

    assert provider._resolve_text_match_mode({"mode": "literal"}, None) == "auto"
    assert provider._resolve_text_match_mode({"searchmode": "literal"}, None) == "auto"


@pytest.mark.asyncio
async def test_handle_skips_expensive_default_scopes_after_fast_hits(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()
    calls: list[str] = []

    async def fake_resolve_target_programs(_args: dict[str, object]) -> tuple[list[dict[str, object]], list[str], dict[str, object]]:
        return ([{"programKey": "test.bin", "program": object()}], [], {"requestedProgramCount": 1, "projectProgramCount": 1, "skippedPrograms": []})

    def fake_search_scope(**kwargs: object) -> tuple[list[dict[str, object]], dict[str, object] | None]:
        scope = str(kwargs["scope"])
        calls.append(scope)
        if scope == "functions":
            results = [
                {
                    "scope": "functions",
                    "resultType": "function",
                    "function": f"entry_{index}",
                    "name": f"entry_{index}",
                    "address": f"0x{index:04x}",
                    "functionAddress": f"0x{index:04x}",
                    "score": 1.0,
                    "matchType": "literal",
                    "query": "entry",
                }
                for index in range(8)
            ]
            return results, None
        if scope in {"decompilation", "disassembly"}:
            raise AssertionError(f"{scope} should have been skipped once cheap scopes satisfied the limit")
        return [], None

    monkeypatch.setattr(provider, "_resolve_target_programs", fake_resolve_target_programs)
    monkeypatch.setattr(provider, "_search_scope", fake_search_scope)

    result = await provider._handle({"query": "entry", "limit": 5})
    payload = json.loads(result[0].text)

    assert "functions" in calls
    assert "decompilation" not in calls
    assert "disassembly" not in calls
    assert any(item.get("skipped") for item in payload["scopeDiagnostics"])


def test_search_decompilation_counts_cancelled_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()

    class FakeFunction:
        def __init__(self, name: str, address: str) -> None:
            self._name = name
            self._address = address

        def getName(self) -> str:
            return self._name

        def getEntryPoint(self) -> str:
            return self._address

    class FakeFunctionManager:
        def getFunctions(self, _forward: bool):
            return [FakeFunction("slow_a", "0x1000"), FakeFunction("slow_b", "0x2000")]

    class FakeDecompileResults:
        def decompileCompleted(self) -> bool:
            return False

        def isTimedOut(self) -> bool:
            return True

        def isCancelled(self) -> bool:
            return True

    class FakeDecompiler:
        def decompileFunction(self, _func: object, _timeout: int, _monitor: object) -> FakeDecompileResults:
            return FakeDecompileResults()

    monkeypatch.setattr(provider, "_get_function_manager", lambda _program: FakeFunctionManager())

    fake_ghidra = ModuleType("ghidra")
    fake_ghidra_app = ModuleType("ghidra.app")
    fake_ghidra_decompiler = ModuleType("ghidra.app.decompiler")
    fake_ghidra_util = ModuleType("ghidra.util")
    fake_ghidra_task = ModuleType("ghidra.util.task")

    setattr(fake_ghidra_decompiler, "DecompileResults", FakeDecompileResults)
    setattr(fake_ghidra_decompiler, "DecompiledFunction", object)
    setattr(fake_ghidra_task, "ConsoleTaskMonitor", object)

    monkeypatch.setitem(sys.modules, "ghidra", fake_ghidra)
    monkeypatch.setitem(sys.modules, "ghidra.app", fake_ghidra_app)
    monkeypatch.setitem(sys.modules, "ghidra.app.decompiler", fake_ghidra_decompiler)
    monkeypatch.setitem(sys.modules, "ghidra.util", fake_ghidra_util)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", fake_ghidra_task)

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.decompiler_util.acquire_decompiler_for_program",
        lambda _session, _program: nullcontext(SimpleNamespace(decompiler=FakeDecompiler(), reused_session=False)),
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.decompiler_util.get_decompiled_function_from_results",
        lambda _result: None,
    )

    results, diagnostic = provider._search_decompilation(
        cast(Any, object()),
        None,
        ["ReadFieldCResRef"],
        "auto",
        False,
        0.7,
        {},
        10,
        10,
        1,
    )

    assert results == []
    assert diagnostic["scannedFunctions"] == 2
    assert diagnostic["timedOutCount"] == 2
    assert diagnostic["cancelledCount"] == 2
    assert diagnostic["failedCount"] == 2


def test_search_decompilation_prefers_target_program_info_decompiler(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()

    class FakeFunctionManager:
        def getFunctions(self, _forward: bool):
            return []

    class FakeCachedDecompiler:
        pass

    class FakeProgramInfo:
        def __init__(self) -> None:
            self.decompiler = FakeCachedDecompiler()
            self.get_decompiler_calls = 0

        def get_decompiler(self) -> FakeCachedDecompiler:
            self.get_decompiler_calls += 1
            return self.decompiler

    class FakeLease:
        def __init__(self, decompiler: object) -> None:
            self.decompiler = decompiler
            self.reused_session = True

        def __enter__(self) -> FakeLease:
            return self

        def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
            return None

    fake_info = FakeProgramInfo()
    provider.program_info = cast(Any, SimpleNamespace(decompiler=None))
    monkeypatch.setattr(provider, "_get_function_manager", lambda _program: FakeFunctionManager())

    fake_ghidra = ModuleType("ghidra")
    fake_ghidra_util = ModuleType("ghidra.util")
    fake_ghidra_task = ModuleType("ghidra.util.task")
    setattr(fake_ghidra_task, "ConsoleTaskMonitor", object)
    monkeypatch.setitem(sys.modules, "ghidra", fake_ghidra)
    monkeypatch.setitem(sys.modules, "ghidra.util", fake_ghidra_util)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", fake_ghidra_task)

    seen_session_decompilers: list[object] = []

    def fake_acquire(session_decompiler: object, _program: object) -> FakeLease:
        seen_session_decompilers.append(session_decompiler)
        return FakeLease(session_decompiler)

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.decompiler_util.acquire_decompiler_for_program",
        fake_acquire,
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.decompiler_util.get_decompiled_function_from_results",
        lambda _result: None,
    )

    results, diagnostic = provider._search_decompilation(
        cast(Any, object()),
        cast(Any, fake_info),
        ["ReadFieldCResRef"],
        "auto",
        False,
        0.7,
        {},
        10,
        10,
        1,
    )

    assert results == []
    assert diagnostic["reusedSessionDecompiler"] is True
    assert fake_info.get_decompiler_calls == 1
    assert seen_session_decompilers == [fake_info.decompiler]


def test_collect_project_program_paths_prefers_session_project_binaries(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()

    monkeypatch.setattr(
        search_module.SESSION_CONTEXTS,
        "get_project_binaries",
        lambda _session_id, fallback_to_latest=False: [
            {"path": "/Other BioWare Engines/Aurora/nwmain.exe"},
            {"programPath": "/Other BioWare Engines/Aurora/nwserver.exe"},
            {"name": "toolset.exe"},
            {"path": "/Other BioWare Engines/Aurora/nwmain.exe"},
        ],
    )

    result = provider._collect_project_program_paths(session_id="session-1")

    assert result == [
        "/Other BioWare Engines/Aurora/nwmain.exe",
        "/Other BioWare Engines/Aurora/nwserver.exe",
        "toolset.exe",
    ]


@pytest.mark.asyncio
async def test_resolve_target_programs_reports_project_inventory_and_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()

    class FakeManager:
        def _resolve_project_data(self) -> None:
            return None

        async def _activate_requested_program(self, _session_id: str, requested_program_key: str) -> object | None:
            if requested_program_key.endswith("nwserver.exe"):
                raise RuntimeError("checkout failed")
            if requested_program_key.endswith("toolset.exe"):
                return None
            return SimpleNamespace(program=object())

    provider._manager = cast(Any, FakeManager())

    monkeypatch.setattr(
        search_module.SESSION_CONTEXTS,
        "get_project_binaries",
        lambda _session_id, fallback_to_latest=False: [
            {"path": "/Other BioWare Engines/Aurora/nwmain.exe"},
            {"path": "/Other BioWare Engines/Aurora/nwserver.exe"},
            {"path": "/Other BioWare Engines/Aurora/toolset.exe"},
        ],
    )
    monkeypatch.setattr(search_module.SESSION_CONTEXTS, "get_program_info", lambda _session_id, _key: None)
    monkeypatch.setattr(search_module.SESSION_CONTEXTS, "get_active_program_info", lambda _session_id: None)

    targets, warnings, resolution = await provider._resolve_target_programs({"query": "Aurora"})

    assert [target["programKey"] for target in targets] == ["/Other BioWare Engines/Aurora/nwmain.exe"]
    assert resolution["projectProgramCount"] == 3
    assert resolution["requestedProgramCount"] == 3
    assert resolution["usedProjectInventory"] is True
    assert resolution["usedActiveFallback"] is False
    assert resolution["skippedPrograms"] == [
        {"program": "/Other BioWare Engines/Aurora/nwserver.exe", "reason": "checkout failed"},
        {"program": "/Other BioWare Engines/Aurora/toolset.exe", "reason": "not activated"},
    ]
    assert warnings == ["program '/Other BioWare Engines/Aurora/nwserver.exe': checkout failed"]


def test_search_structures_enriches_field_preview_and_related_class(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()

    class FakeSymbolType:
        CLASS = "CLASS"

    fake_ghidra_program = ModuleType("ghidra.program")
    fake_ghidra_model = ModuleType("ghidra.program.model")
    fake_ghidra_symbol = ModuleType("ghidra.program.model.symbol")
    setattr(fake_ghidra_symbol, "SymbolType", FakeSymbolType)

    monkeypatch.setitem(sys.modules, "ghidra.program", fake_ghidra_program)
    monkeypatch.setitem(sys.modules, "ghidra.program.model", fake_ghidra_model)
    monkeypatch.setitem(sys.modules, "ghidra.program.model.symbol", fake_ghidra_symbol)

    struct_obj = object()
    monkeypatch.setattr(
        search_module,
        "collect_structures",
        lambda _program, limit=None: [
            {
                "name": "CResTGA",
                "categoryPath": "/Res",
                "description": "Texture resource header",
                "length": 64,
                "numComponents": 3,
                "isUnion": False,
                "structure": struct_obj,
            },
        ],
    )
    monkeypatch.setattr(
        search_module,
        "collect_structure_fields",
        lambda _structure: [
            {"offset": 0, "name": "width", "type": "uint32", "comment": "texture width"},
            {"offset": 4, "name": "height", "type": "uint32", "comment": "texture height"},
            {"offset": 8, "name": "format", "type": "uint32", "comment": "pixel format"},
        ],
    )
    monkeypatch.setattr(
        search_module,
        "collect_symbols",
        lambda _program, symbol_type=None, limit=None: [
            {"name": "CResTGA", "address": "0x401000", "namespace": "global", "source": "ANALYSIS", "isPrimary": True}
        ] if symbol_type == FakeSymbolType.CLASS else [],
    )
    monkeypatch.setattr(
        provider,
        "_collect_reference_summary",
        lambda _program, _address, max_refs=3: {
            "referenceCount": 2,
            "referencesPreview": [{"fromAddress": "0x402000", "function": "LoadTexture", "type": "DATA"}],
        },
    )

    results = provider._search_structures(cast(Any, object()), ["CResTGA"], "auto", False, 0.7, {}, 10)

    assert len(results) == 1
    result = results[0]
    assert result["fieldCount"] == 3
    assert "width@0x0:uint32" in result["fieldPreviewText"]
    assert result["relatedClasses"] == ["CResTGA"]
    assert result["relatedClassAddress"] == "0x401000"
    assert result["referenceCount"] == 2


def test_search_classes_enriches_related_structure_and_references(monkeypatch: pytest.MonkeyPatch) -> None:
    provider = SearchEverythingToolProvider()

    class FakeSymbolType:
        CLASS = "CLASS"

    fake_ghidra_program = ModuleType("ghidra.program")
    fake_ghidra_model = ModuleType("ghidra.program.model")
    fake_ghidra_symbol = ModuleType("ghidra.program.model.symbol")
    setattr(fake_ghidra_symbol, "SymbolType", FakeSymbolType)

    monkeypatch.setitem(sys.modules, "ghidra.program", fake_ghidra_program)
    monkeypatch.setitem(sys.modules, "ghidra.program.model", fake_ghidra_model)
    monkeypatch.setitem(sys.modules, "ghidra.program.model.symbol", fake_ghidra_symbol)

    struct_obj = object()
    monkeypatch.setattr(
        search_module,
        "collect_structures",
        lambda _program: [
            {
                "name": "CResDDS",
                "categoryPath": "/Res",
                "description": "DDS resource",
                "length": 80,
                "numComponents": 2,
                "structure": struct_obj,
            },
        ],
    )
    monkeypatch.setattr(
        search_module,
        "collect_structure_fields",
        lambda _structure: [
            {"offset": 0, "name": "header", "type": "DDSHeader", "comment": ""},
            {"offset": 4, "name": "pixels", "type": "byte *", "comment": ""},
        ],
    )
    monkeypatch.setattr(
        search_module,
        "collect_symbols",
        lambda _program, symbol_type=None, limit=None: [
            {
                "name": "CResDDS",
                "address": "0x405000",
                "namespace": "global",
                "source": "USER_DEFINED",
                "isPrimary": True,
                "isExternalEntryPoint": False,
            },
        ] if symbol_type == FakeSymbolType.CLASS else [],
    )
    monkeypatch.setattr(
        provider,
        "_collect_reference_summary",
        lambda _program, _address, max_refs=3: {
            "referenceCount": 1,
            "referencesPreview": [{"fromAddress": "0x406000", "function": "CreateDDS", "type": "UNCONDITIONAL_CALL"}],
        },
    )

    results = provider._search_classes(cast(Any, object()), ["CResDDS"], "auto", False, 0.7, {}, 10)

    assert len(results) == 1
    result = results[0]
    assert result["relatedStructure"] == "CResDDS"
    assert result["relatedStructureLength"] == 80
    assert "header@0x0:DDSHeader" in result["relatedStructureFieldPreviewText"]
    assert result["referenceCount"] == 1