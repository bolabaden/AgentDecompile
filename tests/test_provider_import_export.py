from __future__ import annotations

import sys
import types

from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider
from tests.helpers import parse_single_text_content_json


class _FakeMemory:
    def getLoadedAndInitializedAddressSet(self):
        return "loaded-address-set"


class _FakeProgram:
    def __init__(self, domain_file=None) -> None:
        self.transactions: list[tuple[str, bool | None]] = []
        self._domain_file = domain_file

    def getName(self) -> str:
        return "test_binary.exe"

    def startTransaction(self, label: str) -> int:
        self.transactions.append((label, None))
        return len(self.transactions)

    def endTransaction(self, tx: int, commit: bool) -> None:
        label, _ = self.transactions[tx - 1]
        self.transactions[tx - 1] = (label, commit)

    def getMemory(self):
        return _FakeMemory()

    def getDomainFile(self):
        return self._domain_file


class _FakeDomainFile:
    def isVersioned(self) -> bool:  # noqa: N802
        return False


class _FakeAnalysisManager:
    def __init__(self) -> None:
        self.reanalyze_calls: list[object] = []
        self.start_analysis_calls = 0

    def reAnalyzeAll(self, arg) -> None:  # noqa: N802
        self.reanalyze_calls.append(arg)

    def startAnalysis(self, monitor) -> None:  # noqa: N802
        self.start_analysis_calls += 1


def _install_analyze_stubs(monkeypatch: pytest.MonkeyPatch, *, should_ask_to_analyze: bool) -> _FakeAnalysisManager:
    manager = _FakeAnalysisManager()

    analysis_module = types.ModuleType("ghidra.app.plugin.core.analysis")

    class AutoAnalysisManager:
        @staticmethod
        def getAnalysisManager(program):  # noqa: N802
            return manager

    analysis_module.AutoAnalysisManager = AutoAnalysisManager

    task_module = types.ModuleType("ghidra.util.task")
    task_module.TaskMonitor = SimpleNamespace(DUMMY="dummy-monitor")

    program_util_module = types.ModuleType("ghidra.program.util")

    class GhidraProgramUtilities:
        @staticmethod
        def shouldAskToAnalyze(program):  # noqa: N802
            return should_ask_to_analyze

    program_util_module.GhidraProgramUtilities = GhidraProgramUtilities

    address_module = types.ModuleType("ghidra.program.model.address")

    class AddressSet:
        pass

    address_module.AddressSet = AddressSet

    monkeypatch.setitem(sys.modules, "ghidra.app.plugin.core.analysis", analysis_module)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", task_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.util", program_util_module)
    monkeypatch.setitem(sys.modules, "ghidra.program.model.address", address_module)

    return manager


@pytest.mark.asyncio
async def test_analyze_program_blocks_reanalysis_without_force(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _install_analyze_stubs(monkeypatch, should_ask_to_analyze=False)
    program = _FakeProgram()
    provider = ImportExportToolProvider(SimpleNamespace(program=program, analysis_complete=True, ghidra_analysis_complete=True))

    response = await provider.call_tool("analyze-program", {})
    payload = parse_single_text_content_json(response)

    assert payload["success"] is False
    assert payload["alreadyAnalyzed"] is True
    assert payload["forceAllowed"] is True
    assert "force=true" in payload["error"]
    assert program.transactions == []
    assert manager.start_analysis_calls == 0


@pytest.mark.asyncio
async def test_analyze_program_allows_force_reanalysis(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = _install_analyze_stubs(monkeypatch, should_ask_to_analyze=False)
    program = _FakeProgram()
    program_info = SimpleNamespace(program=program, analysis_complete=True, ghidra_analysis_complete=False)
    provider = ImportExportToolProvider(program_info)

    response = await provider.call_tool("analyze-program", {"force": True})
    payload = parse_single_text_content_json(response)

    assert payload["success"] is True
    assert payload["force"] is True
    assert manager.start_analysis_calls == 1
    assert manager.reanalyze_calls == ["loaded-address-set"]
    assert program.transactions == [("auto-analysis", True)]
    assert program_info.ghidra_analysis_complete is True


@pytest.mark.asyncio
async def test_checkout_program_fails_for_local_only_domain_files() -> None:
    provider = ImportExportToolProvider(SimpleNamespace(program=_FakeProgram(domain_file=_FakeDomainFile()), analysis_complete=True, ghidra_analysis_complete=True))

    response = await provider.call_tool("checkout-program", {})
    payload = parse_single_text_content_json(response)

    assert payload["success"] is False
    assert payload["versionControlEnabled"] is False
    assert "local-only project files" in payload["error"]


@pytest.mark.asyncio
async def test_import_binary_rejects_enable_version_control_request() -> None:
    provider = ImportExportToolProvider()

    response = await provider.call_tool(
        "import-binary",
        {"filePath": "C:/example/test.exe", "enableVersionControl": True},
    )
    payload = parse_single_text_content_json(response)

    assert payload["success"] is False
    assert payload["versionControlRequested"] is True
    assert payload["versionControlEnabled"] is False