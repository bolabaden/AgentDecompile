"""Ghidra integration tests for decompiler variable rename persistence."""

from __future__ import annotations

import json
import re
from types import SimpleNamespace
from typing import Any

import pytest

from agentdecompile_cli.mcp_server.providers.getfunction import (
    GetFunctionToolProvider,
    is_default_decompiler_var_name,
)
from tests.helpers import create_test_program_with_stack_function, ghidra_install_available

_INTEGRATION_SKIP = pytest.mark.skipif(
    not ghidra_install_available(),
    reason="GHIDRA_INSTALL_DIR not available",
)


@pytest.mark.unit
def test_ghidra_install_available_false_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    assert ghidra_install_available() is False


@pytest.fixture(scope="module")
def stack_function_program():
    builder = create_test_program_with_stack_function()
    if builder is None:
        pytest.skip("Failed to create stack-function test program")
    yield builder
    try:
        builder.dispose()
    except Exception:
        pass


def _first_default_local_name(hfunc: Any) -> str:
    for sym in hfunc.getLocalSymbolMap().getSymbols():
        name = str(sym.getName() or "")
        if is_default_decompiler_var_name(name):
            return name
    raise AssertionError("No default decompiler local variable found")


def _decompile_c(provider: GetFunctionToolProvider, program: Any, func: Any) -> str:
    from ghidra.app.decompiler import DecompInterface  # pyright: ignore[reportMissingModuleSource]
    from ghidra.util.task import TaskMonitor

    decomp = DecompInterface()
    decomp.openProgram(program)
    try:
        result = decomp.decompileFunction(func, 60, TaskMonitor.DUMMY)
        assert result is not None and result.decompileCompleted()
        decompiled = result.getDecompiledFunction()
        assert decompiled is not None
        return str(decompiled.getC() or "")
    finally:
        decomp.dispose()


@pytest.mark.integration
@_INTEGRATION_SKIP
@pytest.mark.asyncio
async def test_rename_variable_persists_in_decompiled_output(
    ghidra_initialized,
    stack_function_program,
) -> None:
    program = stack_function_program.getProgram()
    func = program.getFunctionManager().getFunctionAt(program.getAddressFactory().getDefaultAddressSpace().getAddress(0x00401000))
    assert func is not None, "test_func not created"

    provider = GetFunctionToolProvider()
    provider.program_info = SimpleNamespace(
        program=program,
        flat_api=None,
        decompiler=None,
        name=program.getName(),
        file_path="VarRenameIntegrationProgram",
    )

    hfunc = provider._decompile_high_function(program, func)
    original_name = _first_default_local_name(hfunc)
    new_name = "slotIndex"

    result = await provider._handle_manage(
        {
            "mode": "rename_variable",
            "addressOrSymbol": "test_func",
            "variableName": original_name,
            "newName": new_name,
            "format": "json",
        },
    )
    assert len(result) == 1
    payload = json.loads(result[0].text)
    assert payload.get("success") is True
    assert payload.get("action") == "rename_variable"
    assert payload.get("newName") == new_name

    decompiled = _decompile_c(provider, program, func)
    assert new_name in decompiled
    assert original_name not in decompiled or not re.search(rf"\b{re.escape(original_name)}\b", decompiled)
