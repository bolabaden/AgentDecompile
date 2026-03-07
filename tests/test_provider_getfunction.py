from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.getfunction import GetFunctionToolProvider
from tests.helpers import parse_single_text_content_json


class _FakeFunction:
    def __init__(self, name: str, address: str, *, param_count: int = 0, return_type: str = "void") -> None:
        self._name = name
        self._address = address
        self._param_count = param_count
        self._return_type = return_type
        self._callers: list[_FakeFunction] = []
        self._callees: list[_FakeFunction] = []
        self.calling_accesses = 0
        self.called_accesses = 0

    def getName(self) -> str:
        return self._name

    def getEntryPoint(self) -> str:
        return self._address

    def getParameterCount(self) -> int:
        return self._param_count

    def getReturnType(self) -> str:
        return self._return_type

    def getSignature(self) -> str:
        return f"{self._return_type} {self._name}()"

    def getCallingFunctions(self, monitor):
        self.calling_accesses += 1
        return iter(self._callers)

    def getCalledFunctions(self, monitor):
        self.called_accesses += 1
        return iter(self._callees)


class _FakeFunctionManager:
    def __init__(self, functions: list[_FakeFunction]) -> None:
        self._functions = functions

    def getFunctions(self, include_externals: bool):
        return iter(self._functions)

    def getFunctionCount(self) -> int:
        return len(self._functions)


class _FakeProgram:
    def __init__(self, functions: list[_FakeFunction]) -> None:
        self._functions = functions
        self._function_manager = _FakeFunctionManager(functions)

    def getFunctionManager(self):
        return self._function_manager


def _graph_accesses(functions: list[_FakeFunction]) -> int:
    return sum(func.calling_accesses + func.called_accesses for func in functions)


@pytest.mark.asyncio
async def test_match_function_reuses_cached_call_graph_index() -> None:
    shared_callee = _FakeFunction("shared_callee", "00401040")
    helper = _FakeFunction("helper", "00401080")
    target = _FakeFunction("target", "00401000", param_count=1, return_type="int")
    peer = _FakeFunction("peer", "00401020", param_count=1, return_type="int")

    target._callees = [shared_callee]
    peer._callees = [shared_callee]
    helper._callees = []
    shared_callee._callees = []

    target._callers = [helper]
    peer._callers = [helper]
    helper._callers = []
    shared_callee._callers = [target, peer]

    functions = [target, peer, shared_callee, helper]
    provider = GetFunctionToolProvider(SimpleNamespace(program=_FakeProgram(functions)))

    first_response = await provider.call_tool("match-function", {"function": "target", "mode": "similar", "maxResults": 5})
    first_payload = parse_single_text_content_json(first_response)
    first_accesses = _graph_accesses(functions)

    second_response = await provider.call_tool("match-function", {"function": "target", "mode": "similar", "maxResults": 5})
    second_payload = parse_single_text_content_json(second_response)
    second_accesses = _graph_accesses(functions)

    assert first_payload["count"] == 1
    assert first_payload["results"][0]["name"] == "peer"
    assert first_payload["cacheHit"] is False
    assert second_payload["cacheHit"] is True
    assert second_accesses == first_accesses
