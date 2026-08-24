from __future__ import annotations

import json

from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.callgraph import CallGraphToolProvider


class FakeFunction:
    def __init__(self, name: str, address: str) -> None:
        self._name = name
        self._address = address

    def getName(self) -> str:
        return self._name

    def getEntryPoint(self) -> str:
        return self._address

    def getCallingFunctions(self, _monitor: object) -> list[FakeFunction]:
        return [FakeFunction("Caller", "00402000")]

    def getCalledFunctions(self, _monitor: object) -> list[FakeFunction]:
        return [FakeFunction("Callee", "00403000")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("arguments", "expected_mode", "result_key", "expected_name", "expected_address"),
    [
        ({"mode": "callers"}, "callers", "callers", "Caller", "00402000"),
        ({"mode": "callees"}, "callees", "callees", "Callee", "00403000"),
        ({"direction": "calling"}, "callers", "callers", "Caller", "00402000"),
        ({"direction": "called"}, "callees", "callees", "Callee", "00403000"),
        ({"mode": "callers_decomp"}, "callers_decomp", "callers", "Caller", "00402000"),
        ({"mode": "common_callers"}, "common_callers", "callers", "Caller", "00402000"),
    ],
)
async def test_nonvisual_modes_return_structured_call_relationships(
    monkeypatch: pytest.MonkeyPatch,
    arguments: dict[str, str],
    expected_mode: str,
    result_key: str,
    expected_name: str,
    expected_address: str,
) -> None:
    target = FakeFunction("Target", "00401000")
    provider = CallGraphToolProvider(program_info=SimpleNamespace(program=object()))

    monkeypatch.setattr(provider, "_require_program", lambda: None)
    monkeypatch.setattr(provider, "_resolve_function", lambda _value, program=None: target)
    monkeypatch.setattr(provider, "_get_function_manager", lambda _program: object())

    visual_calls: list[dict[str, object]] = []

    class VisualGraphMustNotRun:
        def generate_for_mcp(self, **_kwargs: object) -> object:
            visual_calls.append(_kwargs)
            raise AssertionError("nonvisual call-graph modes must use structured handlers")

    monkeypatch.setattr(provider, "_get_callgraph_tool", lambda: VisualGraphMustNotRun())

    result = await provider._handle({"function": "0x00401000", **arguments})
    payload = json.loads(result[0].text)

    assert payload["mode"] == expected_mode
    assert payload[result_key] == [{"name": expected_name, "address": expected_address}]
    assert payload["count"] == 1
    assert visual_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["graph", "tree"])
async def test_visual_modes_still_use_callgraph_renderer(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    provider = CallGraphToolProvider(program_info=SimpleNamespace(program=object()))
    monkeypatch.setattr(provider, "_require_program", lambda: None)
    visual_calls: list[dict[str, object]] = []

    class VisualGraph:
        def generate_for_mcp(self, **kwargs: object) -> object:
            visual_calls.append(kwargs)
            return SimpleNamespace(
                function_name="Target-00401000",
                direction=SimpleNamespace(value="calling"),
                display_type=SimpleNamespace(value="flow"),
                graph="graph output",
                mermaid_url=None,
            )

    monkeypatch.setattr(provider, "_get_callgraph_tool", lambda: VisualGraph())

    result = await provider._handle({"function": "0x00401000", "mode": mode})
    payload = json.loads(result[0].text)

    assert payload["graph"] == "graph output"
    assert len(visual_calls) == 1
