from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.dissect import GetFunctionAioToolProvider
from agentdecompile_cli.mcp_server.response_formatter import _render_get_function


pytestmark = pytest.mark.unit


class _FakeFunction:
    def __init__(self, name: str) -> None:
        self._name = name
        self._address = f"addr_{name}"
        self._callers: list[_FakeFunction] = []
        self._callees: list[_FakeFunction] = []

    def getName(self) -> str:
        return self._name

    def getEntryPoint(self) -> str:
        return self._address

    def getSignature(self) -> str:
        return f"void {self._name}(void)"

    def getCallingFunctions(self, monitor):
        return iter(self._callers)

    def getCalledFunctions(self, monitor):
        return iter(self._callees)


def _link_callers(target: _FakeFunction, *callers: _FakeFunction) -> None:
    target._callers.extend(callers)


def _link_callees(target: _FakeFunction, *callees: _FakeFunction) -> None:
    target._callees.extend(callees)


def test_collect_related_tree_caps_expanded_callers_at_nine() -> None:
    provider = GetFunctionAioToolProvider(program_info=SimpleNamespace(program=None))
    target = _FakeFunction("target")
    callers = [_FakeFunction(f"caller_{idx}") for idx in range(1, 5)]
    second_level = [_FakeFunction(f"caller_{idx}_{child}") for idx in range(1, 5) for child in range(1, 4)]

    _link_callers(target, *callers)
    for idx, caller in enumerate(callers, start=1):
        base = (idx - 1) * 3
        _link_callers(caller, *second_level[base : base + 3])

    tree, expanded = provider._collect_related_tree(
        target,
        direction="callers",
        depth=2,
        branching=3,
        max_details=9,
    )

    assert [node["name"] for node in tree] == ["caller_1", "caller_2", "caller_3"]
    assert [func.getName() for func in expanded] == [
        "caller_1",
        "caller_1_1",
        "caller_1_2",
        "caller_1_3",
        "caller_2",
        "caller_2_1",
        "caller_2_2",
        "caller_2_3",
        "caller_3",
    ]
    assert tree[0]["children"]
    assert tree[1]["children"]
    assert "children" not in tree[2]


def test_collect_related_tree_prevents_cycles() -> None:
    provider = GetFunctionAioToolProvider(program_info=SimpleNamespace(program=None))
    target = _FakeFunction("target")
    callee = _FakeFunction("callee")

    _link_callees(target, callee)
    _link_callees(callee, target)

    tree, expanded = provider._collect_related_tree(
        target,
        direction="callees",
        depth=2,
        branching=3,
        max_details=9,
    )

    assert [node["name"] for node in tree] == ["callee"]
    assert [func.getName() for func in expanded] == ["callee"]
    assert "children" not in tree[0]


def test_render_get_function_includes_tree_and_related_sections() -> None:
    payload = {
        "targetFunction": {
            "name": "target",
            "address": "00401000",
            "signature": "void target(void)",
            "metadata": {"size": 4, "returnType": "void", "callingConvention": "__cdecl", "parameters": []},
            "namespace": {"path": "(global)", "segments": []},
            "decompilation": "void target(void) {}",
            "disassembly": {"instructions": [], "count": 0, "truncated": False},
            "comments": {},
            "labels": [],
            "callers": [],
            "callees": [],
            "crossReferences": [],
            "outboundReferences": [],
            "tags": [],
            "bookmarks": [],
            "stackFrame": {"variables": [], "frameSize": 0},
            "memoryBlock": {},
        },
        "callGraphTree": {
            "callers": [{"name": "caller_one", "address": "00402000", "children": [{"name": "caller_two", "address": "00403000"}]}],
            "callees": [{"name": "callee_one", "address": "00404000"}],
            "callerDepth": 2,
            "calleeDepth": 2,
            "callerBranching": 3,
            "calleeBranching": 3,
            "expandedCallerCount": 1,
            "expandedCalleeCount": 1,
        },
        "callerDetails": [
            {
                "name": "caller_one",
                "address": "00402000",
                "signature": "void caller_one(void)",
                "relationship": "caller",
                "metadata": {"size": 4, "returnType": "void", "callingConvention": "__cdecl", "parameters": []},
                "namespace": {"path": "(global)", "segments": []},
                "decompilation": "void caller_one(void) {}",
                "disassembly": {"instructions": [], "count": 0, "truncated": False},
                "comments": {},
                "labels": [],
                "callers": [],
                "callees": [],
                "crossReferences": [],
                "outboundReferences": [],
                "tags": [],
                "bookmarks": [],
                "stackFrame": {"variables": [], "frameSize": 0},
                "memoryBlock": {},
            }
        ],
        "calleeDetails": [
            {
                "name": "callee_one",
                "address": "00404000",
                "signature": "void callee_one(void)",
                "relationship": "callee",
                "metadata": {"size": 4, "returnType": "void", "callingConvention": "__cdecl", "parameters": []},
                "namespace": {"path": "(global)", "segments": []},
                "decompilation": "void callee_one(void) {}",
                "disassembly": {"instructions": [], "count": 0, "truncated": False},
                "comments": {},
                "labels": [],
                "callers": [],
                "callees": [],
                "crossReferences": [],
                "outboundReferences": [],
                "tags": [],
                "bookmarks": [],
                "stackFrame": {"variables": [], "frameSize": 0},
                "memoryBlock": {},
            }
        ],
    }

    rendered = _render_get_function(payload)

    assert "## Function: `target`" in rendered
    assert "## Expanded Call Graph" in rendered
    assert "### Caller Tree" in rendered
    assert "### Callee Tree" in rendered
    assert "## Expanded Caller Details (1)" in rendered
    assert "## Expanded Callee Details (1)" in rendered
    assert "### Function: `caller_one` (caller)" in rendered
    assert "### Function: `callee_one` (callee)" in rendered
