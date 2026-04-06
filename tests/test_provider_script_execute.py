from __future__ import annotations

import json

import pytest

from agentdecompile_cli.mcp_server.providers.script import ScriptToolProvider


def _decode_result(result: list) -> dict:
    assert isinstance(result, list)
    assert len(result) > 0
    first = result[0]
    text = getattr(first, "text", "")
    assert isinstance(text, str)
    return json.loads(text)


@pytest.mark.asyncio
async def test_execute_expression_result() -> None:
    provider = ScriptToolProvider()
    result = await provider.call_tool("execute-script", {"code": "2 + 2"})
    data = _decode_result(result)
    assert data["success"] is True
    assert data.get("result") == "4"


@pytest.mark.asyncio
async def test_execute_multiline_with_result_variable() -> None:
    provider = ScriptToolProvider()
    result = await provider.call_tool(
        "execute-script",
        {"code": "x = 10\ny = 20\n__result__ = x * y"},
    )
    data = _decode_result(result)
    assert data["success"] is True
    assert data.get("result") == "200"


@pytest.mark.asyncio
async def test_execute_captures_stdout() -> None:
    provider = ScriptToolProvider()
    result = await provider.call_tool("execute-script", {"code": 'print("hello from test")'})
    data = _decode_result(result)
    assert data["success"] is True
    assert "hello from test" in data.get("stdout", "")


@pytest.mark.asyncio
async def test_execute_handles_zero_division() -> None:
    provider = ScriptToolProvider()
    result = await provider.call_tool("execute-script", {"code": "1/0"})
    data = _decode_result(result)
    assert data["success"] is False
    assert "ZeroDivisionError" in data.get("stderr", "")


@pytest.mark.asyncio
async def test_execute_current_program_none_without_context() -> None:
    provider = ScriptToolProvider()
    result = await provider.call_tool("execute-script", {"code": "str(currentProgram)"})
    data = _decode_result(result)
    assert data["success"] is True
    assert data.get("result") == "None"


@pytest.mark.asyncio
async def test_execute_requires_code_argument() -> None:
    provider = ScriptToolProvider()
    result = await provider.call_tool("execute-script", {"timeout": 5})
    data = _decode_result(result)
    assert data.get("success") is False
    assert "code" in data.get("error", "").lower()


@pytest.mark.asyncio
async def test_execute_serializes_dict_result() -> None:
    provider = ScriptToolProvider()
    result = await provider.call_tool("execute-script", {"code": '{"a": 1, "b": [2, 3]}'})
    data = _decode_result(result)
    assert data["success"] is True
    assert "a: 1" in data.get("result", "")
