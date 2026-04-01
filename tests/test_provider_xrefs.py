"""Unit tests for CrossReferencesToolProvider – no-address (index) path."""
from __future__ import annotations

import pytest

from agentdecompile_cli.mcp_server.providers.xrefs import CrossReferencesToolProvider
from tests.helpers import parse_single_text_content_json


@pytest.mark.unit
@pytest.mark.asyncio
async def test_get_references_no_program_returns_error() -> None:
    """get-references with no program loaded returns a recognisable error, not a crash."""
    provider = CrossReferencesToolProvider()
    result = await provider.call_tool("get-references", {})
    payload = parse_single_text_content_json(result)
    assert payload["success"] is False
    assert "program" in (payload.get("error") or "").lower()


@pytest.mark.unit
@pytest.mark.asyncio
async def test_list_cross_references_no_program_returns_error() -> None:
    """list-cross-references with no program loaded returns a recognisable error, not a crash."""
    provider = CrossReferencesToolProvider()
    result = await provider.call_tool("list-cross-references", {})
    payload = parse_single_text_content_json(result)
    assert payload["success"] is False
    assert "program" in (payload.get("error") or "").lower()


@pytest.mark.unit
def test_list_tools_addressorsymbol_not_required() -> None:
    """Both tools must advertise addressOrSymbol as optional (not in 'required' list)."""
    provider = CrossReferencesToolProvider()
    tools = provider.list_tools()
    tool_map = {t.name: t for t in tools}

    for tool_name in ("get-references", "list-cross-references"):
        assert tool_name in tool_map, f"{tool_name} not in list_tools()"
        schema = tool_map[tool_name].inputSchema
        required = schema.get("required", [])
        assert "addressOrSymbol" not in required, (
            f"{tool_name}: addressOrSymbol must not be required; got required={required}"
        )
        assert "address" not in required, (
            f"{tool_name}: address must not be required; got required={required}"
        )
