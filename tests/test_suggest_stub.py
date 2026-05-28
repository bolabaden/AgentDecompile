from __future__ import annotations

import json

import pytest

from agentdecompile_cli.mcp_server.providers.suggestions import SuggestionToolProvider


@pytest.mark.unit
@pytest.mark.asyncio
async def test_suggest_no_args_lists_available_types() -> None:
    provider = SuggestionToolProvider()
    result = await provider._handle({})
    payload = json.loads(result[0].text)
    assert "function_name" in payload["availableSuggestionTypes"]
    assert payload.get("note")


@pytest.mark.unit
@pytest.mark.asyncio
async def test_suggest_with_type_raises_not_implemented() -> None:
    provider = SuggestionToolProvider()
    with pytest.raises(ValueError, match="not implemented"):
        await provider._handle(
            {
                "suggestiontype": "function_name",
                "programpath": "/bin.exe",
                "addressorsymbol": "0x401000",
            }
        )


@pytest.mark.unit
def test_suggest_tool_description_notes_not_implemented() -> None:
    provider = SuggestionToolProvider()
    tools = provider.list_tools()
    suggest = next(tool for tool in tools if tool.name == "suggest")
    assert "Not implemented" in suggest.description
