from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.suggestions import SuggestionToolProvider
from tests.helpers import parse_single_text_content_json


def _make_provider(with_program: bool = False) -> SuggestionToolProvider:
    if not with_program:
        return SuggestionToolProvider(program_info=None)
    pi = MagicMock()
    pi.program = MagicMock()
    pi.program.getName = MagicMock(return_value="TestProgram")
    return SuggestionToolProvider(program_info=pi)


def _parse(resp):
    return parse_single_text_content_json(resp)


class TestSuggestionProviderSchema:
    def test_suggest_tool_advertised(self):
        p = _make_provider()
        names = {t.name for t in p.list_tools()}
        assert "suggest" in names


class TestSuggestionProviderHandlers:
    def test_handler_key_present(self):
        assert "suggest" in SuggestionToolProvider.HANDLERS


class TestSuggestionProviderValidation:
    @pytest.mark.asyncio
    async def test_no_program_returns_error(self):
        p = _make_provider(with_program=False)
        with pytest.raises(ValueError):
            await p.call_tool("suggest", {"suggestionType": "function_name", "function": "main"})
