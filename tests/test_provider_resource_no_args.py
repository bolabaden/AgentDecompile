"""Unit tests verifying resource-exposed tools handle no-args calls without erroring.

MCP resources call tools with no arguments (or only programPath). Every tool in
TOOLS_RESOURCE_SESSION_SCOPED / TOOLS_RESOURCE_PROGRAM_SCOPED must not require
parameters at either the schema level or the handler level.
"""
from __future__ import annotations

import pytest

from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider
from agentdecompile_cli.mcp_server.providers.suggestions import SuggestionToolProvider
from tests.helpers import parse_single_text_content_json


# ---------------------------------------------------------------------------
# suggest
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_suggest_no_args_returns_available_types() -> None:
    """suggest with no args returns available suggestion types, not an error."""
    provider = SuggestionToolProvider()
    result = await provider.call_tool("suggest", {})
    payload = parse_single_text_content_json(result)
    # create_success_response does not inject success:True; check the actual payload keys
    assert "success" not in payload or payload["success"] is not False, f"Got error: {payload}"
    assert "availableSuggestionTypes" in payload, f"Expected availableSuggestionTypes in {payload}"
    types_list = payload["availableSuggestionTypes"]
    assert isinstance(types_list, list)
    assert len(types_list) > 0
    assert "function_name" in types_list


# ---------------------------------------------------------------------------
# import-binary
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_import_binary_no_args_returns_open_programs() -> None:
    """import-binary with no path returns open-programs listing, not an error."""
    provider = ImportExportToolProvider()
    result = await provider.call_tool("import-binary", {})
    payload = parse_single_text_content_json(result)
    assert "success" not in payload or payload["success"] is not False, f"Got error: {payload}"
    assert "openPrograms" in payload, f"Expected openPrograms in {payload}"
    assert "note" in payload
    assert "path" in str(payload["note"]).lower()


# ---------------------------------------------------------------------------
# change-processor
# ---------------------------------------------------------------------------

@pytest.mark.unit
@pytest.mark.asyncio
async def test_change_processor_no_args_no_program_returns_error() -> None:
    """change-processor with no args and no program returns a program-missing error, not a language error."""
    provider = ImportExportToolProvider()
    result = await provider.call_tool("change-processor", {})
    payload = parse_single_text_content_json(result)
    # Without a loaded program the handler errors with a program-missing message,
    # NOT a "Required parameter missing: language" message.
    assert payload["success"] is False
    error = (payload.get("error") or "").lower()
    assert "language" not in error, f"Should not complain about missing language; got: {error}"
    assert "program" in error, f"Expected program-missing error; got: {error}"
