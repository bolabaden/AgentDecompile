from __future__ import annotations

import pytest

from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
from tests.helpers import parse_single_text_content_json


@pytest.mark.asyncio
async def test_import_file_rejects_enable_version_control_request_for_local_imports() -> None:
    provider = ProjectToolProvider()

    response = await provider.call_tool(
        "import-file",
        {"path": "C:/example/test.exe", "enableVersionControl": True},
    )
    payload = parse_single_text_content_json(response)

    assert payload["success"] is False
    assert payload["versionControlRequested"] is True
    assert payload["versionControlEnabled"] is False
    assert "shared-project version control" in payload["error"]