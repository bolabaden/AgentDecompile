from __future__ import annotations

import pytest

from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider
from tests.helpers import parse_single_text_content_json


@pytest.mark.asyncio
async def test_import_binary_rejects_enable_version_control_without_shared_session(tmp_path) -> None:
    """import-binary with enableVersionControl requires shared-server context (not local-only)."""
    bin_file = tmp_path / "stub.exe"
    bin_file.write_bytes(b"MZ")

    provider = ImportExportToolProvider()

    response = await provider.call_tool(
        "import-binary",
        {"path": str(bin_file), "enableVersionControl": True},
    )
    payload = parse_single_text_content_json(response)

    assert payload["success"] is False
    assert payload["versionControlRequested"] is True
    assert payload["versionControlEnabled"] is False
    assert "shared" in (payload.get("error") or "").lower()
    assert "version" in (payload.get("error") or "").lower()
