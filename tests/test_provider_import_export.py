from __future__ import annotations

from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers import import_export as import_export_module
from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider
from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS
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


@pytest.mark.asyncio
async def test_repair_shared_working_copy_for_checkin_reuses_shared_checkout_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_id = "test-shared-checkin-repair"
    provider = ImportExportToolProvider()
    repo_adapter = object()
    checkout_calls: list[tuple[object, str, str, bool]] = []
    ensure_calls: list[tuple[object, str]] = []

    class DummyDomainFile:
        def isCheckedOut(self) -> bool:
            return True

    resolved_df = DummyDomainFile()

    async def _fake_checkout_shared_program(
        adapter: object,
        program_path: str,
        session_id_arg: str,
        *,
        exclusive: bool = False,
    ) -> str:
        checkout_calls.append((adapter, program_path, session_id_arg, exclusive))
        return program_path

    class StubProjectProvider(ProjectToolProvider):
        """Minimal subclass so isinstance(..., ProjectToolProvider) passes in repair flow."""

        def __init__(self) -> None:
            super().__init__(None)

        async def _checkout_shared_program(  # type: ignore[override]
            self,
            adapter: object,
            program_path: str,
            session_id_arg: str,
            *,
            exclusive: bool = False,
        ) -> str:
            return await _fake_checkout_shared_program(adapter, program_path, session_id_arg, exclusive=exclusive)

        def _ensure_shared_domain_file_registered_for_version_control(  # type: ignore[override]
            self,
            domain_file: object,
            program_path: str,
        ) -> None:
            ensure_calls.append((domain_file, program_path))

    project_provider = StubProjectProvider()
    provider._manager = SimpleNamespace(_get_project_provider=lambda: project_provider)

    monkeypatch.setattr(import_export_module, "get_current_mcp_session_id", lambda: session_id)
    monkeypatch.setattr(
        provider,
        "_resolve_domain_file_for_checkout_status",
        lambda program_path: (resolved_df, program_path),
    )

    SESSION_CONTEXTS.set_project_handle(
        session_id,
        {
            "mode": "shared-server",
            "repository_adapter": repo_adapter,
            "repository_name": "agentrepo",
            "server_host": "127.0.0.1",
        },
    )

    try:
        repaired = await provider._repair_shared_working_copy_for_checkin(
            program_path="/K1/test.exe",
            exclusive=True,
        )
    finally:
        SESSION_CONTEXTS.set_project_handle(session_id, None)

    assert repaired == (resolved_df, "/K1/test.exe")
    assert checkout_calls == [(repo_adapter, "/K1/test.exe", session_id, True)]
    assert ensure_calls == [(resolved_df, "/K1/test.exe")]
