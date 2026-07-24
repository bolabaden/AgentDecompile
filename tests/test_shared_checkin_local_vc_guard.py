"""Guards: shared-server checkout must not create local-only version control.

Regression for LFG step 5: DomainFile.checkin was versioning ``/tmp/agentdecompile_shared/.../versioned``
while the Ghidra Server tip stayed at v1, so search-symbols found 0 labels after MCP restart.

Follow-up: after refusing local VC, private analyzeHeadless stubs still hide RemoteFileSystem items —
promote deletes the stub and binds a versioned checkout.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agentdecompile_cli.mcp_server.providers.project import ProjectToolProvider
from agentdecompile_cli.mcp_server.session_context import SESSION_CONTEXTS


@pytest.mark.unit
def test_ensure_shared_domain_file_refuses_local_add_to_version_control(monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = "test-shared-vc-guard"
    SESSION_CONTEXTS.set_project_handle(
        session_id,
        {
            "mode": "shared-server",
            "server_host": "127.0.0.1",
            "server_port": 26100,
            "repository_name": "agentrepo",
            "repository_adapter": object(),
        },
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.project.get_current_mcp_session_id",
        lambda: session_id,
    )

    domain_file = MagicMock()
    domain_file.isVersioned.return_value = False
    domain_file.addToVersionControl = MagicMock()

    provider = ProjectToolProvider.__new__(ProjectToolProvider)
    provider._manager = None
    provider._ensure_shared_domain_file_registered_for_version_control(domain_file, "/fixture.exe")

    domain_file.addToVersionControl.assert_not_called()
    domain_file.save.assert_not_called()


@pytest.mark.unit
def test_ensure_private_domain_file_still_adds_to_version_control(monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = "test-private-vc-ok"
    SESSION_CONTEXTS.set_project_handle(session_id, {"mode": "local", "project": object()})
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.project.get_current_mcp_session_id",
        lambda: session_id,
    )

    # Avoid importing real Ghidra TaskMonitor in unit context.
    fake_tm = SimpleNamespace(DUMMY=object())
    monkeypatch.setitem(__import__("sys").modules, "ghidra.util.task", SimpleNamespace(TaskMonitor=fake_tm))

    domain_file = MagicMock()
    domain_file.isVersioned.side_effect = [False, True]
    domain_file.addToVersionControl = MagicMock()
    domain_file.save = MagicMock()

    provider = ProjectToolProvider.__new__(ProjectToolProvider)
    provider._ensure_shared_domain_file_registered_for_version_control(domain_file, "/local.exe")

    domain_file.addToVersionControl.assert_called_once()


@pytest.mark.unit
def test_resolve_shared_checkout_prefers_versioned_over_private_stub() -> None:
    provider = ProjectToolProvider.__new__(ProjectToolProvider)
    private = MagicMock(name="private")
    private.isCheckedOut.return_value = False
    private.isVersioned.return_value = False
    versioned = MagicMock(name="versioned")
    versioned.isCheckedOut.return_value = False
    versioned.isVersioned.return_value = True

    provider._get_domain_file_with_path_variants = MagicMock(return_value=private)  # type: ignore[method-assign]
    provider._find_domain_file_shared_item_in_tree = MagicMock(return_value=versioned)  # type: ignore[method-assign]

    got = provider._resolve_shared_checkout_domain_file(MagicMock(), "/fixture.exe", "fixture.exe")
    assert got is versioned


@pytest.mark.unit
def test_ensure_shared_calls_promote_when_project_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    session_id = "test-shared-promote"
    adapter = MagicMock()
    SESSION_CONTEXTS.set_project_handle(
        session_id,
        {
            "mode": "shared-server",
            "server_host": "127.0.0.1",
            "server_port": 26100,
            "repository_name": "agentrepo",
            "repository_adapter": adapter,
        },
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.project.get_current_mcp_session_id",
        lambda: session_id,
    )

    domain_file = MagicMock()
    domain_file.isVersioned.return_value = False
    domain_file.addToVersionControl = MagicMock()

    promoted = MagicMock()
    promoted.isVersioned.return_value = True

    provider = ProjectToolProvider.__new__(ProjectToolProvider)
    provider._manager = SimpleNamespace(ghidra_project=object())
    provider._promote_private_to_shared_versioned_checkout = MagicMock(return_value=promoted)  # type: ignore[method-assign]

    provider._ensure_shared_domain_file_registered_for_version_control(domain_file, "/fixture.exe")

    provider._promote_private_to_shared_versioned_checkout.assert_called_once()
    domain_file.addToVersionControl.assert_not_called()


@pytest.mark.unit
def test_promote_refreshes_project_data_after_stub_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    """After deleting a private stub, ProjectData.refresh(True) must run before getFile."""
    fake_tm = SimpleNamespace(DUMMY=object())
    monkeypatch.setitem(__import__("sys").modules, "ghidra.util.task", SimpleNamespace(TaskMonitor=fake_tm))
    monkeypatch.setitem(
        __import__("sys").modules,
        "ghidra.framework.store",
        SimpleNamespace(CheckoutType=SimpleNamespace(NORMAL=object(), EXCLUSIVE=object())),
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.project.get_current_mcp_session_id",
        lambda: "test-refresh-after-stub",
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.project.repository_adapter_folder_candidates",
        lambda folder: ["/"],
    )

    private = MagicMock(name="private")
    private.isVersioned.return_value = False
    private.isCheckedOut.return_value = False
    private.delete = MagicMock()

    versioned = MagicMock(name="versioned")
    versioned.isVersioned.return_value = True
    versioned.isCheckedOut.return_value = False
    versioned.checkout = MagicMock()

    project_data = MagicMock()
    project_data.refresh = MagicMock()

    ghidra_project = MagicMock()
    ghidra_project.getProjectData.return_value = project_data
    ghidra_project.getProject.return_value = None

    adapter = MagicMock()
    adapter.isConnected.return_value = True
    adapter.getItem.return_value = object()

    provider = ProjectToolProvider.__new__(ProjectToolProvider)
    provider._manager = SimpleNamespace(ghidra_project=ghidra_project)
    provider._ensure_ghidra_project_linked_to_repository = MagicMock(return_value=ghidra_project)  # type: ignore[method-assign]
    provider._release_session_programs_for_domain_file = MagicMock()  # type: ignore[method-assign]
    resolve_calls: list[str] = []

    def _resolve(_pd: object, _path: str, _name: str) -> MagicMock:
        resolve_calls.append("resolve")
        # After stub delete + refresh, expose the RemoteFS shadow.
        return versioned if len(resolve_calls) >= 1 and private.delete.called else private

    provider._resolve_shared_checkout_domain_file = MagicMock(side_effect=_resolve)  # type: ignore[method-assign]

    got = provider._promote_private_to_shared_versioned_checkout(
        ghidra_project=ghidra_project,
        repository_adapter=adapter,
        program_path="/fixture.exe",
        exclusive=False,
        domain_file_hint=private,
    )

    private.delete.assert_called_once()
    project_data.refresh.assert_called_with(True)
    versioned.checkout.assert_called_once()
    assert got is versioned
    # Prefer DomainFile.checkout after refresh; adapter checkout is a fallback only.
    adapter.checkout.assert_not_called()
    assert len(resolve_calls) >= 1

@pytest.mark.unit
def test_ensure_linked_reopens_after_convert(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_tm = SimpleNamespace(DUMMY=object())
    monkeypatch.setitem(__import__("sys").modules, "ghidra.util.task", SimpleNamespace(TaskMonitor=fake_tm))

    project_data = MagicMock()
    project_data.getRepository.return_value = None
    project_data.convertProjectToShared = MagicMock()

    original = MagicMock(name="original_project")
    original.getProjectData.return_value = project_data
    reopened = MagicMock(name="reopened_project")

    provider = ProjectToolProvider.__new__(ProjectToolProvider)
    provider._manager = SimpleNamespace(ghidra_project=original, pyghidra_context_ref=None, shared_checkout_project_bound=False)
    provider._reopen_ghidra_project_after_shared_convert = MagicMock(return_value=reopened)  # type: ignore[method-assign]

    adapter = MagicMock()
    adapter.isConnected.return_value = True
    got = provider._ensure_ghidra_project_linked_to_repository(original, adapter)

    project_data.convertProjectToShared.assert_called_once()
    provider._reopen_ghidra_project_after_shared_convert.assert_called_once_with(original)
    assert got is reopened


@pytest.mark.unit
def test_shared_repository_item_version_helper() -> None:
    from agentdecompile_cli.mcp_server.providers.import_export import ImportExportToolProvider

    session_id = "test-server-ver"
    item = MagicMock()
    item.getVersion.return_value = 3
    adapter = MagicMock()
    adapter.getItem.return_value = item
    SESSION_CONTEXTS.set_project_handle(
        session_id,
        {
            "mode": "shared-server",
            "server_host": "127.0.0.1",
            "server_port": 26100,
            "repository_name": "agentrepo",
            "repository_adapter": adapter,
        },
    )

    provider = ImportExportToolProvider.__new__(ImportExportToolProvider)

    # Patch session id used by helper
    import agentdecompile_cli.mcp_server.providers.import_export as ie

    original = ie.get_current_mcp_session_id
    ie.get_current_mcp_session_id = lambda: session_id
    try:
        assert provider._shared_repository_item_version("/sort_fixture.exe") == 3
        adapter.getItem.assert_called_with("/", "sort_fixture.exe")
    finally:
        ie.get_current_mcp_session_id = original
