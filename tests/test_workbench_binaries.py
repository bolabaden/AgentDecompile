from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard.actions import catalog
from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router
from agentdecompile_recovery.corpus.store import connect

pytestmark = pytest.mark.unit


def _client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    db = tmp_path / "corpus.sqlite"
    connect(db).close()
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path / "work"))
    app = FastAPI()
    app.include_router(create_dashboard_router())
    return TestClient(app)


def test_workbench_has_dropzone_and_manage_controls() -> None:
    app = FastAPI()
    app.include_router(create_dashboard_router())
    page = TestClient(app).get("/dashboard")
    assert page.status_code == 200
    assert 'id="wb-drop"' in page.text
    assert "Drop binaries here" in page.text
    assert 'id="wb-bin-path"' in page.text
    assert 'id="wb-bin-remove"' in page.text


def test_add_binary_from_path_registers_store_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    binary = tmp_path / "demo.exe"
    binary.write_bytes(b"MZ")
    added = client.post(
        "/dashboard/api/workbench/binaries",
        json={"path": str(binary), "slug": "demo.exe", "role": "member"},
    )
    assert added.status_code == 200
    body = added.json()
    assert body["ok"] is True
    assert body["binary"]["slug"] == "demo.exe"
    listed = client.get("/dashboard/api/workbench/binaries")
    slugs = [row["slug"] for row in listed.json()["binaries"]]
    assert "demo.exe" in slugs


def test_remove_binary_requires_confirm_then_deletes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    binary = tmp_path / "gone.exe"
    binary.write_bytes(b"MZ")
    client.post(
        "/dashboard/api/workbench/binaries",
        json={"path": str(binary), "slug": "gone.exe"},
    )
    denied = client.request(
        "DELETE",
        "/dashboard/api/workbench/binaries/gone.exe",
        json={"confirm": False},
    )
    assert denied.status_code == 400
    removed = client.request(
        "DELETE",
        "/dashboard/api/workbench/binaries/gone.exe",
        json={"confirm": True},
    )
    assert removed.status_code == 200
    slugs = [row["slug"] for row in client.get("/dashboard/api/workbench/binaries").json()["binaries"]]
    assert "gone.exe" not in slugs


def test_upload_binary_is_saved_and_listed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    uploaded = client.post(
        "/dashboard/api/workbench/binaries",
        files={"file": ("upload.bin", b"MZ\x00demo", "application/octet-stream")},
        data={"slug": "upload.bin"},
    )
    assert uploaded.status_code == 200
    assert uploaded.json()["ok"] is True
    slugs = [row["slug"] for row in client.get("/dashboard/api/workbench/binaries").json()["binaries"]]
    assert "upload.bin" in slugs
    saved = Path(uploaded.json()["binary"]["repo"])
    assert saved.is_file()
    assert saved.read_bytes().startswith(b"MZ")


def test_edit_binary_updates_role_and_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    binary = tmp_path / "edit.exe"
    binary.write_bytes(b"MZ")
    client.post(
        "/dashboard/api/workbench/binaries",
        json={"path": str(binary), "slug": "edit.exe", "role": "member"},
    )
    edited = client.patch(
        "/dashboard/api/workbench/binaries/edit.exe",
        json={"role": "donor", "label": "layout source"},
    )
    assert edited.status_code == 200
    assert edited.json()["binary"]["role"] == "donor"


def test_catalog_includes_cli_and_acquisition_surfaces() -> None:
    catalog._ACTIONS = None
    ids = {item.id for item in catalog.list_actions()}
    assert any(item.startswith("cli.") for item in ids)
    assert "cli.tool" in ids or "cli.ghidrecomp" in ids or "cli.alias" in ids
    assert "mcp.decompile-function" in ids
    assert "recover.acquisition-query" in ids
    assert "corpus.add-binary" in ids
    assert "corpus.remove-binary" in ids
