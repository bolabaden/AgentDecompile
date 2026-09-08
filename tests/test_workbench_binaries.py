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
    from agentdecompile_recovery.corpus.dashboard.react_api import ASSETS

    app = FastAPI()
    app.include_router(create_dashboard_router())
    page = TestClient(app).get("/dashboard")
    assert page.status_code == 200
    react_entry = ASSETS / "index.html"
    if react_entry.is_file():
        assert 'id="root"' in page.text
        assert "/dashboard/static/react/assets/" in page.text
    else:
        assert 'id="wb-drop"' in page.text
        assert 'id="wb-sessions"' in page.text
        assert 'role="tablist"' in page.text
        assert "workbench.css" in page.text
        assert "workbench-app.js" in page.text
        assert 'class="workbench-page"' in page.text
    js = Path("src/agentdecompile_recovery/corpus/dashboard/static/workbench-app.js").read_text(
        encoding="utf-8"
    )
    assert "wb-bin-folder-global" in js
    assert "wb-bin-file-global" in js
    assert "triggerFileUpload" in js
    if react_entry.is_file():
        assert "Save As" in js or "Save As…" in js
        assert "wb-save-as-form" in js or "wb-modal" in js
        assert "wb-quick-actions" in js
        return
    assert 'id="wb-browse"' in page.text
    assert 'id="wb-shared-host"' in page.text
    assert 'id="wb-shared-url"' in page.text
    assert 'id="wb-dossier"' in page.text
    assert "wb-chrome" in page.text
    assert 'id="wb-menubar"' in page.text
    assert "Save As" in js or "Save As…" in js
    assert "wb-save-as-form" in js or "wb-modal" in js
    assert 'id="wb-atlas"' in page.text
    assert 'id="wb-report"' in page.text
    assert 'id="wb-graph"' in page.text
    assert 'id="wb-tools"' in page.text
    assert 'id="wb-mcp-list"' not in page.text
    assert "wb-quick-actions" in js
    assert 'id="wb-pipeline"' in page.text
    assert 'id="wb-review"' in page.text


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


def test_overview_redirects_to_workbench(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, tmp_path)
    res = client.get("/dashboard/overview", follow_redirects=False)
    assert res.status_code == 302
    loc = res.headers["location"]
    assert loc.startswith("/dashboard?")
    assert "overview" in loc


def test_overview_fragment_scopes_to_slugs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    a = tmp_path / "a.exe"
    b = tmp_path / "b.exe"
    a.write_bytes(b"MZ")
    b.write_bytes(b"MZ")
    client.post("/dashboard/api/workbench/binaries", json={"path": str(a), "slug": "a.exe"})
    client.post("/dashboard/api/workbench/binaries", json={"path": str(b), "slug": "b.exe"})
    frag = client.get("/dashboard/overview-fragment", params={"slug": "a.exe"})
    assert frag.status_code == 200
    assert "a.exe" in frag.text
    assert "b.exe" not in frag.text


def test_overview_fragment_lists_ghidra_programs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    frag = client.get(
        "/dashboard/overview-fragment",
        params=[("slug", "a.exe"), ("program", "k1_xbox_default.xbe")],
    )
    assert frag.status_code == 200
    assert "k1_xbox_default.xbe" in frag.text
    assert "Project programs" in frag.text
    assert "Program in the open Ghidra project" in frag.text


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


def _write_gpr(root: Path, stem: str = "Demo") -> Path:
    gpr = root / f"{stem}.gpr"
    gpr.write_text('<?xml version="1.0" encoding="UTF-8"?><FILE_INFO/>\n')
    rep = root / f"{stem}.rep"
    (rep / "idata").mkdir(parents=True)
    (rep / "Game.exe").mkdir()
    (rep / "Game.exe" / "propertyList.xml").write_text("<PROPERTIES/>\n")
    return gpr


def test_register_gpr_project_lists_programs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    gpr = _write_gpr(tmp_path)
    added = client.post(
        "/dashboard/api/workbench/binaries",
        json={"path": str(gpr), "slug": "Demo"},
    )
    assert added.status_code == 200
    body = added.json()
    assert body["ok"] is True
    assert body["binary"]["kind"] == "ghidra-project"
    assert "Game.exe" in body["binary"]["programs"]


def test_register_project_folder_and_shared_urls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    folder = tmp_path / "proj"
    folder.mkdir()
    _write_gpr(folder, "SharedSrc")
    from_folder = client.post(
        "/dashboard/api/workbench/binaries",
        json={"path": str(folder)},
    )
    assert from_folder.status_code == 200
    assert from_folder.json()["binary"]["kind"] == "ghidra-project"
    ghidra = client.post(
        "/dashboard/api/workbench/binaries",
        json={"url": "ghidra://127.0.0.1:13300/Odyssey/k1.exe", "slug": "odyssey-k1"},
    )
    assert ghidra.status_code == 200
    assert ghidra.json()["binary"]["kind"] == "shared-project"
    assert ghidra.json()["binary"]["repo"].startswith("ghidra://")
    http = client.post(
        "/dashboard/api/workbench/binaries",
        json={"url": "http://127.0.0.1:13100/Repo", "slug": "http-repo"},
    )
    assert http.status_code == 200
    assert http.json()["binary"]["kind"] == "shared-project"
    assert http.json()["binary"]["repo"].startswith("http://")
    assert "k1.exe" in ghidra.json()["binary"]["programs"]


def test_browse_lists_pe_binaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, tmp_path)
    work = tmp_path / "work"
    folder = work / "downloads"
    folder.mkdir(parents=True)
    exe = folder / "witcher-6.exe"
    exe.write_bytes(b"MZ")
    dll = folder / "helper.dll"
    dll.write_bytes(b"MZ")
    txt = folder / "readme.txt"
    txt.write_text("ignore me")
    listed = client.get("/dashboard/api/workbench/browse", params={"path": str(folder)})
    assert listed.status_code == 200
    body = listed.json()
    names = {row["name"] for row in body["entries"]}
    kinds = {row["name"]: row["kind"] for row in body["entries"]}
    assert "witcher-6.exe" in names
    assert "helper.dll" in names
    assert kinds["witcher-6.exe"] == "binary"
    assert "readme.txt" not in names
    opened = client.get("/dashboard/api/workbench/browse", params={"path": str(exe)})
    assert opened.status_code == 200
    assert opened.json()["kind"] == "binary"


def test_browse_lists_local_gpr(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, tmp_path)
    folder = tmp_path / "work" / "proj"
    folder.mkdir(parents=True)
    _write_gpr(folder, "Demo")
    listed = client.get("/dashboard/api/workbench/browse", params={"path": str(folder)})
    assert listed.status_code == 200
    names = [row["name"] for row in listed.json()["entries"]]
    assert "Demo.gpr" in names
    kinds = {row["name"]: row["kind"] for row in listed.json()["entries"]}
    assert kinds["Demo.gpr"] == "gpr"
    assert "Game.exe" in listed.json()["entries"][names.index("Demo.gpr")]["programs"]


def test_upload_gpr_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, tmp_path)
    uploaded = client.post(
        "/dashboard/api/workbench/binaries",
        files={"file": ("Demo.gpr", b"<FILE_INFO/>", "application/xml")},
    )
    assert uploaded.status_code == 400
    assert "Name.rep" in uploaded.json()["error"]


def test_classify_local_ghidra_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, tmp_path)
    gpr = _write_gpr(tmp_path, "Local")
    classified = client.get(
        "/dashboard/api/workbench/classify",
        params={"locator": f"ghidra:{gpr}?Game.exe"},
    )
    assert classified.status_code == 200
    assert classified.json()["kind"] == "ghidra-project"
    assert "Game.exe" in classified.json()["programs"]
