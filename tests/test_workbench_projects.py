from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

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


def _write_gpr(root: Path, stem: str = "Demo") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    gpr = root / f"{stem}.gpr"
    gpr.write_text('<?xml version="1.0" encoding="UTF-8"?><FILE_INFO/>\n')
    rep = root / f"{stem}.rep"
    (rep / "idata").mkdir(parents=True)
    (rep / "Game.exe").mkdir()
    (rep / "Game.exe" / "propertyList.xml").write_text("<PROPERTIES/>\n")
    return gpr


def _write_shared_fs(root: Path) -> Path:
    repos = root / "repos"
    index = repos / "_demo" / "~index.dat"
    index.parent.mkdir(parents=True)
    index.write_text(
        "VERSION=1\n/\n/Game\n  00000001:Game.exe:abc\nNEXT-ID:2\nMD5:0\n",
        encoding="utf-8",
    )
    (repos / "users").write_text("alice:secret:*\n", encoding="utf-8")
    return repos


def test_inspect_local_gpr_lists_programs_and_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    gpr = _write_gpr(tmp_path)
    inspected = client.get("/dashboard/api/workbench/inspect", params={"locator": str(gpr)})
    assert inspected.status_code == 200
    body = inspected.json()
    assert body["kind"] == "ghidra-project"
    assert body["access"] == "local"
    assert "Game.exe" in body["programs"]
    assert body["gpr_stat"]["exists"] is True
    assert body["rep_stat"]["exists"] is True
    assert body["files"]


def test_inspect_shared_fs_hides_user_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    repos = _write_shared_fs(tmp_path)
    inspected = client.get("/dashboard/api/workbench/inspect", params={"locator": str(repos)})
    assert inspected.status_code == 200
    body = inspected.json()
    assert body["kind"] == "shared-fs"
    assert body["access"] == "fs"
    assert "Game.exe" in body["programs"]
    assert body["users"] == ["alice"]
    dumped = str(body)
    assert "secret" not in dumped


def test_resolve_drop_finds_gpr_by_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    gpr = _write_gpr(work, "Dropped")
    resolved = client.post(
        "/dashboard/api/workbench/resolve-drop",
        json={"name": "Dropped.gpr"},
    )
    assert resolved.status_code == 200
    assert Path(resolved.json()["locator"]).name == gpr.name


def test_create_project_writes_gpr_and_rep(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    created = client.post("/dashboard/api/workbench/projects", json={"name": "Fresh"})
    assert created.status_code == 200
    body = created.json()
    assert body["ok"] is True
    assert Path(body["gpr"]).is_file()
    assert Path(body["rep"]).is_dir()


def test_sessions_start_with_a_draft_tab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    listed = client.get("/dashboard/api/workbench/sessions")
    assert listed.status_code == 200
    body = listed.json()
    assert body["sessions"]
    assert body["sessions"][0]["kind"] == "draft"
    renamed = client.put(
        "/dashboard/api/workbench/sessions",
        json={
            "active": body["active"],
            "sessions": [
                {
                    "id": body["sessions"][0]["id"],
                    "title": "Lab",
                    "kind": "draft",
                    "locator": "",
                }
            ],
        },
    )
    assert renamed.status_code == 200
    assert renamed.json()["sessions"][0]["title"] == "Lab"


def test_users_file_alone_is_not_a_shared_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    decoy = tmp_path / "not-repos"
    decoy.mkdir()
    (decoy / "users").write_text("alice:secret:*\n", encoding="utf-8")
    inspected = client.get("/dashboard/api/workbench/inspect", params={"locator": str(decoy)})
    assert inspected.status_code == 400
    assert inspected.json()["kind"] == "empty"


def test_register_shared_fs_and_inspect_http(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    repos = _write_shared_fs(tmp_path)
    added = client.post(
        "/dashboard/api/workbench/binaries",
        json={"path": str(repos), "slug": "server-fs"},
    )
    assert added.status_code == 200
    body = added.json()
    assert body["ok"] is True
    assert body["binary"]["kind"] == "shared-fs"
    assert "Game.exe" in body["binary"]["programs"]
    http = client.get(
        "/dashboard/api/workbench/inspect",
        params={"locator": "ghidra://127.0.0.1:1/Repo/Game.exe"},
    )
    assert http.status_code == 200
    remote = http.json()
    assert remote["kind"] == "shared-project"
    assert remote["access"] == "http"
    assert remote["reachable"] is False
    assert "Game.exe" in remote["programs"]


def test_resolve_drop_rep_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    gpr = _write_gpr(work, "Packed")
    resolved = client.post(
        "/dashboard/api/workbench/resolve-drop",
        json={
            "name": "Packed.rep",
            "relativePaths": ["Packed.rep/Game.exe/propertyList.xml"],
        },
    )
    assert resolved.status_code == 200
    assert Path(resolved.json()["locator"]).name == gpr.name


def test_browse_marks_shared_fs_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    repos = _write_shared_fs(tmp_path)
    listed = client.get("/dashboard/api/workbench/browse", params={"path": str(repos.parent)})
    assert listed.status_code == 200
    kinds = {row["name"]: row["kind"] for row in listed.json()["entries"]}
    assert kinds[repos.name] == "shared-fs"


def test_browse_roots_mark_env_shared_fs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repos = _write_shared_fs(tmp_path)
    monkeypatch.setenv("AGENT_DECOMPILE_GHIDRA_REPOS_DIR", str(repos))
    client = _client(monkeypatch, tmp_path)
    listed = client.get("/dashboard/api/workbench/browse")
    assert listed.status_code == 200
    kinds = {row["path"]: row["kind"] for row in listed.json()["entries"]}
    assert kinds[str(repos.resolve())] == "shared-fs"


def test_empty_session_put_keeps_a_draft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    wiped = client.put("/dashboard/api/workbench/sessions", json={"active": "", "sessions": []})
    assert wiped.status_code == 200
    assert wiped.json()["sessions"]
    assert wiped.json()["sessions"][0]["kind"] == "draft"


def test_save_as_http_to_local_keeps_origin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    saved = client.post(
        "/dashboard/api/workbench/save-as",
        json={
            "locator": "ghidra://127.0.0.1:1/Repo/Game.exe",
            "target": "ghidra-project",
            "name": "FromHttp",
        },
    )
    assert saved.status_code == 200
    body = saved.json()
    assert body["kind"] == "ghidra-project"
    assert body["access"] == "local"
    assert Path(body["gpr"]).is_file()
    assert body["origin"]["source_kind"] == "shared-project"
    assert "Game.exe" in body["programs"]
    assert "secret" not in str(body)


def test_save_as_local_to_shared_fs_and_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    gpr = _write_gpr(work, "Packed")
    exported = client.post(
        "/dashboard/api/workbench/save-as",
        json={"locator": str(gpr), "target": "shared-fs", "name": "PackedOut"},
    )
    assert exported.status_code == 200
    body = exported.json()
    assert body["kind"] == "shared-fs"
    assert "Game.exe" in body["programs"]
    checkout = client.post(
        "/dashboard/api/workbench/save-as",
        json={"locator": body["locator"], "target": "ghidra-project", "name": "FromFs"},
    )
    assert checkout.status_code == 200
    assert checkout.json()["kind"] == "ghidra-project"
    assert checkout.json()["origin"]["source_kind"] == "shared-fs"


def test_save_as_local_to_http_writes_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    gpr = _write_gpr(work, "Packed")
    linked = client.post(
        "/dashboard/api/workbench/save-as",
        json={
            "locator": str(gpr),
            "target": "shared-project",
            "name": "PackedRemote",
            "url": "ghidra://127.0.0.1:1/Repo",
        },
    )
    assert linked.status_code == 200
    body = linked.json()
    assert body["kind"] == "shared-project"
    assert body["local_checkout"]
    assert Path(str(body["local_checkout"])).is_file()


def test_save_without_locator_creates_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    saved = client.post("/dashboard/api/workbench/save", json={"locator": ""})
    assert saved.status_code == 200
    assert saved.json()["kind"] == "ghidra-project"
    assert Path(saved.json()["gpr"]).is_file()
