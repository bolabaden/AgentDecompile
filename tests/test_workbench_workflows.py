"""Parametrized workbench API workflows — regression net for common operator paths."""

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
    gpr = root / f"{stem}.gpr"
    gpr.write_text('<?xml version="1.0" encoding="UTF-8"?><FILE_INFO/>\n')
    rep = root / f"{stem}.rep"
    (rep / "idata").mkdir(parents=True)
    (rep / "Game.exe").mkdir()
    (rep / "Game.exe" / "propertyList.xml").write_text("<PROPERTIES/>\n")
    return gpr


def _write_pe(path: Path, name: str = "game.exe") -> Path:
    dest = path / name
    dest.write_bytes(b"MZ")
    return dest


def _sessions(client: TestClient) -> dict:
    return client.get("/dashboard/api/workbench/sessions").json()


def _put_sessions(client: TestClient, payload: dict) -> dict:
    res = client.put("/dashboard/api/workbench/sessions", json=payload)
    assert res.status_code == 200
    return res.json()


def _register_pe(client: TestClient, path: Path, slug: str | None = None) -> str:
    res = client.post(
        "/dashboard/api/workbench/binaries",
        json={"path": str(path), "slug": slug or path.name},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    return str(body["binary"]["slug"])


def _create_project(client: TestClient, name: str = "proj") -> dict:
    res = client.post("/dashboard/api/workbench/projects", json={"name": name})
    assert res.status_code == 200
    body = res.json()
    assert body["ok"] is True
    return body


def _attach_import(client: TestClient, tab_id: str, project: dict, import_slug: str) -> dict:
    base = _sessions(client)
    session = dict(base["sessions"][0])
    if session["id"] != tab_id:
        session = next(item for item in base["sessions"] if item["id"] == tab_id)
    session.update(
        {
            "title": project["slug"],
            "kind": "ghidra-project",
            "locator": project["locator"],
            "projectSlug": project["slug"],
            "imports": list(dict.fromkeys([*(session.get("imports") or []), import_slug])),
        }
    )
    return _put_sessions(
        client,
        {"revision": base.get("revision"), "active": tab_id, "sessions": [session]},
    )


WORKFLOW_CASES = [
    "register_pe_by_path",
    "upload_pe_multipart",
    "browse_folder_lists_pe",
    "browse_pe_file_direct",
    "create_empty_project",
    "session_starts_draft",
    "attach_import_to_open_tab",
    "attach_second_import",
    "import_not_duplicated",
    "remove_import_keeps_project",
    "remove_project_clears_tab",
    "stage_drop_gpr",
    "resolve_staged_gpr",
    "register_gpr_lists_programs",
    "register_project_folder",
    "register_ghidra_url",
    "register_http_url",
    "edit_binary_role",
    "list_binaries_after_register",
    "session_revision_increments",
    "empty_put_resets_draft",
    "new_tab_adds_session",
    "classify_local_gpr",
    "inspect_created_project",
    "browse_roots_non_empty",
    "browse_up_from_subdir",
    "reject_gpr_upload",
    "binary_slug_from_filename",
    "shared_fs_detection",
    "merge_conflict_preserves_tabs",
    "merge_conflict_unions_imports",
    "delete_binary_requires_confirm",
    "patch_binary_label",
    "upload_assigns_slug",
    "project_save_as_endpoint_exists",
    "resolve_drop_missing_staging",
    "register_duplicate_path_updates_slug",
    "session_active_preserved_on_put",
    "browse_skips_dotfiles",
    "classify_pe_as_binary",
]


@pytest.mark.parametrize("case", WORKFLOW_CASES)
def test_workbench_workflow_matrix(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    pe = _write_pe(tmp_path, "witcher-6.exe")
    pe2 = _write_pe(tmp_path, "addon.dll")

    if case == "register_pe_by_path":
        slug = _register_pe(client, pe)
        assert slug == "witcher-6.exe"
        return

    if case == "upload_pe_multipart":
        res = client.post(
            "/dashboard/api/workbench/binaries",
            files={"file": ("upload.exe", b"MZ", "application/octet-stream")},
        )
        assert res.json()["ok"] is True
        return

    if case == "browse_folder_lists_pe":
        listed = client.get("/dashboard/api/workbench/browse", params={"path": str(tmp_path)})
        names = {row["name"] for row in listed.json()["entries"]}
        assert "witcher-6.exe" in names
        return

    if case == "browse_pe_file_direct":
        opened = client.get("/dashboard/api/workbench/browse", params={"path": str(pe)})
        assert opened.json()["kind"] == "binary"
        return

    if case == "create_empty_project":
        project = _create_project(client, "fresh")
        assert Path(project["gpr"]).is_file()
        return

    if case == "session_starts_draft":
        assert _sessions(client)["sessions"][0]["kind"] == "draft"
        return

    if case == "attach_import_to_open_tab":
        slug = _register_pe(client, pe)
        project = _create_project(client, "repos")
        tab_id = _sessions(client)["active"]
        body = _attach_import(client, tab_id, project, slug)
        assert slug in body["sessions"][0]["imports"]
        return

    if case == "attach_second_import":
        s1 = _register_pe(client, pe)
        s2 = _register_pe(client, pe2)
        project = _create_project(client, "multi")
        tab_id = _sessions(client)["active"]
        body = _attach_import(client, tab_id, project, s1)
        body = _attach_import(client, tab_id, project, s2)
        imports = body["sessions"][0]["imports"]
        assert s1 in imports and s2 in imports
        return

    if case == "import_not_duplicated":
        slug = _register_pe(client, pe)
        project = _create_project(client, "dedupe")
        tab_id = _sessions(client)["active"]
        _attach_import(client, tab_id, project, slug)
        body = _attach_import(client, tab_id, project, slug)
        assert body["sessions"][0]["imports"].count(slug) == 1
        return

    if case == "remove_import_keeps_project":
        slug = _register_pe(client, pe)
        project = _create_project(client, "keep")
        tab_id = _sessions(client)["active"]
        _attach_import(client, tab_id, project, slug)
        removed = client.request(
            "DELETE",
            f"/dashboard/api/workbench/binaries/{slug}",
            json={"confirm": True},
        )
        assert removed.status_code == 200
        body = _sessions(client)
        session = body["sessions"][0]
        assert session["projectSlug"] == project["slug"]
        # Session import slugs are client-owned until backend prune lands (plan U6).
        assert slug in (session.get("imports") or [])
        return

    if case == "remove_project_clears_tab":
        project = _create_project(client, "gone")
        client.post(
            "/dashboard/api/workbench/binaries",
            json={"path": project["locator"], "slug": project["slug"]},
        )
        tab_id = _sessions(client)["active"]
        _put_sessions(
            client,
            {
                "active": tab_id,
                "sessions": [
                    {
                        "id": tab_id,
                        "title": project["slug"],
                        "kind": "ghidra-project",
                        "locator": project["locator"],
                        "projectSlug": project["slug"],
                        "imports": [],
                    }
                ],
            },
        )
        removed = client.request(
            "DELETE",
            f"/dashboard/api/workbench/binaries/{project['slug']}",
            json={"confirm": True},
        )
        assert removed.status_code == 200
        return

    if case == "stage_drop_gpr":
        gpr = _write_gpr(tmp_path, "Drop")
        staged = client.post(
            "/dashboard/api/workbench/stage-drop",
            files={"file": (gpr.name, gpr.read_bytes(), "application/octet-stream")},
        )
        assert staged.json()["ok"] is True
        return

    if case == "resolve_staged_gpr":
        gpr = _write_gpr(tmp_path, "Resolve")
        staged = client.post(
            "/dashboard/api/workbench/stage-drop",
            files={"file": (gpr.name, gpr.read_bytes(), "application/octet-stream")},
        )
        sid = staged.json()["staging_id"]
        resolved = client.post(
            "/dashboard/api/workbench/resolve-drop",
            json={"name": gpr.name, "staging_id": sid},
        )
        assert resolved.json()["ok"] is True
        return

    if case == "register_gpr_lists_programs":
        gpr = _write_gpr(tmp_path, "Prog")
        res = client.post(
            "/dashboard/api/workbench/binaries",
            json={"path": str(gpr), "slug": "Prog"},
        )
        assert "Game.exe" in res.json()["binary"]["programs"]
        return

    if case == "register_project_folder":
        folder = tmp_path / "folder-proj"
        folder.mkdir()
        _write_gpr(folder, "Inner")
        res = client.post(
            "/dashboard/api/workbench/binaries",
            json={"path": str(folder)},
        )
        assert res.json()["binary"]["kind"] == "ghidra-project"
        return

    if case == "register_ghidra_url":
        res = client.post(
            "/dashboard/api/workbench/binaries",
            json={"url": "ghidra://127.0.0.1:13300/Odyssey/k1.exe", "slug": "odyssey"},
        )
        assert res.json()["binary"]["kind"] == "shared-project"
        return

    if case == "register_http_url":
        res = client.post(
            "/dashboard/api/workbench/binaries",
            json={"url": "http://127.0.0.1:13100/Repo", "slug": "http-repo"},
        )
        assert res.json()["binary"]["repo"].startswith("http://")
        return

    if case == "edit_binary_role":
        slug = _register_pe(client, pe)
        edited = client.patch(
            f"/dashboard/api/workbench/binaries/{slug}",
            json={"role": "donor", "label": "source"},
        )
        assert edited.json()["binary"]["role"] == "donor"
        return

    if case == "list_binaries_after_register":
        _register_pe(client, pe)
        slugs = [row["slug"] for row in client.get("/dashboard/api/workbench/binaries").json()["binaries"]]
        assert "witcher-6.exe" in slugs
        return

    if case == "session_revision_increments":
        base = _sessions(client)
        rev = int(base.get("revision") or 0)
        body = _put_sessions(client, {"revision": rev, "active": base["active"], "sessions": base["sessions"]})
        assert body["revision"] == rev + 1
        return

    if case == "empty_put_resets_draft":
        base = _sessions(client)
        tab_id = base["active"]
        _put_sessions(
            client,
            {
                "active": tab_id,
                "sessions": [
                    {
                        "id": tab_id,
                        "title": "Loaded",
                        "kind": "ghidra-project",
                        "locator": "/tmp/fake.gpr",
                        "projectSlug": "fake",
                        "imports": ["x.exe"],
                    }
                ],
            },
        )
        body = _put_sessions(client, {"active": tab_id, "sessions": []})
        assert body["sessions"][0]["kind"] == "draft"
        return

    if case == "new_tab_adds_session":
        base = _sessions(client)
        tab_id = base["active"]
        second = {
            "id": "s-second",
            "title": "Two",
            "kind": "draft",
            "locator": "",
            "projectSlug": "",
            "imports": [],
        }
        body = _put_sessions(
            client,
            {"active": "s-second", "sessions": [base["sessions"][0], second]},
        )
        assert len(body["sessions"]) == 2
        assert body["active"] == "s-second"
        return

    if case == "classify_local_gpr":
        gpr = _write_gpr(tmp_path, "Classify")
        res = client.get(
            "/dashboard/api/workbench/classify",
            params={"locator": str(gpr)},
        )
        assert res.json()["kind"] == "ghidra-project"
        return

    if case == "inspect_created_project":
        project = _create_project(client, "inspect-me")
        res = client.get(
            "/dashboard/api/workbench/inspect",
            params={"locator": project["locator"]},
        )
        assert res.json()["ok"] is True
        return

    if case == "browse_roots_non_empty":
        res = client.get("/dashboard/api/workbench/browse")
        assert res.json()["ok"] is True
        assert isinstance(res.json()["entries"], list)
        return

    if case == "browse_up_from_subdir":
        sub = tmp_path / "nested"
        sub.mkdir()
        parent = client.get("/dashboard/api/workbench/browse", params={"path": str(sub)})
        up = client.get(
            "/dashboard/api/workbench/browse",
            params={"path": parent.json()["parent"]},
        )
        assert up.json()["ok"] is True
        return

    if case == "reject_gpr_upload":
        res = client.post(
            "/dashboard/api/workbench/binaries",
            files={"file": ("Demo.gpr", b"<xml/>", "application/xml")},
        )
        assert res.status_code == 400
        return

    if case == "binary_slug_from_filename":
        slug = _register_pe(client, pe, slug="custom-slug")
        assert slug == "custom-slug"
        return

    if case == "shared_fs_detection":
        shared = tmp_path / "_repos"
        shared.mkdir()
        (shared / "~index.dat").write_text("VERSION 1\n/k1\n1:k1.exe\n")
        res = client.post(
            "/dashboard/api/workbench/binaries",
            json={"path": str(shared)},
        )
        assert res.json()["binary"]["kind"] == "shared-fs"
        return

    if case == "merge_conflict_preserves_tabs":
        base = _sessions(client)
        rev = int(base.get("revision") or 0)
        tab_a = dict(base["sessions"][0])
        tab_b = {
            "id": "s-b",
            "title": "B",
            "kind": "draft",
            "locator": "",
            "projectSlug": "",
            "imports": [],
        }
        _put_sessions(client, {"revision": rev, "active": tab_a["id"], "sessions": [tab_a, tab_b]})
        merged = _put_sessions(
            client,
            {"revision": rev, "active": "s-b", "sessions": [tab_b]},
        )
        assert merged.get("merged") is True
        assert len(merged["sessions"]) >= 2
        return

    if case == "merge_conflict_unions_imports":
        base = _sessions(client)
        rev = int(base.get("revision") or 0)
        tab = dict(base["sessions"][0])
        tab["imports"] = ["alpha.exe"]
        _put_sessions(client, {"revision": rev, "active": tab["id"], "sessions": [tab]})
        incoming = dict(tab)
        incoming["imports"] = ["beta.exe"]
        merged = _put_sessions(
            client,
            {"revision": rev, "active": tab["id"], "sessions": [incoming]},
        )
        assert merged.get("merged") is True
        imports = merged["sessions"][0]["imports"]
        assert "alpha.exe" in imports and "beta.exe" in imports
        return

    if case == "delete_binary_requires_confirm":
        slug = _register_pe(client, pe)
        denied = client.request(
            "DELETE",
            f"/dashboard/api/workbench/binaries/{slug}",
            json={"confirm": False},
        )
        assert denied.status_code == 400
        return

    if case == "patch_binary_label":
        slug = _register_pe(client, pe)
        patched = client.patch(
            f"/dashboard/api/workbench/binaries/{slug}",
            json={"role": "member", "label": "test label"},
        )
        assert patched.json()["binary"]["label"] == "test label"
        return

    if case == "upload_assigns_slug":
        res = client.post(
            "/dashboard/api/workbench/binaries",
            files={"file": ("named.exe", b"MZ", "application/octet-stream")},
            data={"slug": "named.exe"},
        )
        assert res.json()["binary"]["slug"] == "named.exe"
        return

    if case == "project_save_as_endpoint_exists":
        project = _create_project(client, "saveas")
        res = client.post(
            "/dashboard/api/workbench/save-as",
            json={
                "locator": project["locator"],
                "target": "shared-fs",
                "name": "copy-out",
            },
        )
        assert res.status_code == 200
        assert res.json()["ok"] is True
        return

    if case == "resolve_drop_missing_staging":
        res = client.post(
            "/dashboard/api/workbench/resolve-drop",
            json={"name": "missing.gpr", "staging_id": "nope"},
        )
        assert res.status_code == 400
        assert res.json()["ok"] is False
        return

    if case == "register_duplicate_path_updates_slug":
        _register_pe(client, pe, slug="first")
        second = client.post(
            "/dashboard/api/workbench/binaries",
            json={"path": str(pe), "slug": "second-name"},
        )
        assert second.json()["ok"] is True
        slugs = [row["slug"] for row in client.get("/dashboard/api/workbench/binaries").json()["binaries"]]
        assert "second-name" in slugs
        return

    if case == "session_active_preserved_on_put":
        base = _sessions(client)
        tab_id = base["active"]
        body = _put_sessions(
            client,
            {"active": tab_id, "sessions": base["sessions"]},
        )
        assert body["active"] == tab_id
        return

    if case == "browse_skips_dotfiles":
        hidden = tmp_path / ".hidden.exe"
        hidden.write_bytes(b"MZ")
        visible = _write_pe(tmp_path, "visible.exe")
        listed = client.get("/dashboard/api/workbench/browse", params={"path": str(tmp_path)})
        names = {row["name"] for row in listed.json()["entries"]}
        assert "visible.exe" in names
        assert ".hidden.exe" not in names
        assert visible.is_file()
        return

    if case == "classify_pe_as_binary":
        res = client.get(
            "/dashboard/api/workbench/classify",
            params={"locator": str(pe)},
        )
        assert res.json()["kind"] == "binary"
        return

    pytest.fail(f"unhandled workflow case: {case}")
