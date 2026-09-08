from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router
from agentdecompile_recovery.corpus.dashboard.workbench import _slug_from_disk_path, list_functions
from agentdecompile_recovery.corpus.store import connect

pytestmark = pytest.mark.unit

REPOS = Path("/home/brunner56/biodecompwarehouse/repos")
LOCAL_GPR = Path("/home/brunner56/biodecompwarehouse/projects/agentdecompile.gpr")
NWN = [
    (
        "nwtoolset-win32",
        Path(
            "/run/media/brunner56/MyBook/SteamLibrary/steamapps/common/"
            "Neverwinter Nights/bin/win32/nwtoolset.exe"
        ),
    ),
    (
        "nwserver-win32",
        Path(
            "/run/media/brunner56/MyBook/SteamLibrary/steamapps/common/"
            "Neverwinter Nights/bin/win32/nwserver.exe"
        ),
    ),
    (
        "nwmain-win32",
        Path(
            "/run/media/brunner56/MyBook/SteamLibrary/steamapps/common/"
            "Neverwinter Nights/bin/win32/nwmain.exe"
        ),
    ),
    (
        "nwmain-macos",
        Path(
            "/run/media/brunner56/MyBook/SteamLibrary/steamapps/common/"
            "Neverwinter Nights/bin/macos/nwmain.app/Contents/MacOS/nwmain"
        ),
    ),
    (
        "nwmain-linux-x86",
        Path(
            "/run/media/brunner56/MyBook/SteamLibrary/steamapps/common/"
            "Neverwinter Nights/bin/linux-x86/nwmain-linux"
        ),
    ),
    (
        "nwserver-linux-x86",
        Path(
            "/run/media/brunner56/MyBook/SteamLibrary/steamapps/common/"
            "Neverwinter Nights/bin/linux-x86/nwserver-linux"
        ),
    ),
    (
        "nwserver-linux-arm64",
        Path(
            "/run/media/brunner56/MyBook/SteamLibrary/steamapps/common/"
            "Neverwinter Nights/bin/linux-arm64/nwserver-linux"
        ),
    ),
    (
        "nwmain-linux-arm64",
        Path(
            "/run/media/brunner56/MyBook/SteamLibrary/steamapps/common/"
            "Neverwinter Nights/bin/linux-arm64/nwmain-linux"
        ),
    ),
]


def test_slug_from_disk_path_uses_platform_dir() -> None:
    assert _slug_from_disk_path(Path("/bin/win32/nwmain.exe"), "") == "nwmain-win32"
    assert _slug_from_disk_path(Path("/bin/linux-x86/nwmain-linux"), "") == "nwmain-linux-x86"
    assert _slug_from_disk_path(Path("/bin/linux-arm64/nwmain-linux"), "") == "nwmain-linux-arm64"


def test_list_functions_without_logical_name_table(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "corpus.sqlite"
    con = connect(db)
    con.execute(
        "INSERT INTO binary(repo_path, slug, role) VALUES(?,?,?)",
        (str(tmp_path / "nwmain.exe"), "nwmain-win32", "member"),
    )
    con.commit()
    con.close()
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path / "work"))
    listed = list_functions("nwmain-win32")
    assert listed["ok"] is True
    assert listed["results"] == []
    assert "logical_name" not in str(listed.get("error") or "")


def _client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> TestClient:
    db = tmp_path / "corpus.sqlite"
    connect(db).close()
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path / "work"))
    (tmp_path / "work").mkdir()
    app = FastAPI()
    app.include_router(create_dashboard_router())
    return TestClient(app)


def test_shared_fs_folder_converts_to_gpr_and_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if not REPOS.is_dir():
        pytest.skip(f"shared-fs folder missing: {REPOS}")
    client = _client(monkeypatch, tmp_path)
    inspected = client.get("/dashboard/api/workbench/inspect", params={"locator": str(REPOS)})
    assert inspected.status_code == 200
    body = inspected.json()
    assert body["kind"] == "shared-fs"
    assert body["access"] == "fs"
    assert body["program_count"] >= 1

    dest = tmp_path / "work" / "converted"
    saved = client.post(
        "/dashboard/api/workbench/save-as",
        json={
            "locator": str(REPOS),
            "target": "ghidra-project",
            "name": "repos-from-shared",
            "dest": str(dest),
        },
    )
    assert saved.status_code == 200
    gpr = saved.json()
    assert gpr["kind"] == "ghidra-project"
    assert Path(gpr["gpr"]).is_file()
    assert Path(gpr["rep"]).is_dir()
    assert gpr["origin"]["source_kind"] == "shared-fs"
    assert set(body["programs"]).issubset(set(gpr["programs"] or []))

    exported = client.post(
        "/dashboard/api/workbench/save-as",
        json={
            "locator": gpr["locator"],
            "target": "shared-fs",
            "name": "repos-as-shared",
            "dest": str(tmp_path / "work" / "shared-out"),
        },
    )
    assert exported.status_code == 200
    assert exported.json()["kind"] == "shared-fs"


def test_local_gpr_and_http_shared_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _client(monkeypatch, tmp_path)
    if LOCAL_GPR.is_file():
        local = client.get("/dashboard/api/workbench/inspect", params={"locator": str(LOCAL_GPR)})
        assert local.status_code == 200
        assert local.json()["kind"] == "ghidra-project"
        locator = str(LOCAL_GPR)
    else:
        created = client.post("/dashboard/api/workbench/projects", json={"name": "LocalKind"})
        assert created.status_code == 200
        locator = created.json()["locator"]

    http = client.get(
        "/dashboard/api/workbench/inspect",
        params={"locator": "ghidra://127.0.0.1:13100/odyssey"},
    )
    assert http.status_code == 200
    remote = http.json()
    assert remote["kind"] == "shared-project"
    assert remote["access"] == "http"

    checkout = client.post(
        "/dashboard/api/workbench/save-as",
        json={
            "locator": "ghidra://127.0.0.1:13100/odyssey",
            "target": "ghidra-project",
            "name": "odyssey-http-checkout",
            "dest": str(tmp_path / "work" / "http-out"),
        },
    )
    assert checkout.status_code == 200
    assert checkout.json()["kind"] == "ghidra-project"
    assert Path(checkout.json()["gpr"]).is_file()

    linked = client.post(
        "/dashboard/api/workbench/save-as",
        json={
            "locator": locator,
            "target": "shared-project",
            "name": "local-as-http",
            "url": "ghidra://127.0.0.1:13100/odyssey",
        },
    )
    assert linked.status_code == 200
    assert linked.json()["kind"] == "shared-project"


def test_nwn_binaries_import_into_project_then_save_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    present = [(slug, path) for slug, path in NWN if path.is_file()]
    if len(present) < 8:
        pytest.skip("Neverwinter Nights binaries are not on this machine")
    if not REPOS.is_dir():
        pytest.skip(f"shared-fs folder missing: {REPOS}")
    client = _client(monkeypatch, tmp_path)
    opened = client.get("/dashboard/api/workbench/inspect", params={"locator": str(REPOS)})
    assert opened.status_code == 200
    saved = client.post(
        "/dashboard/api/workbench/save-as",
        json={
            "locator": str(REPOS),
            "target": "ghidra-project",
            "name": "nwn-host",
            "dest": str(tmp_path / "work" / "nwn-host"),
        },
    )
    assert saved.status_code == 200
    project_slug = saved.json()["slug"]
    slugs = []
    for slug, path in present:
        added = client.post(
            "/dashboard/api/workbench/binaries",
            json={"path": str(path), "slug": slug, "role": "member"},
        )
        assert added.status_code == 200, added.text
        assert added.json()["ok"] is True
        assert added.json()["binary"]["slug"] == slug
        slugs.append(slug)
    assert len(slugs) == 8

    sessions = client.get("/dashboard/api/workbench/sessions").json()
    sid = sessions["sessions"][0]["id"]
    written = client.put(
        "/dashboard/api/workbench/sessions",
        json={
            "active": sid,
            "sessions": [
                {
                    "id": sid,
                    "title": "nwn-host",
                    "kind": "ghidra-project",
                    "locator": saved.json()["locator"],
                    "projectSlug": project_slug,
                    "imports": slugs,
                }
            ],
        },
    )
    assert written.status_code == 200
    persist = client.post(
        "/dashboard/api/workbench/save",
        json={"locator": saved.json()["locator"]},
    )
    assert persist.status_code == 200
    reloaded = client.get("/dashboard/api/workbench/sessions").json()
    imports = reloaded["sessions"][0].get("imports") or []
    assert set(slugs) <= set(imports)
    listed = {row["slug"] for row in client.get("/dashboard/api/workbench/binaries").json()["binaries"]}
    assert set(slugs) <= listed


def test_nwn_paths_get_platform_slugs_without_requested_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    present = [path for _slug, path in NWN if path.is_file()]
    if len(present) < 8:
        pytest.skip("Neverwinter Nights binaries are not on this machine")
    client = _client(monkeypatch, tmp_path)
    got = []
    for path in present:
        added = client.post("/dashboard/api/workbench/binaries", json={"path": str(path)})
        assert added.status_code == 200, added.text
        assert added.json()["ok"] is True
        got.append(added.json()["binary"]["slug"])
    assert len(set(got)) == 8
    assert "nwmain-linux-x86" in got
    assert "nwmain-linux-arm64" in got
    assert got.count("nwmain-linux") == 0
    funcs = client.get("/dashboard/api/workbench/functions", params={"slug": got[0]})
    assert funcs.status_code == 200
    body = funcs.json()
    assert "logical_name" not in str(body.get("error") or "")
    assert body["ok"] is True
    assert body["results"] == []
