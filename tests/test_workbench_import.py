"""Import a binary into the open project store, not a leftover staging stub."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.ghidra_db.project import ProgramEntry, storage_subdirectory
from agentdecompile_recovery.ghidra_db.store import write_index_dat, write_property_file

pytestmark = pytest.mark.unit


def _write_item(
    root: Path,
    *,
    storage_name: str = "0000000b",
    name: str = "game.exe",
    parent: str = "/",
    file_id: str = "id-b",
    payload: bytes = b"db-bytes",
    version: int = 1,
) -> ProgramEntry:
    sub = root / storage_subdirectory(storage_name)
    sub.mkdir(parents=True, exist_ok=True)
    prp = write_property_file(
        sub / f"{storage_name}.prp",
        name=name,
        parent=parent,
        file_id=file_id,
    )
    db_dir = sub / f"~{storage_name}.db"
    db_dir.mkdir(exist_ok=True)
    gbf = db_dir / f"db.{version}.gbf"
    gbf.write_bytes(payload)
    return ProgramEntry(
        name=name,
        folder_path=parent,
        file_id=file_id,
        content_type="Program",
        storage_name=storage_name,
        property_file=prp,
        database_path=gbf,
        version=version,
    )


def _shared_dest(tmp_path: Path) -> Path:
    repos = tmp_path / "repos"
    dest = repos / "_demo"
    dest.mkdir(parents=True)
    write_index_dat(dest, [])
    return repos


def _live_gpr(tmp_path: Path, name: str = "game.exe") -> Path:
    folder = tmp_path / "agentdecompile_projects"
    folder.mkdir()
    gpr = folder / "my_project.gpr"
    gpr.write_text('<?xml version="1.0" encoding="UTF-8"?><FILE_INFO/>\n')
    versioned = gpr.with_suffix(".rep") / "versioned"
    versioned.mkdir(parents=True)
    entry = _write_item(versioned, name=name, payload=b"imported-db")
    write_index_dat(versioned, [entry])
    return gpr


def test_classify_prefers_server_repo_over_stray_gpr(tmp_path: Path) -> None:
    from agentdecompile_recovery.corpus.ghidra_project import classify_locator
    from agentdecompile_recovery.ghidra_db.store import write_index_dat, write_property_file
    from agentdecompile_recovery.ghidra_db.project import storage_subdirectory

    repo = tmp_path / "_odyssey"
    repo.mkdir()
    write_index_dat(repo, [])
    storage = "0000000b"
    prp = write_property_file(
        repo / storage_subdirectory(storage) / f"{storage}.prp",
        name="nwn.exe",
        parent="/",
        file_id="id-b",
    )
    db = prp.parent / f"~{storage}.db"
    db.mkdir()
    (db / "db.1.gbf").write_bytes(b"x")
    write_index_dat(repo, [])
    from agentdecompile_recovery.ghidra_db.store import rebuild_index, list_store_programs

    rebuild_index(repo)
    (repo / "_odyssey.gpr").write_text('<?xml version="1.0" encoding="UTF-8"?><FILE_INFO/>\n')
    (repo / "_odyssey.rep" / "idata").mkdir(parents=True)
    info = classify_locator(str(repo))
    assert info["kind"] == "shared-fs", info
    assert "nwn.exe" in (info.get("programs") or [])
    assert any(item.name == "nwn.exe" for item in list_store_programs(repo))


def test_import_copies_from_live_project_when_staging_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = _shared_dest(tmp_path)
    live = _live_gpr(tmp_path)
    binary = tmp_path / "game.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AGENT_DECOMPILE_PROJECT_PATH", str(live.parent))

    def fake_call(name: str, arguments=None, *, timeout: float = 90.0):
        if name == "import-binary":
            return {
                "ok": True,
                "error": "",
                "parsed": {
                    "success": True,
                    "importedPrograms": [
                        {"programName": "game.exe", "programPath": "/game.exe"}
                    ],
                },
            }
        return {"ok": False, "error": "not a Ghidra project", "parsed": None}

    monkeypatch.setattr(
        "agentdecompile_recovery.corpus.dashboard.mcp_bridge.call_tool",
        fake_call,
    )

    from agentdecompile_recovery.corpus.dashboard.workbench import import_program_into_project
    from agentdecompile_recovery.ghidra_db.store import find_store_program

    result = import_program_into_project(str(dest), path=str(binary), name="game.exe")
    assert result["ok"] is True, result
    assert result["program"] == "game.exe"
    landed = find_store_program(dest, "game.exe")
    assert landed is not None
    assert landed.database_path.read_bytes() == b"imported-db"
    assert "staging project yet" not in str(result.get("error") or "")


def test_import_uses_mcp_name_when_requested_name_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = _shared_dest(tmp_path)
    live = _live_gpr(tmp_path, name="swkotor.exe")
    binary = tmp_path / "drop.bin"
    binary.write_bytes(b"MZ")
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AGENT_DECOMPILE_PROJECT_PATH", str(live))

    def fake_call(name: str, arguments=None, *, timeout: float = 90.0):
        if name == "import-binary":
            return {
                "ok": True,
                "error": "",
                "parsed": {
                    "success": True,
                    "importedPrograms": [
                        {"programName": "swkotor.exe", "programPath": "/swkotor.exe"}
                    ],
                },
            }
        return {"ok": False, "error": "not a Ghidra project", "parsed": None}

    monkeypatch.setattr(
        "agentdecompile_recovery.corpus.dashboard.mcp_bridge.call_tool",
        fake_call,
    )

    from agentdecompile_recovery.corpus.dashboard.workbench import import_program_into_project
    from agentdecompile_recovery.ghidra_db.store import find_store_program

    result = import_program_into_project(str(dest), path=str(binary), name="drop.bin")
    assert result["ok"] is True, result
    assert find_store_program(dest, "swkotor.exe") is not None


def _write_flat_idata(gpr: Path, *, name: str = "nwn.exe", payload: bytes = b"flat-db") -> None:
    gpr.parent.mkdir(parents=True, exist_ok=True)
    gpr.write_text('<?xml version="1.0" encoding="UTF-8"?><FILE_INFO/>\n')
    idata = gpr.with_suffix(".rep") / "idata"
    idata.mkdir(parents=True)
    (gpr.with_suffix(".rep") / "versioned").mkdir(parents=True, exist_ok=True)
    (idata / f"{name}.prp").write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<FILE_INFO>
    <BASIC_INFO>
        <STATE NAME="CONTENT_TYPE" TYPE="string" VALUE="Program" />
        <STATE NAME="FILE_ID" TYPE="string" VALUE="flat-1" />
        <STATE NAME="FILE_TYPE" TYPE="int" VALUE="0" />
    </BASIC_INFO>
</FILE_INFO>
"""
    )
    db = idata / f"~{name}.db"
    db.mkdir()
    (db / "db.1.gbf").write_bytes(payload)


def test_import_same_name_different_bytes_gets_a_new_program(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = _shared_dest(tmp_path)
    demo = dest / "_demo"
    existing = _write_item(demo, name="nwn.exe", payload=b"old-nwn")
    write_index_dat(demo, [existing])
    work = tmp_path / "work"
    staging_gpr = work / "import-staging" / "ghidra-projects" / "import-nwn.exe.gpr"
    _write_flat_idata(staging_gpr, name="nwn.exe", payload=b"new-nwn")
    binary = tmp_path / "other" / "nwn.exe"
    binary.parent.mkdir()
    binary.write_bytes(b"MZ-new")
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(work))
    monkeypatch.delenv("AGENT_DECOMPILE_PROJECT_PATH", raising=False)

    def fake_call(name: str, arguments=None, *, timeout: float = 90.0):
        if name == "import-binary":
            return {"ok": True, "error": "", "parsed": {"success": True, "importedPrograms": []}}
        return {"ok": False, "error": "not a Ghidra project", "parsed": None}

    monkeypatch.setattr(
        "agentdecompile_recovery.corpus.dashboard.mcp_bridge.call_tool",
        fake_call,
    )
    monkeypatch.setattr(
        "agentdecompile_recovery.corpus.ghidra_project.create_local_project",
        lambda name, *, work_dir, destination=None: {
            "ok": True,
            "locator": str(staging_gpr),
            "gpr": str(staging_gpr),
        },
    )

    from agentdecompile_recovery.corpus.dashboard.workbench import import_program_into_project
    from agentdecompile_recovery.ghidra_db.store import find_store_program

    result = import_program_into_project(str(dest), path=str(binary), name="nwn.exe")
    assert result["ok"] is True, result
    assert result["program"] != "nwn.exe"
    kept = find_store_program(dest, "nwn.exe")
    assert kept is not None
    assert kept.database_path.read_bytes() == b"old-nwn"
    landed = find_store_program(dest, result["program"])
    assert landed is not None
    assert landed.database_path.read_bytes() == b"new-nwn"


def test_import_copies_flat_idata_staging_into_shared_fs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = _shared_dest(tmp_path)
    work = tmp_path / "work"
    staging_gpr = work / "import-staging" / "ghidra-projects" / "import-nwn.exe.gpr"
    _write_flat_idata(staging_gpr, name="nwn.exe", payload=b"nwn-bytes")
    binary = tmp_path / "nwn.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(work))
    monkeypatch.delenv("AGENT_DECOMPILE_PROJECT_PATH", raising=False)
    monkeypatch.delenv("AGENTDECOMPILE_PROJECT_PATH", raising=False)

    def fake_call(name: str, arguments=None, *, timeout: float = 90.0):
        if name == "import-binary":
            return {"ok": True, "error": "", "parsed": {"success": True, "importedPrograms": []}}
        return {"ok": False, "error": "not a Ghidra project", "parsed": None}

    monkeypatch.setattr(
        "agentdecompile_recovery.corpus.dashboard.mcp_bridge.call_tool",
        fake_call,
    )
    monkeypatch.setattr(
        "agentdecompile_recovery.corpus.ghidra_project.create_local_project",
        lambda name, *, work_dir, destination=None: {
            "ok": True,
            "locator": str(staging_gpr),
            "gpr": str(staging_gpr),
        },
    )

    from agentdecompile_recovery.corpus.dashboard.workbench import import_program_into_project
    from agentdecompile_recovery.ghidra_db.store import find_store_program

    result = import_program_into_project(str(dest), path=str(binary), name="nwn.exe")
    assert result["ok"] is True, result
    landed = find_store_program(dest, "nwn.exe")
    assert landed is not None
    assert landed.database_path.read_bytes() == b"nwn-bytes"


def test_import_finds_cwd_projects_dir_without_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = _shared_dest(tmp_path)
    live = _live_gpr(tmp_path)
    binary = tmp_path / "game.exe"
    binary.write_bytes(b"MZ")
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.delenv("AGENT_DECOMPILE_PROJECT_PATH", raising=False)
    monkeypatch.delenv("AGENTDECOMPILE_PROJECT_PATH", raising=False)
    monkeypatch.chdir(tmp_path)

    def fake_call(name: str, arguments=None, *, timeout: float = 90.0):
        if name == "import-binary":
            return {
                "ok": True,
                "error": "",
                "parsed": {
                    "success": True,
                    "importedPrograms": [
                        {"programName": "game.exe", "programPath": "/game.exe"}
                    ],
                },
            }
        return {"ok": False, "error": "not a Ghidra project", "parsed": None}

    monkeypatch.setattr(
        "agentdecompile_recovery.corpus.dashboard.mcp_bridge.call_tool",
        fake_call,
    )

    from agentdecompile_recovery.corpus.dashboard.workbench import import_program_into_project
    from agentdecompile_recovery.ghidra_db.store import find_store_program

    result = import_program_into_project(str(dest), path=str(binary), name="game.exe")
    assert result["ok"] is True, result
    assert live.is_file()
    assert find_store_program(dest, "game.exe") is not None
