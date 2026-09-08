from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.store import connect
from agentdecompile_recovery.decomp_function_corpus import CorpusDump, DecompFunctionDoc, VectorEntry
from agentdecompile_recovery.decomp_indexer import write_index
from agentdecompile_recovery import unified_pages
from agentdecompile_recovery.unified_pages import create_unified_router, render_hub, render_dashboard

pytestmark = pytest.mark.unit


def _app() -> TestClient:
    app = FastAPI()
    app.include_router(create_unified_router())
    return TestClient(app)


def test_hub_and_healthz_are_on_the_same_app() -> None:
    client = _app()
    hub = client.get("/app")
    assert hub.status_code == 200
    assert "/atlas" in hub.text
    assert "Run work" in hub.text
    assert "/dashboard/actions" not in hub.text
    health = client.get("/dashboard/healthz")
    assert health.status_code == 200
    assert health.json()["ok"] is True
    assert health.json()["pages"]["atlas"] == "/atlas"
    assert health.json()["pages"]["graph"] == "/dashboard/functions#graph"
    assert health.json()["pages"]["review"] == "/dashboard/functions#review"
    assert health.json()["pages"]["builds"] == "/dashboard/functions#builds"


def test_dashboard_reads_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db = tmp_path / "corpus.sqlite"
    con = connect(db)
    con.execute(
        "INSERT INTO binary(id, repo_path, slug, game, platform, func_count, named_count, role) "
        "VALUES (1,'/a','donor','g','elf',12,4,'donor')"
    )
    con.commit()
    con.close()
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    client = _app()
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert "donor" in page.text
    assert "complete executable" in page.text.lower()
    assert "/dashboard/binary/donor" in page.text


def test_functions_page_works_without_source_file_column(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "corpus.sqlite"
    con = connect(db)
    con.execute(
        "INSERT INTO binary(id, repo_path, slug, game, platform, func_count, named_count, role) "
        "VALUES (1,'/a','donor','g','elf',1,1,'donor')"
    )
    con.execute(
        "INSERT INTO func(binary_id, addr, name, canon_key, source, n_instr) "
        "VALUES (1, 4198400, 'main', 'main', 'main.c', 12)"
    )
    con.commit()
    con.close()
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    client = _app()
    page = client.get("/dashboard/functions")
    assert page.status_code == 200
    assert "main" in page.text
    assert "0x401000" in page.text or "00401000" in page.text or "0x00401000" in page.text
    assert 'id="page-size"' in page.text
    assert 'id="review"' in page.text
    assert 'id="graph"' in page.text
    assert 'id="builds"' in page.text
    partial = client.get("/dashboard/functions?binary=donor&partial=1")
    assert partial.status_code == 200
    assert "<!doctype html>" not in partial.text.lower()
    assert 'id="function-results"' in partial.text
    aliased = client.get("/functions?binary=donor")
    assert aliased.status_code == 200
    assert "main" in aliased.text
    one = client.get("/dashboard/function/donor/0x401000")
    assert one.status_code == 200
    assert "main.c" in one.text
    binary = client.get("/binary/donor")
    assert binary.status_code == 200
    assert "main" in binary.text


def test_report_serves_html_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "report.html"
    path.write_text("<html><body>run report body</body></html>", encoding="utf-8")
    monkeypatch.setenv("AGENT_DECOMPILE_REPORT_HTML", str(path))
    client = _app()
    page = client.get("/report")
    assert page.status_code == 200
    assert "run report body" in page.text
    assert client.get("/recovery").status_code == 200


def test_artifact_stays_inside_work_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    work = tmp_path / "run"
    work.mkdir()
    (work / "note.txt").write_text("inside", encoding="utf-8")
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(work))
    client = _app()
    listing = client.get("/dashboard/artifact")
    assert listing.status_code == 200
    assert "note.txt" in listing.text
    ok = client.get("/artifact?p=note.txt")
    assert ok.status_code == 200
    assert "inside" in ok.text
    denied = client.get("/artifact?p=../secret")
    assert denied.status_code == 403


def test_atlas_load_then_build_keeps_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dump = CorpusDump(
        platform="win32",
        functions=[
            DecompFunctionDoc(id="fn1", name="target_func", asm_code="push ebp\nret", asm_module_path="a.c"),
            DecompFunctionDoc(
                id="fn2",
                name="similar_func",
                c_code="int similar_func(void) { return 1; }",
                c_module_path="a.c",
                asm_code="push ebp\nret",
                asm_module_path="a.s",
            ),
        ],
        vectors=[VectorEntry(id="fn1", embedding=[1.0, 0.0]), VectorEntry(id="fn2", embedding=[0.9, 0.1])],
    )
    write_index(tmp_path, dump, {})
    monkeypatch.setenv("AGENT_DECOMPILE_ATLAS_PROJECT_ROOT", str(tmp_path))
    unified_pages._ATLAS = None
    client = _app()
    loaded = client.post("/atlas/api/loadProject")
    assert loaded.status_code == 200
    built = client.post("/atlas/api/buildPrompt", json={"functionId": "fn1"})
    assert built.status_code == 200
    assert "target_func" in built.json()["prompt"]
    unified_pages._ATLAS = None


def test_atlas_page_uses_prefixed_api() -> None:
    client = _app()
    page = client.get("/atlas")
    assert page.status_code == 200
    assert "/atlas/api" in page.text
    missing = client.post("/atlas/api/loadProject", json={})
    assert missing.status_code == 404
    assert "AGENT_DECOMPILE_ATLAS_PROJECT_ROOT" in missing.json()["error"]


def test_render_helpers_state_claim_boundary() -> None:
    assert "not completion" in render_hub()
    page = render_dashboard(store_path=None, work_dir=None)
    assert "Real C and byte-accuracy" in page
