from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard.actions import catalog, jobs
from agentdecompile_recovery.corpus.dashboard.pages import render_browse_block
from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router

pytestmark = pytest.mark.unit


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(create_dashboard_router())
    return TestClient(app)


def test_catalog_covers_corpus_and_mcp() -> None:
    ids = {item.id for item in catalog.list_actions()}
    assert "corpus.ghidra-bulk" in ids
    assert "corpus.cross-place" in ids
    assert "mcp.decompile-function" in ids
    assert "mcp.list-functions" in ids
    assert "corpus.bsim-ingest" in ids
    assert "corpus.bsim-report" in ids
    assert "corpus.bsim-createdatabase" in ids
    assert "mcp.bsim-ingest" in ids
    assert "mcp.bsim-report" in ids


def test_ghidra_bulk_command_uses_cataloged_flags() -> None:
    action = catalog.action_by_id("corpus.ghidra-bulk")
    assert action is not None
    argv = catalog.build_command(
        action,
        {
            "program": "/games/debug.exe",
            "repo": "/repo",
            "db": "/tmp/store.sqlite",
            "out-dir": "/tmp/out",
            "kb": "/tmp/kb.sqlite",
            "mode": "compile-only",
        },
    )
    assert "ghidra-bulk" in argv
    assert "--program" in argv
    assert "/games/debug.exe" in argv
    assert "--force" not in argv
    assert argv[0].endswith("python") or "python" in Path(argv[0]).name
    assert "-c" in argv


def test_reconstruct_input_rewrites_shared_fs_dir(tmp_path: Path) -> None:
    imports = tmp_path / "imports"
    imports.mkdir()
    pe = imports / "k1_win_gog_swkotor.exe"
    pe.write_bytes(b"MZ")
    repos = tmp_path / "repos"
    repos.mkdir()
    action = catalog.action_by_id("reconstruct.one-shot")
    assert action is not None
    merged = catalog.apply_defaults(
        action,
        {"input": str(repos)},
        {"program": "k1_win_gog_swkotor.exe", "work_dir": str(tmp_path), "repo": str(repos)},
    )
    assert merged["input"] == str(pe)


def test_danger_requires_confirm() -> None:
    action = catalog.action_by_id("corpus.apply-annotations")
    assert action is not None
    errors = catalog.validate_params(
        action,
        {"jsonl": "/tmp/names.jsonl", "program": "/games/debug.exe"},
        confirm=False,
    )
    assert errors
    assert not catalog.validate_params(
        action,
        {"jsonl": "/tmp/names.jsonl", "program": "/games/debug.exe"},
        confirm=True,
    )


def test_start_job_dry_run_does_not_spawn() -> None:
    payload, status = jobs.start_job(
        "corpus.stages",
        {},
        dry_run=True,
    )
    assert status == 200
    assert payload["dryRun"] is True
    assert payload["argv"][-1] == "stages"


def test_job_api_runs_fake_executor(monkeypatch: pytest.MonkeyPatch) -> None:
    done = threading.Event()

    def fake(argv, cwd, cancel):
        done.set()
        return 0, "ok " + " ".join(argv[-2:])

    monkeypatch.setattr(jobs.STORE, "executor", fake)
    client = _client()
    started = client.post("/dashboard/api/jobs", json={"action": "corpus.stages", "confirm": True})
    assert started.status_code == 202
    job_id = started.json()["job"]["id"]
    assert done.wait(2)
    listed = client.get("/dashboard/api/jobs")
    assert listed.status_code == 200
    assert any(row["id"] == job_id for row in listed.json()["jobs"])


def test_actions_api_accepts_context_only_body(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Workbench quick actions send only confirm + context; no 422 from Pydantic."""
    work = tmp_path / "work"
    work.mkdir()
    db = tmp_path / "store.sqlite"
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(work))
    client = _client()
    ctx = {"slug": "demo-corpus", "work_dir": str(work), "db": str(db), "kb": ""}

    init_store = client.post(
        "/api/v1/actions/corpus/init-store",
        json={"confirm": True, "dryRun": True, "context": ctx},
    )
    assert init_store.status_code == 200, init_store.json()
    assert init_store.json()["params"]["db"] == str(db)

    init_corpus = client.post(
        "/api/v1/actions/corpus/init",
        json={"confirm": True, "dryRun": True, "context": ctx},
    )
    assert init_corpus.status_code == 200, init_corpus.json()
    assert init_corpus.json()["params"]["id"] == "demo-corpus"
    assert init_corpus.json()["params"]["out"] == str(work)

    bulk_ctx = {
        **ctx,
        "program": "/games/demo.exe",
        "repo": "/games/demo.exe",
    }
    ghidra_bulk = client.post(
        "/api/v1/actions/corpus/ghidra-bulk",
        json={"confirm": True, "dryRun": True, "context": bulk_ctx},
    )
    assert ghidra_bulk.status_code == 200, ghidra_bulk.json()
    params = ghidra_bulk.json()["params"]
    assert params["program"] == "/games/demo.exe"
    assert params["repo"] == "/games/demo.exe"
    assert params["db"] == str(db)
    assert params["out-dir"] == str(work)
    assert params["kb"]


def test_actions_api_unwraps_nested_params(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The workbench used to nest field overrides under params; those must apply."""
    work = tmp_path / "work"
    work.mkdir()
    db = tmp_path / "store.sqlite"
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(work))
    client = _client()
    ctx = {"slug": "demo-corpus", "work_dir": str(work), "db": str(db), "kb": ""}
    res = client.post(
        "/api/v1/actions/corpus/init",
        json={
            "confirm": True,
            "dryRun": True,
            "context": ctx,
            "params": {"id": "from-nested"},
        },
    )
    assert res.status_code == 200, res.json()
    assert res.json()["params"]["id"] == "from-nested"


def test_overview_has_run_work_and_no_actions_page() -> None:
    from agentdecompile_recovery.corpus.dashboard.react_api import ASSETS

    client = _client()
    overview = client.get("/dashboard/overview", follow_redirects=False)
    assert overview.status_code == 302
    assert "window=wb-overview" in overview.headers["location"]
    home = client.get("/dashboard/overview", follow_redirects=True)
    assert home.status_code == 200
    assert "AgentDecompile" in home.text
    react_entry = ASSETS / "index.html"
    if react_entry.is_file():
        assert 'id="root"' in home.text
    else:
        assert 'id="wb-sessions"' in home.text
    assert "action-catalog" not in home.text
    assert "/dashboard/actions" not in home.text
    assert client.get("/dashboard/actions", follow_redirects=False).status_code == 302
    assert client.get("/dashboard/builds", follow_redirects=False).headers["location"] == (
        "/dashboard?window=wb-corpus"
    )
    workbench = client.get("/dashboard")
    assert workbench.status_code == 200
    assert "AgentDecompile" in workbench.text
    if react_entry.is_file():
        assert 'id="root"' in workbench.text
    else:
        assert 'id="wb-sessions"' in workbench.text
        assert 'role="tablist"' in workbench.text
        assert "wb-strip" not in workbench.text
    assert "/docs" in workbench.text or react_entry.is_file()
    assert "CommandPalette" in Path(
        "src/agentdecompile_recovery/corpus/dashboard/static/workbench-app.js"
    ).read_text(encoding="utf-8")


def test_browse_surfaces_are_workbench_windows_not_a_second_page() -> None:
    """Functions, logical identities, review, graph and builds share one page."""
    from agentdecompile_recovery.corpus.dashboard.react_api import ASSETS

    client = _client()
    landing = client.get("/dashboard/functions", follow_redirects=False)
    assert landing.status_code == 302
    assert landing.headers["location"] == "/dashboard?window=wb-fnbrowse"
    workbench = client.get("/dashboard")
    assert workbench.status_code == 200
    react_entry = ASSETS / "index.html"
    js = Path(
        "src/agentdecompile_recovery/corpus/dashboard/static/workbench-app.js"
    ).read_text(encoding="utf-8")
    for surface in ("wb-fnbrowse", "wb-logical", "wb-review", "wb-graph", "wb-corpus"):
        if react_entry.is_file():
            assert f'id="{surface}"' in js or f'id={surface}' in js
        else:
            assert f'id="{surface}"' in workbench.text
    # The old five-block browse page must not be nested inside the workbench.
    assert "workspace-nav" not in workbench.text
    for block in ("logical", "review", "graph", "builds"):
        body, status = render_browse_block(block, {})
        assert status == 200
        assert "workspace-nav" not in body
    graph = client.get("/dashboard/graph", follow_redirects=False)
    assert graph.status_code == 302
    assert graph.headers["location"].startswith("/dashboard")


def test_identity_writers_serialize_per_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    db_a = tmp_path / "a.sqlite"
    db_b = tmp_path / "b.sqlite"
    db_a.write_bytes(b"")
    db_b.write_bytes(b"")
    hold = threading.Event()
    started = []

    def fake(argv, cwd, cancel):
        started.append(" ".join(argv))
        hold.wait(2)
        return 0, "ok"

    monkeypatch.setattr(jobs.STORE, "executor", fake)
    monkeypatch.setattr(
        jobs,
        "_mcp_executor",
        lambda action, params, cancel: (0, "ok"),
    )
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db_a))
    first, status = jobs.start_job(
        "corpus.logical-build",
        {"db": str(db_a)},
        confirm=True,
    )
    assert status == 202
    second, status = jobs.start_job(
        "corpus.logical-build",
        {"db": str(db_a)},
        confirm=True,
    )
    assert status == 202
    other, status = jobs.start_job(
        "corpus.logical-build",
        {"db": str(db_b)},
        confirm=True,
    )
    assert status == 202
    time.sleep(0.4)
    listed = {row.id: row for row in jobs.list_jobs()}
    assert listed[first["job"]["id"]].status == "running"
    assert listed[second["job"]["id"]].status == "queued"
    assert listed[other["job"]["id"]].status == "running"
    analyze, status = jobs.start_job(
        "mcp.analyze-program",
        {"program": "/games/demo.exe"},
        confirm=True,
    )
    assert status in {202, 400, 404}
    if status == 202:
        time.sleep(0.3)
        assert jobs.get_job(analyze["job"]["id"]).status in {"running", "queued", "ok"}
    jobs.cancel_job(second["job"]["id"])
    hold.set()
    time.sleep(0.4)
    assert jobs.get_job(second["job"]["id"]).status in {"cancelled", "cancelling", "ok"}


def test_identity_writer_without_db_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_DECOMPILE_CORPUS_DB", raising=False)
    payload, status = jobs.start_job("corpus.logical-build", {}, confirm=True)
    assert status == 400
    assert "db" in payload["error"]


def test_objdiff_job_env_drops_wine() -> None:
    env = jobs.isolated_job_env(
        ["agentdecompile-corpus", "objdiff-check", "--a", "x"],
        {"WINEPREFIX": "/tmp/wine-bulk", "PATH": "/usr/bin", "WINE": "/usr/bin/wine"},
    )
    assert env["AGENT_DECOMPILE_OBJDIFF_ISOLATED"] == "1"
    assert "WINEPREFIX" not in env
    assert "WINE" not in env


def test_cancel_running_identity_writer_unblocks_queued(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "one.sqlite"
    db.write_bytes(b"")
    hold = threading.Event()

    def fake(argv, cwd, cancel):
        while not cancel.is_set() and not hold.wait(0.05):
            pass
        return 0, "ok"

    monkeypatch.setattr(jobs.STORE, "executor", fake)
    first, status = jobs.start_job("corpus.logical-build", {"db": str(db)}, confirm=True)
    assert status == 202
    second, status = jobs.start_job("corpus.logical-build", {"db": str(db)}, confirm=True)
    assert status == 202
    time.sleep(0.4)
    listed = {row.id: row for row in jobs.list_jobs()}
    assert listed[first["job"]["id"]].status == "running"
    assert listed[second["job"]["id"]].status == "queued"
    jobs.cancel_job(first["job"]["id"])
    time.sleep(0.5)
    assert jobs.get_job(first["job"]["id"]).status in {"cancelled", "cancelling"}
    assert jobs.get_job(second["job"]["id"]).status in {"running", "ok"}
    hold.set()
