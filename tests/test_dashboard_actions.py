from __future__ import annotations

import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard.actions import catalog, jobs
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


def test_overview_has_run_work_and_no_actions_page() -> None:
    client = _client()
    home = client.get("/dashboard/overview")
    assert home.status_code == 200
    assert 'id="run"' in home.text
    assert "action-catalog" in home.text
    assert "/dashboard/actions" not in home.text
    assert client.get("/dashboard/actions", follow_redirects=False).status_code == 302
    assert client.get("/dashboard/builds", follow_redirects=False).headers["location"].endswith("#builds")
    workbench = client.get("/dashboard")
    assert workbench.status_code == 200
    assert "AgentDecompile" in workbench.text
    assert 'role="tablist"' not in workbench.text
    assert "/docs" in workbench.text


def test_functions_page_includes_logical_identities() -> None:
    client = _client()
    page = client.get("/dashboard/functions")
    assert page.status_code == 200
    assert 'id="logical"' in page.text
    assert 'id="review"' in page.text
    assert 'id="graph"' in page.text
    assert 'id="builds"' in page.text
    assert 'workspace-nav' in page.text
    assert "action-bar" in page.text
    graph = client.get("/dashboard/graph", follow_redirects=False)
    assert graph.status_code == 302
    assert graph.headers["location"].endswith("#graph")
