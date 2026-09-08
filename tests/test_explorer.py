from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard.explorer import (
    select_preparation,
    selection_from_mapping,
)
from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router
from agentdecompile_recovery.corpus.store import connect

pytestmark = pytest.mark.unit

JS = Path("src/agentdecompile_recovery/corpus/dashboard/static/explorer-page.js")
CSS = Path("src/agentdecompile_recovery/corpus/dashboard/static/explorer-page.css")
VITE_APP = Path("src/agentdecompile_recovery/corpus/dashboard/frontend/src/App.tsx")


def _client(monkeypatch: pytest.MonkeyPatch | None = None, tmp_path: Path | None = None) -> TestClient:
    if monkeypatch is not None and tmp_path is not None:
        db = tmp_path / "corpus.sqlite"
        connect(db).close()
        monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
        monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path / "work"))
    app = FastAPI()
    app.include_router(create_dashboard_router())
    return TestClient(app)


def test_selection_reads_alias_query_keys() -> None:
    row = selection_from_mapping({"path": "/repos/_odyssey", "binary": "nwn.exe", "fn": "0x401000"})
    assert row["locator"] == "/repos/_odyssey"
    assert row["slug"] == "nwn.exe"
    assert row["addr"] == "0x401000"


def test_select_preparation_prefers_active_run() -> None:
    runs = [
        {"id": "done", "locator": "/proj", "program": "game.exe", "status": "completed", "updatedAt": 90},
        {"id": "live", "locator": "/proj", "program": "game.exe", "status": "running", "updatedAt": 10},
    ]
    picked = select_preparation(runs, {"locator": "/proj", "program": "game.exe"})
    assert picked is not None
    assert picked["id"] == "live"


def test_select_preparation_matches_slug_when_locator_absent() -> None:
    runs = [
        {"id": "other", "slug": "k1", "status": "running", "updatedAt": 20},
        {"id": "mine", "slug": "nwn.exe", "status": "queued", "updatedAt": 5},
    ]
    picked = select_preparation(runs, {"slug": "nwn.exe"})
    assert picked is not None
    assert picked["id"] == "mine"


def test_select_preparation_accepts_program_in_run_list() -> None:
    runs = [
        {"id": "wave", "locator": "/proj", "program": "", "programs": ["nwserver.exe", "nwn.exe"], "status": "running", "updatedAt": 1},
    ]
    picked = select_preparation(runs, {"locator": "/proj", "program": "nwn.exe"})
    assert picked is not None
    assert picked["id"] == "wave"


def test_select_preparation_ignores_empty_selection() -> None:
    assert select_preparation([{"id": "x", "locator": "/p", "status": "running"}], {}) is None


def test_explorer_page_is_island_not_vite() -> None:
    page = _client().get("/dashboard/explorer")
    assert page.status_code == 200
    assert "explorer-page.js" in page.text
    assert "explorer-page.css" in page.text
    assert "workbench.css" in page.text
    assert "workbench-tokens.css" in page.text
    assert 'class="workbench-page explorer-page"' in page.text
    assert 'id="explorer-binaries"' in page.text
    assert 'id="explorer-functions"' in page.text
    assert 'id="explorer-workflow"' in page.text
    assert "static/react/" not in page.text
    assert "frontend/src" not in page.text


def test_explorer_listed_in_healthz() -> None:
    payload = _client().get("/dashboard/healthz").json()
    assert payload["pages"]["explorer"] == "/dashboard/explorer"


def test_explorer_snapshot_returns_workflow_slot(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)
    payload = client.get("/dashboard/api/workbench/explorer").json()
    assert payload["ok"] is True
    assert payload["selection"]["slug"] == ""
    assert payload["binaries"] == []
    assert payload["run"] is None
    assert "entities" in payload["activity"]


def test_explorer_snapshot_selects_matching_run(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import json

    client = _client(monkeypatch, tmp_path)
    run_id = "a" * 32
    row = {
        "id": run_id,
        "locator": "/proj",
        "program": "nwn.exe",
        "status": "running",
        "updatedAt": 1,
        "stages": [{"key": "assembly-floor", "title": "Assembly floor", "status": "running", "completed": 1, "total": 4}],
        "events": [],
    }
    dest = tmp_path / "work" / "preparations"
    dest.mkdir(parents=True)
    (dest / (run_id + ".json")).write_text(json.dumps(row), encoding="utf-8")
    payload = client.get("/dashboard/api/workbench/explorer?locator=/proj&program=nwn.exe").json()
    assert payload["run"]["id"] == run_id
    assert payload["run"]["stages"][0]["key"] == "assembly-floor"
    assert payload["selection"]["locator"] == "/proj"
    assert payload["selection"]["program"] == "nwn.exe"


def test_island_script_wires_live_workflow() -> None:
    js = JS.read_text(encoding="utf-8")
    assert "/dashboard/api/workbench/explorer" in js
    assert "/dashboard/api/workbench/activity" in js
    assert "/dashboard/api/workbench/preparations" in js
    assert "workbench.workflow-control" in js
    assert "history.replaceState" in js
    assert "EventSource" in js
    assert "entity-dimensions" in js
    assert "entity-chip-mark" in js
    assert "KIND_MARK" in js
    assert "statusWord" in js
    assert "prefers-reduced-motion" in CSS.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")
    assert ".entity-activity" in css
    assert ".entity-chip" in css
    assert "var(--fg-body)" in css
    assert "var(--wb-space-4)" in css
    assert '[data-kind="human"]' not in css
    assert re.search(r"#[0-9a-fA-F]{3,8}\b", css) is None
    assert "animation: explorer-working" in css
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "is-active progress:not([value])" in css
    assert ".workflow-rail" in css
    assert "No proof recorded" in js


def test_vite_app_untouched() -> None:
    text = VITE_APP.read_text(encoding="utf-8")
    assert "PersistentExplorer" in text
