from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router
from agentdecompile_recovery.corpus.store import connect

pytestmark = pytest.mark.unit

JS = Path("src/agentdecompile_recovery/corpus/dashboard/static/workbench-app.js").read_text(
    encoding="utf-8"
)


def _client(monkeypatch: pytest.MonkeyPatch, tmp_path) -> TestClient:
    db = tmp_path / "corpus.sqlite"
    connect(db).close()
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path / "work"))
    app = FastAPI()
    app.include_router(create_dashboard_router())
    return TestClient(app)


def test_workbench_js_five_way_access() -> None:
    assert "function ContextMenu" in JS
    assert "function runCommand" in JS
    assert "WORKBENCH_COMMANDS" in JS
    assert "wb-ctx-menu" in JS
    assert "Keyboard & five ways" in JS
    assert "wb-last-action" in JS
    assert "file.open-url" in JS
    assert "onContextMenu" in JS
    assert 'data-cmd=' in JS
    assert "view.inspect" in JS
    assert "view.pipeline" in JS
    assert "help.classic-overview" in JS


def test_workbench_js_command_palette_and_dock() -> None:
    assert "function CommandPalette" in JS
    assert "function JobsDock" in JS
    assert "function ConfirmDialog" in JS
    assert "function ActionStrip" in JS
    assert "readActionParams" in JS
    assert "scrollToSurface" in JS
    assert 'accel: "mod+K"' in JS
    assert "function accelLabel" in JS
    assert "A finished job is not a match" in JS
    assert "window.confirm" not in JS
    assert "ArrowDown" in JS
    assert "Enter to select" in JS
    assert "lastActionId" in JS
    assert 'j: "view.jobs"' in JS
    assert "wb-ingest-drop" in JS


def test_workbench_js_palette_keyboard_navigation() -> None:
    assert "wb-palette-item active" in JS or "itemClass(idx)" in JS
    assert "onIngestDragOver" in JS


def test_workbench_js_phase_b_spatial() -> None:
    assert "function CorpusNavBar" in JS
    assert "wb-corpus-nav" in JS
    assert "CORPUS_NAV" in JS
    assert "RECENT_ACTIONS_KEY" in JS
    assert "Recent actions" in JS
    assert "wb-density-compact" in JS
    assert "wb-jobs-rail" in JS
    assert "Compact density" in JS
    assert "Jobs dock on side" in JS


def test_workbench_js_editor_shell() -> None:
    assert "function renderEditorBody" in JS
    assert "wb-editor" in JS
    assert "wb-editor-tabs" in JS
    assert "Listing" in JS
    assert "EDITOR_TABS" in JS
    assert "EDITOR_PRIMARY" in JS
    assert "setCenterTab" in JS
    assert "Drop a binary or project here." in JS
    assert "wb-open-paste" in JS
    assert "openProjectDialog(tab)" in JS
    assert "wb-import-head" in JS
    assert "wb-program-head" in JS
    assert "function TabRoster" in JS
    assert "Close the project tab" in JS or "closes the project tab" in JS
    assert "Run Cross-place" in JS
    assert 'placeholder="Filter functions…"' in JS
    assert "slugFromDiskPath" in JS
    assert "startImportPipeline" in JS
    assert "chainAfterAnalyze" in JS
    assert "wb-prog-meter" in JS
    assert "analyze.program" in JS
    assert "mcp.analyze-program" in JS


def test_workbench_js_phase_c_batch() -> None:
    assert "function JobLiveRegion" in JS
    assert 'aria-live="polite"' in JS
    assert "function jobLiveAnnouncement" in JS
    assert "A finished job is not a match" in JS
    assert "function actionUsesAddr" in JS
    assert "function toggleAddrList" in JS
    assert "function rangeAddrList" in JS
    assert "checkedAddrs" in JS
    assert "wb-sel-chip" in JS
    assert "wb-func-check" in JS
    assert "skipBatch" in JS or "batch: false" in JS
    assert 'key === "x"' in JS
    assert "Run " in JS
    assert "Queued " in JS


def test_workbench_control_system_files() -> None:
    static = Path("src/agentdecompile_recovery/corpus/dashboard/static")
    tokens = (static / "workbench-tokens.css").read_text(encoding="utf-8")
    controls = (static / "workbench-controls.css").read_text(encoding="utf-8")
    chrome = (static / "workbench-chrome.css").read_text(encoding="utf-8")
    sidebar = (static / "workbench-sidebar.css").read_text(encoding="utf-8")
    editor = (static / "workbench-editor.css").read_text(encoding="utf-8")
    dialogs = (static / "workbench-dialogs.css").read_text(encoding="utf-8")
    overlays = (static / "workbench-overlays.css").read_text(encoding="utf-8")
    assert "--wb-ctrl-h" in tokens
    assert ".wb-btn-primary" in controls
    assert ".wb-menu-item" in chrome
    assert "#wb-func-window" in sidebar
    assert "display: block" in editor
    assert "display: none" not in editor or ".wb-surface-head" in editor
    assert ".wb-modal" in dialogs
    assert ".wb-palette" in overlays
    html = Path("src/agentdecompile_recovery/corpus/dashboard/workbench.py").read_text(encoding="utf-8")
    assert "workbench-tokens.css" in html
    assert "workbench-chrome.css" in html


def test_workbench_css_phase_c_batch() -> None:
    css = Path("src/agentdecompile_recovery/corpus/dashboard/static/workbench.css").read_text(
        encoding="utf-8"
    )
    assert "wb-func-check" in css
    assert "wb-sel-chip" in css
    assert "1.35rem 7.5rem 1fr" in css
    assert "wb-editor" in css
    assert "wb-editor-tabs" in css
    assert "#214283" in css


def test_workbench_js_palette_surface_navigation() -> None:
    assert "Cross-match" in JS
    assert "setMoreOpen(true)" in JS
    assert "wb-jobs-dock" in JS
    assert "View log in dock" in JS


def test_job_cancel_route_callable(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, tmp_path)
    listed = client.get("/api/v1/jobs").json()
    assert listed["ok"] is True
    assert "jobs" in listed
    # Unknown job still returns structured response (not 404 crash)
    res = client.post("/api/v1/jobs/nonexistent-job/cancel")
    assert res.status_code in (200, 404, 422)
