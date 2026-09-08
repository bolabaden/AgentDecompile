from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard.actions.catalog import action_by_id
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


def test_list_binaries_includes_label(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, tmp_path)
    binary = tmp_path / "demo.exe"
    binary.write_bytes(b"MZ")
    client.post(
        "/dashboard/api/workbench/binaries",
        json={"path": str(binary), "slug": "demo.exe", "label": "layout source"},
    )
    listed = client.get("/dashboard/api/workbench/binaries").json()
    row = next(item for item in listed["binaries"] if item["slug"] == "demo.exe")
    assert row["label"] == "layout source"


def test_extract_stabs_action_fields_map_to_context_keys() -> None:
    action = action_by_id("corpus.extract-stabs")
    assert action is not None
    by_name = {field.name: field for field in action.fields}
    assert "binary" in by_name
    assert by_name["binary"].kind == "path"
    assert "id" in by_name
    assert by_name["id"].from_context == "slug"
    assert "out-dir" in by_name
    assert by_name["out-dir"].from_context == "work_dir"


def test_actions_api_includes_env_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, tmp_path)
    payload = client.get("/api/v1/actions").json()
    assert payload["ok"] is True
    assert "defaults" in payload["context"]
    assert payload["context"]["defaults"]["work_dir"].endswith("work")


def test_workbench_js_exposes_tool_field_helpers() -> None:
    js = Path("src/agentdecompile_recovery/corpus/dashboard/static/workbench-app.js").read_text(
        encoding="utf-8"
    )
    assert "function ToolField" in js
    assert "toolWidgetKind" in js
    assert "function QuickActions" in js
    assert "QUICK_ACTION_SETS" in js
    assert "wb-quick-actions" in js
    assert "function ActionStrip" in js
    assert "readActionParams" in js
    assert "wb-mcp-list" not in js
    assert "corpus.calibrate-global" in js
    assert 'id: "corpus.objdiff-check"' in js
    assert "QUICK_ACTION_SETS.pipeline" in js or "pipeline:" in js
    pipe = js[js.find("pipeline: [") : js.find("function:", js.find("pipeline: ["))]
    assert "corpus.calibrate-global" in pipe
    assert "corpus.calibrate\"" not in pipe.replace("corpus.calibrate-global", "")
    recover = js[js.find("function RecoverWorkbench") : js.find("function HtmlIsland")]
    assert "Ghidra bulk" in recover
    assert "reconstruct.one-shot" not in recover
    assert 'selected.decomp === "c"' in js
    assert "One-shot leftover" in recover
    assert 'runActionButton("reconstruct.one-shot"' not in js
    chain = js[
        js.find("function chainAfterAnalyze(job)") : js.find(
            "chainAfterAnalyzeRef.current = chainAfterAnalyze"
        )
    ]
    assert "corpus.cross-place" not in chain
    assert "mcp.match-function" not in chain
    assert "corpus.bsim-report" not in chain
    assert "corpus.extract-stabs" in chain
    assert "corpus.bsim-ingest" in chain
    assert "function programAlreadyAnalyzed" in js
    assert 'executeAction("mcp.analyze-program"' in js
    assert "if (!force && programAlreadyAnalyzed(data))" in js
    assert "unmeasured" in js
    assert "function fmtByteExact" in js
    assert "function LogDock" in js
    assert 'id="wb-log-dock"' in js
    assert "function beginResize" in js
    assert "function SplitHandle" in js
    assert 'className=${"wb-toast"' not in js


def test_workbench_js_open_binary_and_nested_imports() -> None:
    js = Path("src/agentdecompile_recovery/corpus/dashboard/static/workbench-app.js").read_text(
        encoding="utf-8"
    )
    assert "function triggerFileUpload" in js
    assert "function openBinaryPath" in js
    assert "wb-overview" in js
    assert "overview-fragment" in js
    assert "function selectImportBinary" in js
    assert "wb-bin-file-global" in js
    assert "importsContain" in js
    assert "sessionImportSlugs" in js
    assert 'entry.kind === "binary"' in js


def test_workbench_js_auto_project_on_blank_tab_upload() -> None:
    js = Path("src/agentdecompile_recovery/corpus/dashboard/static/workbench-app.js").read_text(
        encoding="utf-8"
    )
    assert "createTabProject" in js
    assert "tabHasRealProject" in js
    assert "wb-project-actions" not in js
    assert '["Save", "file.save"]' in js
    assert "saveProject" in js
    assert "openSaveAsDialog" in js


def test_draft_session_can_wrap_uploaded_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """API pieces the UI uses when a blank tab receives its first binary."""
    client = _client(monkeypatch, tmp_path)
    sessions = client.get("/dashboard/api/workbench/sessions").json()
    assert sessions["sessions"][0]["kind"] == "draft"
    tab_id = sessions["active"]
    binary = tmp_path / "game.exe"
    binary.write_bytes(b"MZ")
    uploaded = client.post(
        "/dashboard/api/workbench/binaries",
        files={"file": ("game.exe", binary.read_bytes(), "application/octet-stream")},
    )
    assert uploaded.status_code == 200
    slug = uploaded.json()["binary"]["slug"]
    created = client.post("/dashboard/api/workbench/projects", json={"name": "game"})
    assert created.status_code == 200
    project = created.json()
    updated = client.put(
        "/dashboard/api/workbench/sessions",
        json={
            "active": tab_id,
            "sessions": [
                {
                    **sessions["sessions"][0],
                    "title": "game",
                    "kind": "ghidra-project",
                    "locator": project["locator"],
                    "projectSlug": project["slug"],
                    "imports": [slug],
                    "program": "",
                }
            ],
        },
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["sessions"][0]["projectSlug"] == project["slug"]
    assert slug in body["sessions"][0]["imports"]
