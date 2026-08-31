from __future__ import annotations

import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard.actions import catalog, jobs
from agentdecompile_recovery.corpus.dashboard.actions.introspect import public_command_ids
from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router
from agentdecompile_recovery.corpus.dashboard.workbench import list_binaries

pytestmark = pytest.mark.unit


def _app() -> FastAPI:
    app = FastAPI(title="AgentDecompile", docs_url="/docs", openapi_url="/openapi.json")
    app.include_router(create_dashboard_router())
    return app


def _client() -> TestClient:
    return TestClient(_app())


def test_catalog_covers_every_public_command() -> None:
    ids = {item.id for item in catalog.list_actions()}
    expected = public_command_ids()
    missing = {key: sorted(values - ids) for key, values in expected.items() if values - ids}
    assert missing == {}
    assert "corpus.compile-link" in ids
    assert "corpus.workspace" in ids
    assert "corpus.remove-binary" in ids
    assert "recover.headers" in ids
    assert "reconstruct.one-shot" in ids
    assert "mcp.decompile-function" in ids


def test_openapi_lists_typed_action_operations() -> None:
    spec = _app().openapi()
    paths = spec["paths"]
    assert "/api/v1/actions/corpus/ghidra-bulk" in paths
    assert "/api/v1/actions/mcp/decompile-function" in paths
    assert "/api/v1/actions/reconstruct/one-shot" in paths
    assert "/api/v1/actions/corpus/compile-link" in paths
    bulk = paths["/api/v1/actions/corpus/ghidra-bulk"]["post"]
    assert bulk["operationId"] == "corpus.ghidra-bulk"
    body = bulk["requestBody"]["content"]["application/json"]["schema"]
    assert body.get("additionalProperties") is not True
    props = body.get("properties") or {}
    if not props and body.get("$ref"):
        name = str(body["$ref"]).rsplit("/", 1)[-1]
        props = spec["components"]["schemas"][name]["properties"]
    assert "program" in props
    assert "confirm" in props


def test_swagger_dry_run_and_two_jobs_do_not_block(monkeypatch: pytest.MonkeyPatch) -> None:
    started = threading.Event()
    release = threading.Event()
    seen: list[str] = []

    def fake(argv, cwd, cancel):
        seen.append(" ".join(argv))
        started.set()
        release.wait(2)
        return 0, "ok"

    monkeypatch.setattr(jobs.STORE, "executor", fake)
    client = _client()
    dry = client.post("/api/v1/actions/corpus/stages", json={"dryRun": True})
    assert dry.status_code == 200
    assert dry.json()["dryRun"] is True
    first = client.post("/api/v1/actions/corpus/ghidra-bulk", json={
        "program": "demo.exe",
        "repo": "/repo",
        "db": "/tmp/x.sqlite",
        "out-dir": "/tmp/out",
        "kb": "/tmp/kb.sqlite",
    })
    second = client.post("/api/v1/actions/corpus/compile-link", json={
        "src-dir": "/tmp/src",
        "out": "/tmp/out.exe",
    })
    assert first.status_code == 202
    assert second.status_code == 202
    assert first.json()["job"]["id"] != second.json()["job"]["id"]
    assert started.wait(2)
    release.set()


def test_workbench_binaries_empty_without_db(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_DECOMPILE_CORPUS_DB", raising=False)
    monkeypatch.delenv("AGENT_DECOMPILE_CORPUS_ROOT", raising=False)
    payload = list_binaries()
    assert payload["ok"] is False or payload.get("binaries") == []
    page = _client().get("/dashboard")
    assert page.status_code == 200
    assert "kotorxid" not in page.text.lower()
    assert "Mizuchi" not in page.text
