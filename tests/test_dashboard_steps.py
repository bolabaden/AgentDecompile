from __future__ import annotations

from pathlib import Path

import pytest

from agentdecompile_recovery.corpus.dashboard.panels import steps
from agentdecompile_recovery.corpus.store import connect

pytestmark = pytest.mark.unit


def test_steps_compact_skips_sql_errors_for_missing_optional_tables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "corpus.sqlite"
    con = connect(db)
    con.execute(
        "INSERT INTO binary(id, repo_path, slug, game, platform, func_count, named_count, role) "
        "VALUES (1,'/a/nwmain','nwmain-linux-4','K1','linux',120,4,'member')"
    )
    con.commit()
    con.close()
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_DB", str(db))
    monkeypatch.setenv("AGENT_DECOMPILE_CORPUS_WORK_DIR", str(tmp_path))
    steps._facts_cache["data"] = None

    html = steps.render_compact()

    assert "query failed" not in html
    assert "logical_name" in html or "not populated yet" in html
    assert "nwmain-linux-4" not in html  # per-build ladders collapsed away
    assert "Extract every function" in html
    assert steps.STEP_ACTION_DEFAULTS["apply-cross-build"] == "corpus.cross-place"
    assert steps.STEP_ACTION_DEFAULTS["verify-byte-accuracy"] == "corpus.objdiff-check"
    assert steps.STEP_ACTION_DEFAULTS["apply-cross-build"] == "corpus.cross-place"
    assert steps.STEP_ACTION_DEFAULTS["calibrate-global"] == "corpus.calibrate-global"
    assert "reconstruct.one-shot" not in steps.STEP_ACTION_DEFAULTS.values()
    assert "corpus.propagate-corpus" not in steps.STEP_ACTION_DEFAULTS.values()
    src = Path("src/agentdecompile_recovery/corpus/dashboard/panels/steps.py").read_text(
        encoding="utf-8"
    )
    assert "corpus.propagate-corpus" not in src


def test_healthz_includes_probes() -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router

    app = FastAPI()
    app.include_router(create_dashboard_router())
    client = TestClient(app)
    payload = client.get("/dashboard/healthz").json()
    assert payload["ok"] is True
    assert isinstance(payload.get("probes"), list)
    assert len(payload["probes"]) == 3
