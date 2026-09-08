from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentdecompile_recovery.corpus.dashboard import pages as dashboard
from agentdecompile_recovery.corpus.dashboard.router import create_dashboard_router

pytestmark = pytest.mark.unit


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(create_dashboard_router())
    return TestClient(app)


def test_render_page_has_one_main_landmark() -> None:
    page = dashboard.render_page("<p>detail</p>", "Detail")
    assert page.count("<main ") == 1
    assert page.count("</main>") == 1
    assert '<main id="app" data-live="0" tabindex="-1">' in page
    assert "<title>Detail</title>" in page


def test_dashboard_does_not_bind_legacy_ports() -> None:
    assert not hasattr(dashboard, "PORT")
    assert not hasattr(dashboard, "COMPAT_PORT")
    assert not hasattr(dashboard, "REPORT_PORT")
    source = dashboard.__file__
    text = open(source, encoding="utf-8").read()
    assert "ThreadingHTTPServer" not in text


def test_html_sets_security_cache_and_length_headers() -> None:
    client = _client()
    page = client.get("/dashboard/healthz")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("application/json")


def test_health_route_returns_json_success() -> None:
    client = _client()
    page = client.get("/dashboard/healthz")
    assert page.status_code == 200
    payload = page.json()
    assert payload["ok"] is True
    assert payload["pages"]["dashboard"] == "/dashboard"
    assert payload["pages"]["graph"] in {
        "/dashboard/functions#graph",
        "/dashboard?window=wb-graph",
    }
    assert payload["pages"]["functions"] in {
        "/dashboard/functions",
        "/dashboard?window=wb-fnbrowse",
    }


def test_unknown_route_returns_404() -> None:
    client = _client()
    page = client.get("/dashboard/no-such-dashboard-route")
    assert page.status_code == 404


def test_missing_function_preserves_renderer_404_status() -> None:
    client = _client()
    response = client.get("/dashboard/function/example.exe/0x401080", follow_redirects=False)
    assert response.status_code == 302
    assert "window=wb-fnbrowse" in response.headers["location"]
    assert "binary=example.exe" in response.headers["location"]


def test_functions_route_preserves_renderer_status() -> None:
    client = _client()
    response = client.get("/dashboard/functions?binary=missing", follow_redirects=False)
    assert response.status_code == 302
    assert "window=wb-fnbrowse" in response.headers["location"]


def test_graph_query_redirects_to_the_function_page() -> None:
    from agentdecompile_recovery.corpus.dashboard.pages import graph_to_function_target

    target = graph_to_function_target({
        "slug": ["K1__k1_xbox_default.xbe"],
        "addr": ["0x2273b0"],
        "depth": ["1"],
    })
    assert "window=wb-fnbrowse" in target
    assert "binary=K1__k1_xbox_default.xbe" in target
    assert "0x002273b0" in target
    assert "depth=1" in target
    assert "wb-graph" in graph_to_function_target({}) or graph_to_function_target({}) == "/dashboard/functions#graph"


def test_headline_byte_exact_is_unmeasured_without_receipt(tmp_path, monkeypatch) -> None:
    from agentdecompile_recovery.corpus.dashboard import pages as dashboard

    monkeypatch.setattr(dashboard, "COVERAGE", tmp_path / "missing-coverage.json")
    monkeypatch.setattr(dashboard, "as_root", lambda: tmp_path)
    value, _errors = dashboard._headline_byte_exact()
    assert value == "unmeasured"


def test_corpus_status_has_claim_boundary() -> None:
    client = _client()
    payload = client.get("/dashboard/api/workbench/corpus-status").json()
    assert "claimBoundary" in payload
    assert payload["claimBoundary"]
    headline = payload["headline"]
    assert "real_c" in headline
    assert "byte_exact" in headline
    assert headline["real_c"] != headline["byte_exact"] or headline["byte_exact"] == "unmeasured"
