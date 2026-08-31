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
    assert payload["pages"]["graph"] == "/dashboard/functions#graph"
    assert payload["pages"]["functions"] == "/dashboard/functions"


def test_unknown_route_returns_404() -> None:
    client = _client()
    page = client.get("/dashboard/no-such-dashboard-route")
    assert page.status_code == 404


def test_missing_function_preserves_renderer_404_status() -> None:
    from agentdecompile_recovery.corpus.dashboard import router as dash_router

    client = _client()
    missing = "<div>missing function</div>"
    with patch.object(dash_router, "render_function_page", return_value=(missing, 404)), \
         patch.object(dash_router, "render_page", return_value="wrapped") as page:
        response = client.get("/dashboard/function/example.exe/0x401080")
    page.assert_called_once()
    assert response.status_code == 404
    assert response.text == "wrapped"


def test_functions_route_preserves_renderer_status() -> None:
    from agentdecompile_recovery.corpus.dashboard import router as dash_router

    client = _client()
    missing = "<div>missing build</div>"
    with patch.object(dash_router, "render_functions_page", return_value=(missing, 404)), \
         patch.object(dash_router, "render_page", return_value="wrapped") as page:
        response = client.get("/dashboard/functions?binary=missing")
    page.assert_called_once()
    assert response.status_code == 404
    assert response.text == "wrapped"


def test_graph_query_redirects_to_the_function_page() -> None:
    from agentdecompile_recovery.corpus.dashboard.pages import graph_to_function_target

    target = graph_to_function_target({
        "slug": ["K1__k1_xbox_default.xbe"],
        "addr": ["0x2273b0"],
        "depth": ["1"],
    })
    assert target.startswith("/dashboard/function/K1__k1_xbox_default.xbe/")
    assert "0x002273b0" in target
    assert "depth=1" in target
    assert graph_to_function_target({}) == "/dashboard/functions#graph"
