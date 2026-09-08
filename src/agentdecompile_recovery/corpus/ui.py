"""Probe live UI ports. Never treat a green label as pipeline completion."""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any

from .contract import DEFAULT_ATLAS_PORT, DEFAULT_DASHBOARD_PORT, DEFAULT_REPORT_PORT
from .io import write_json


def probe_url(url: str, timeout: float = 2.0) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read(200).decode("utf-8", "replace")
            return {"ok": 200 <= resp.status < 400, "status": resp.status, "body": body[:120]}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"ok": False, "status": None, "error": str(exc)}


def probe_live_ui(
    *,
    dashboard_port: int = DEFAULT_DASHBOARD_PORT,
    atlas_port: int = DEFAULT_ATLAS_PORT,
    report_port: int = DEFAULT_REPORT_PORT,
    host: str = "127.0.0.1",
    mcp_base: str | None = None,
) -> dict[str, Any]:
    """Probe the unified MCP pages first, then leftover standalone ports."""
    if mcp_base or dashboard_port in (8080, DEFAULT_DASHBOARD_PORT):
        mcp = (mcp_base or f"http://{host}:8080").rstrip("/")
        dashboard = probe_url(f"{mcp}/dashboard/healthz")
        if not dashboard["ok"]:
            dashboard = probe_url(f"{mcp}/dashboard")
        atlas = probe_url(f"{mcp}/atlas")
        report = probe_url(f"{mcp}/report")
        if dashboard["ok"] or atlas["ok"] or report["ok"]:
            return {
                "dashboard": {"url": f"{mcp}/dashboard", **dashboard},
                "atlas": {"url": f"{mcp}/atlas", **atlas},
                "report": {"url": f"{mcp}/report", **report},
                "unified": True,
                "claimBoundary": (
                    "UI reachability is not recovery progress. Completeness comes from "
                    "pipeline receipts on disk."
                ),
            }
    dashboard = probe_url(f"http://{host}:{dashboard_port}/healthz")
    if not dashboard["ok"]:
        dashboard = probe_url(f"http://{host}:{dashboard_port}/")
    atlas = probe_url(f"http://{host}:{atlas_port}/")
    report = probe_url(f"http://{host}:{report_port}/healthz")
    if not report["ok"]:
        report = probe_url(f"http://{host}:{report_port}/report")
    return {
        "dashboard": {"port": dashboard_port, **dashboard},
        "atlas": {"port": atlas_port, **atlas},
        "report": {"port": report_port, **report},
        "unified": False,
        "claimBoundary": (
            "UI reachability is not recovery progress. Completeness comes from "
            "pipeline receipts on disk."
        ),
    }


def write_ui_receipt(path, receipt: dict[str, Any]) -> None:
    write_json(path, receipt)
