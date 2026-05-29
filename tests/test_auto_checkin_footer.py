from __future__ import annotations

import pytest

from agentdecompile_cli.mcp_server.program_metadata import (
    attach_auto_checkin_to_payload,
    summarize_auto_checkin_result,
)
from agentdecompile_cli.mcp_server.response_formatter import render_tool_response


@pytest.mark.unit
def test_summarize_auto_checkin_result_success() -> None:
    summary = summarize_auto_checkin_result(
        {
            "success": True,
            "mode": "checkin_all",
            "count": 2,
            "results": [
                {"programPath": "/a.exe", "success": True, "mode": "checkin"},
                {"programPath": "/b.exe", "success": True, "mode": "save_local"},
            ],
        },
    )

    assert summary["performed"] is True
    assert summary["success"] is True
    assert summary["succeededCount"] == 2
    assert summary["failedCount"] == 0
    assert "2 program" in summary["hint"]


@pytest.mark.unit
def test_summarize_auto_checkin_result_partial_failure() -> None:
    summary = summarize_auto_checkin_result(
        {
            "success": False,
            "mode": "checkin_all",
            "count": 1,
            "results": [
                {"programPath": "/a.exe", "success": False, "mode": "checkin_blocked", "error": "locked"},
            ],
        },
    )

    assert summary["success"] is False
    assert summary["failedCount"] == 1
    assert "failure" in summary["hint"]


@pytest.mark.unit
def test_summarize_auto_checkin_result_exception() -> None:
    summary = summarize_auto_checkin_result({}, exception="checkout timeout")

    assert summary["success"] is False
    assert "checkout timeout" in summary["error"]


@pytest.mark.unit
def test_attach_auto_checkin_appends_gui_hint() -> None:
    payload: dict = {"success": True, "guiHint": "Existing hint."}
    attach_auto_checkin_to_payload(
        payload,
        {
            "success": True,
            "results": [{"programPath": "/a.exe", "success": True, "mode": "save_local"}],
        },
    )

    assert payload["autoCheckin"]["success"] is True
    assert "Auto check-in completed" in payload["guiHint"]


@pytest.mark.unit
def test_render_tool_response_includes_auto_checkin_footer() -> None:
    rendered = render_tool_response(
        "managecomments",
        {
            "success": True,
            "action": "set",
            "autoCheckin": {
                "performed": True,
                "success": True,
                "succeededCount": 1,
                "failedCount": 0,
                "hint": "Auto check-in completed for 1 program(s).",
            },
        },
    )

    assert "### Auto Check-in" in rendered
    assert "Automatic persistence after mutation **succeeded**" in rendered
    assert "Auto check-in completed for 1 program(s)." in rendered
