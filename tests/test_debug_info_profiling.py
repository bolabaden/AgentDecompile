from __future__ import annotations

import json

import pytest

from agentdecompile_cli.mcp_server.profiling import ProfileCapture
from agentdecompile_cli.mcp_server.resources.debug_info import DebugInfoResource


@pytest.mark.asyncio
async def test_debug_info_includes_recent_profile_runs(monkeypatch) -> None:
    monkeypatch.setenv("AGENTDECOMPILE_PROFILE_ANALYZER", "C:/nonexistent/analyze_profile.py")

    with ProfileCapture("debug-info-test", target="unit-test") as capture:
        capture.add_metadata(testCase="debug-info-profile")
        sum(range(100))

    resource = DebugInfoResource()
    result = await resource.read_resource("ghidra://agentdecompile-debug-info")
    data = json.loads(result)

    assert "profiling" in data
    assert data["profiling"]["status"] == "available"
    assert isinstance(data["profiling"]["recent_runs"], list)
    assert data["profiling"]["recent_runs"]
    latest = data["profiling"]["recent_runs"][0]
    assert latest["operation"] == "debug-info-test"
    assert latest["target"] == "unit-test"
    assert latest["summaryText"]