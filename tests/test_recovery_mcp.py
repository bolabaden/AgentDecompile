"""Unit tests for curated recovery MCP tools (reconstruct / status / claim-report)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentdecompile_cli.mcp_server.providers.recovery import RecoveryToolProvider
from agentdecompile_cli.mcp_server.tool_providers import ToolProviderManager, n
from agentdecompile_cli.registry import Tool, get_advertised_tools_for_list, get_tool_analysis_tier
from agentdecompile_recovery.recovery_status import build_recovery_status

pytestmark = pytest.mark.unit


def test_recovery_tools_are_tier_zero() -> None:
    assert get_tool_analysis_tier(Tool.RECONSTRUCT) == 0
    assert get_tool_analysis_tier(Tool.STATUS) == 0
    assert get_tool_analysis_tier(Tool.CLAIM_REPORT) == 0


def test_recovery_tools_advertised_on_default_surface() -> None:
    advertised = set(get_advertised_tools_for_list())
    assert Tool.RECONSTRUCT.value in advertised
    assert Tool.STATUS.value in advertised
    assert Tool.CLAIM_REPORT.value in advertised


def test_build_recovery_status_from_work_dir(tmp_path: Path) -> None:
    work = tmp_path / "run"
    (work / "verified").mkdir(parents=True)
    (work / "advisory").mkdir(parents=True)
    (work / "verified" / "fn.c").write_text("int f(void){return 0;}\n", encoding="utf-8")
    (work / "advisory" / "fn.c").write_text("/* advisory */\n", encoding="utf-8")
    (work / "state.json").write_text(json.dumps({"terminalStatus": "partial", "currentStage": "report"}), encoding="utf-8")
    (work / "claim-report.json").write_text(
        json.dumps({"terminalStatus": "partial", "counts": {"objdiffVerified": 0}}),
        encoding="utf-8",
    )

    status = build_recovery_status(work)
    assert status["schema"] == "agentdecompile.recovery-status.v1"
    assert status["terminalStatus"] == "partial"
    assert status["stage"] == "report"
    assert status["counts"]["verified"] == 1
    assert status["counts"]["advisory"] == 1
    assert "objdiff-verified-semantic" in status["claimBoundary"] or "objdiff" in status["claimBoundary"]


def test_build_recovery_status_includes_autonomy_and_vacuum(tmp_path: Path) -> None:
    work = tmp_path / "run"
    (work / "state").mkdir(parents=True)
    (work / "autonomy-budget.json").write_text(
        json.dumps(
            {
                "schema": "agentdecompile.autonomy-budget.v1",
                "requested": True,
                "status": "bridged",
                "max_functions": 1,
            }
        ),
        encoding="utf-8",
    )
    (work / "state" / "queue.json").write_text(
        json.dumps(
            {
                "schema": "agentdecompile.vacuum-queue.v1",
                "pending": ["a"],
                "matched": ["b"],
                "integrated": [],
                "failed": [],
                "difficult": [],
                "attempts": {},
            }
        ),
        encoding="utf-8",
    )
    (work / "state" / "vacuum-session.json").write_text(
        json.dumps({"schema": "agentdecompile.vacuum-session.v1", "status": "finished"}),
        encoding="utf-8",
    )

    status = build_recovery_status(work)
    assert status["autonomyBudget"]["status"] == "bridged"
    assert status["vacuum"]["queueCounts"]["pending"] == 1
    assert status["vacuum"]["queueCounts"]["matched"] == 1
    assert status["vacuum"]["sessionStatus"] == "finished"
    assert status["paths"]["autonomyBudget"]
    assert status["paths"]["vacuumQueue"]


@pytest.mark.asyncio
async def test_provider_status_and_claim_report(tmp_path: Path) -> None:
    work = tmp_path / "run"
    work.mkdir()
    (work / "advisory").mkdir()
    (work / "advisory" / "x.c").write_text("void x(void){}\n", encoding="utf-8")

    provider = RecoveryToolProvider()
    status_result = await provider._handle_status({n("workDir"): str(work)})
    status_payload = json.loads(status_result[0].text)
    assert status_payload["tool"] == "status"
    assert status_payload["counts"]["advisory"] == 1

    claim_result = await provider._handle_claim_report(
        {n("workDir"): str(work), n("terminalStatus"): "partial", n("write"): True}
    )
    claim_payload = json.loads(claim_result[0].text)
    assert claim_payload["tool"] == "claim-report"
    assert claim_payload["schema"] == "agentdecompile.claim-report.v1"
    assert (work / "claim-report.json").is_file()
    assert any(c.get("class") == "advisory-decompiler" for c in claim_payload["claims"])


@pytest.mark.asyncio
async def test_provider_reconstruct_uses_job_helper(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ\x00\x00")
    work = tmp_path / "work"

    def fake_job(input_path: Path, **kwargs: Any) -> dict[str, Any]:
        assert input_path == binary
        assert kwargs.get("stop_after") == "inventory-binary"
        work.mkdir(parents=True, exist_ok=True)
        return {
            "tool": "reconstruct",
            "exitCode": 0,
            "terminalStatus": "partial",
            "workDir": str(work),
            "claimBoundary": "orchestration outcome only",
        }

    monkeypatch.setattr("agentdecompile_recovery.frontdoor.run_reconstruct_job", fake_job)
    provider = RecoveryToolProvider()
    result = await provider._handle_reconstruct(
        {
            n("binaryPath"): str(binary),
            n("workDir"): str(work),
            n("stopAfter"): "inventory-binary",
        }
    )
    payload = json.loads(result[0].text)
    assert payload["tool"] == "reconstruct"
    assert payload["terminalStatus"] == "partial"


def test_manager_registers_recovery_tools() -> None:
    manager = ToolProviderManager()
    manager.register_all_providers()
    names = {tool.name for tool in manager.list_tools()}
    assert "reconstruct" in names
    assert "status" in names
    assert "claim-report" in names
