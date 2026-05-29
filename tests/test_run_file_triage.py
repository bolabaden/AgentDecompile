"""Unit tests for Tier 0 run-file-triage MCP tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_cli.mcp_server.providers.static_analysis import StaticAnalysisToolProvider
from agentdecompile_cli.mcp_server.tool_providers import n
from agentdecompile_cli.mcp_utils.static_triage import _merge_tier_escalation, build_file_triage_payload
from agentdecompile_cli.registry import Tool, get_tool_analysis_tier

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF\x02\x01\x01\x00HelloAgentDecompile\x00\x00")
    return path


def test_run_file_triage_is_tier_zero() -> None:
    assert get_tool_analysis_tier(Tool.RUN_FILE_TRIAGE) == 0


def test_build_file_triage_payload_core_fields(sample_binary: Path) -> None:
    payload = build_file_triage_payload(
        sample_binary,
        string_limit=10,
        try_yara=False,
        try_capa=False,
        try_binwalk=False,
    )
    assert payload["action"] == "run-file-triage"
    assert payload["binaryPath"] == str(sample_binary.resolve())
    assert len(payload["sha256"]) == 64
    assert payload["file"]["description"]
    assert "values" in payload["strings"]
    assert payload["optionalTools"] == {}
    assert "recommendedTier" in payload["suggestedTierEscalation"]
    assert "externalScans" not in payload


def test_build_file_triage_payload_string_filter(sample_binary: Path) -> None:
    payload = build_file_triage_payload(
        sample_binary,
        string_limit=50,
        string_filter="AgentDecompile",
        try_yara=False,
        try_capa=False,
        try_binwalk=False,
    )
    values = payload["strings"]["values"]
    assert values
    assert all("AgentDecompile" in value for value in values)


def test_build_file_triage_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    with pytest.raises(FileNotFoundError):
        build_file_triage_payload(missing)


@pytest.mark.asyncio
async def test_provider_run_file_triage_success(sample_binary: Path) -> None:
    provider = StaticAnalysisToolProvider()
    raw_args = {
        "binaryPath": str(sample_binary),
        "tryYara": False,
        "tryCapa": False,
        "tryBinwalk": False,
    }
    result = await provider._handle_run_file_triage({n(k): v for k, v in raw_args.items()})
    assert len(result) == 1
    payload = json.loads(result[0].text)
    assert payload["action"] == "run-file-triage"
    assert payload["sha256"]


@pytest.mark.asyncio
async def test_provider_run_file_triage_missing_path() -> None:
    provider = StaticAnalysisToolProvider()
    result = await provider._handle_run_file_triage({n("binaryPath"): "/no/such/file.bin"})
    assert len(result) == 1
    body = json.loads(result[0].text)
    assert "error" in body or body.get("success") is False


def test_run_file_triage_advertised_with_max_tier_two(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_cli.registry import get_advertised_tools_for_list

    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    listed = get_advertised_tools_for_list()
    assert Tool.RUN_FILE_TRIAGE.value in listed


def test_merge_tier_escalation_prefers_higher_bundle_tier() -> None:
    triage = {"recommendedTier": 0, "reason": "archive"}
    bundle = {"suggestedTierEscalation": {"recommendedTier": 2, "reason": "capa findings"}}
    merged = _merge_tier_escalation(triage, bundle)
    assert merged["recommendedTier"] == 2
    assert merged["reason"] == "capa findings"


def test_merge_tier_escalation_keeps_triage_when_higher() -> None:
    triage = {"recommendedTier": 2, "reason": "executable"}
    bundle = {"suggestedTierEscalation": {"recommendedTier": 0, "reason": "archive hint"}}
    merged = _merge_tier_escalation(triage, bundle)
    assert merged["recommendedTier"] == 2
    assert merged["reason"] == "executable"


def test_build_file_triage_payload_embeds_external_scans(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.external_re_scan.shutil.which", lambda name: f"/usr/bin/{name}")

    def fake_runner(command: list[str], *, timeout_ms: int) -> dict:
        return {
            "command": command,
            "exitCode": 0,
            "stdout": "scan output",
            "stderr": "",
            "available": True,
        }

    payload = build_file_triage_payload(
        sample_binary,
        try_yara=False,
        try_capa=False,
        try_binwalk=False,
        external_scan_tools=["capa", "binwalk"],
        external_scan_runner=fake_runner,
    )
    assert "externalScans" in payload
    assert payload["externalScans"]["tools"] == ["capa", "binwalk"]
    assert "capa" in payload["externalScans"]["scans"]
    assert payload["externalScans"]["counts"]["toolsRequested"] == 2


@pytest.mark.asyncio
async def test_provider_run_file_triage_with_external_scans(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.external_re_scan.shutil.which", lambda _name: "/usr/bin/capa")
    provider = StaticAnalysisToolProvider()
    raw_args = {
        "binaryPath": str(sample_binary),
        "tryYara": False,
        "tryCapa": False,
        "tryBinwalk": False,
        "externalScanTools": ["capa"],
    }
    result = await provider._handle_run_file_triage({n(k): v for k, v in raw_args.items()})
    payload = json.loads(result[0].text)
    assert payload["externalScans"]["tools"] == ["capa"]
