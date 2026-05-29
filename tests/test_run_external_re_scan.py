"""Unit tests for Tier 0 run-external-re-scan MCP tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_cli.mcp_server.providers.static_analysis import StaticAnalysisToolProvider
from agentdecompile_cli.mcp_server.tool_providers import n
from agentdecompile_cli.mcp_utils.external_re_scan import build_external_re_scan_payload
from agentdecompile_cli.registry import Tool, get_tool_analysis_tier

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF\x02\x01\x01\x00ExternalRescanTest\x00")
    return path


@pytest.fixture
def yara_rules(tmp_path: Path) -> Path:
    rules = tmp_path / "test.yar"
    rules.write_text('rule test { strings: $a = "ExternalRescanTest" condition: $a }', encoding="utf-8")
    return rules


def _fake_runner(stdout: str = "", stderr: str = "", exit_code: int = 0):
    def runner(command: list[str], *, timeout_ms: int) -> dict:
        return {
            "command": command,
            "exitCode": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "available": True,
        }

    return runner


def test_run_external_re_scan_is_tier_zero() -> None:
    assert get_tool_analysis_tier(Tool.RUN_EXTERNAL_RE_SCAN) == 0


def test_build_external_re_scan_payload_binwalk(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.external_re_scan.shutil.which", lambda name: f"/usr/bin/{name}")
    payload = build_external_re_scan_payload(
        sample_binary,
        tool="binwalk",
        command_runner=_fake_runner("DECIMAL       HEXADECIMAL   DESCRIPTION\n0             0x0           ELF"),
    )
    assert payload["action"] == "run-external-re-scan"
    assert payload["tool"] == "binwalk"
    assert payload["binaryPath"] == str(sample_binary.resolve())
    assert payload["scan"]["available"] is True
    assert payload["lines"]
    assert payload["counts"]["lines"] >= 1


def test_build_external_re_scan_payload_capa_parsed(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capa_json = {"rules": {"accept PE files": {"matches": ["main"]}}}
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.external_re_scan.shutil.which", lambda _name: "/usr/bin/capa")
    payload = build_external_re_scan_payload(
        sample_binary,
        tool="capa",
        command_runner=_fake_runner(json.dumps(capa_json)),
    )
    assert payload["parsed"] == capa_json
    assert payload["suggestedTierEscalation"]["recommendedTier"] == 2


def test_build_external_re_scan_yara_requires_rules_path(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.external_re_scan.shutil.which", lambda _name: "/usr/bin/yara")
    with pytest.raises(ValueError, match="rulesPath"):
        build_external_re_scan_payload(sample_binary, tool="yara", command_runner=_fake_runner())


def test_build_external_re_scan_yara_success(
    sample_binary: Path,
    yara_rules: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.external_re_scan.shutil.which", lambda _name: "/usr/bin/yara")
    payload = build_external_re_scan_payload(
        sample_binary,
        tool="yara",
        rules_path=yara_rules,
        command_runner=_fake_runner("test sample.bin\n0x1000:$a: ExternalRescanTest"),
    )
    assert payload["tool"] == "yara"
    assert payload["rulesPath"] == str(yara_rules.resolve())
    assert payload["suggestedTierEscalation"]["recommendedTier"] == 2


def test_build_external_re_scan_missing_tool_on_path(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.external_re_scan.shutil.which", lambda _name: None)
    payload = build_external_re_scan_payload(sample_binary, tool="capa")
    assert payload["scan"]["available"] is False
    assert payload["scan"]["skipped"] == "binary not on PATH"
    assert payload["lines"] == []


def test_build_external_re_scan_unsupported_tool_raises(sample_binary: Path) -> None:
    with pytest.raises(ValueError, match="Unsupported tool"):
        build_external_re_scan_payload(sample_binary, tool="radare2")


def test_build_external_re_scan_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    with pytest.raises(FileNotFoundError):
        build_external_re_scan_payload(missing, tool="binwalk")


@pytest.mark.asyncio
async def test_provider_run_external_re_scan_success(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.external_re_scan.shutil.which", lambda _name: "/usr/bin/binwalk")
    provider = StaticAnalysisToolProvider()
    raw_args = {"binaryPath": str(sample_binary), "tool": "binwalk"}
    result = await provider._handle_run_external_re_scan({n(k): v for k, v in raw_args.items()})
    assert len(result) == 1
    payload = json.loads(result[0].text)
    assert payload["action"] == "run-external-re-scan"
    assert payload["tool"] == "binwalk"


@pytest.mark.asyncio
async def test_provider_run_external_re_scan_missing_path() -> None:
    provider = StaticAnalysisToolProvider()
    result = await provider._handle_run_external_re_scan(
        {n("binaryPath"): "/no/such/file.bin", n("tool"): "binwalk"},
    )
    assert len(result) == 1
    body = json.loads(result[0].text)
    assert "error" in body or body.get("success") is False


def test_run_external_re_scan_advertised_with_max_tier_two(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_cli.registry import get_advertised_tools_for_list

    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    listed = get_advertised_tools_for_list()
    assert Tool.RUN_EXTERNAL_RE_SCAN.value in listed
