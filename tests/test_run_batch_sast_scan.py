"""Unit tests for Tier 1 run-batch-sast-scan MCP tool."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.batch_analysis import BatchAnalysisToolProvider
from agentdecompile_cli.mcp_server.tool_providers import n
from agentdecompile_cli.mcp_utils.batch_sast import build_batch_sast_payload
from agentdecompile_cli.registry import Tool, get_tool_analysis_tier

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF\x02\x01\x01\x00batch-sast-test\x00")
    return path


def test_run_batch_sast_scan_is_tier_one() -> None:
    assert get_tool_analysis_tier(Tool.RUN_BATCH_SAST_SCAN) == 1


def test_build_batch_sast_payload_unavailable_skips_runner(
    sample_binary: Path,
    tmp_path: Path,
) -> None:
    ran = {"value": False}

    def should_not_run(_args: SimpleNamespace) -> None:
        ran["value"] = True

    payload = build_batch_sast_payload(
        sample_binary,
        output_path=tmp_path / "out",
        decompile_runner=should_not_run,
        semgrep_checker=lambda: False,
    )
    assert payload["action"] == "run-batch-sast-scan"
    assert payload["sast"]["available"] is False
    assert payload["sastPath"].endswith("/sast")
    assert payload["sarifFiles"] == []
    assert ran["value"] is False


def test_build_batch_sast_payload_collects_sarifs_and_summary(
    sample_binary: Path,
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "out"
    bin_name = "sample.bin-deadbeef"

    def fake_decompile(args: SimpleNamespace) -> None:
        assert args.sast is True
        assert args.semgrep_rules == ["p/security-audit"]
        assert args.codeql_rules == "/queries/custom"
        bin_output = output_root / "results" / "bins" / bin_name
        sast_dir = bin_output / "sast"
        sast_dir.mkdir(parents=True, exist_ok=True)
        (sast_dir / "semgrep.sarif").write_text("{}", encoding="utf-8")
        (sast_dir / "sast_summary.json").write_text(
            '{"total_findings": 2, "files_scanned": 1}',
            encoding="utf-8",
        )

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.batch_sast.gen_proj_bin_name_from_path",
        lambda _path: bin_name,
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.batch_sast.get_bin_output_path",
        lambda root, name: Path(root) / "results" / "bins" / name,
    )
    try:
        payload = build_batch_sast_payload(
            sample_binary,
            output_path=output_root,
            semgrep_rules=["p/security-audit"],
            codeql_rules="/queries/custom",
            decompile_runner=fake_decompile,
            semgrep_checker=lambda: True,
        )
    finally:
        monkeypatch.undo()

    assert payload["sast"]["available"] is True
    assert payload["counts"]["sarifFiles"] == 1
    assert payload["sarifFiles"][0].endswith("semgrep.sarif")
    assert payload["summary"]["total_findings"] == 2


def test_build_batch_sast_payload_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    with pytest.raises(FileNotFoundError):
        build_batch_sast_payload(
            missing,
            semgrep_checker=lambda: True,
            decompile_runner=lambda _args: None,
        )


@pytest.mark.asyncio
async def test_provider_run_batch_sast_scan_success(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_payload(*_args, **_kwargs):
        return {
            "action": "run-batch-sast-scan",
            "binaryPath": str(sample_binary),
            "sarifFiles": ["/tmp/semgrep.sarif"],
            "counts": {"sarifFiles": 1},
            "sast": {"available": True},
            "suggestedTierEscalation": {"recommendedTier": 2},
        }

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.batch_analysis.build_batch_sast_payload",
        fake_payload,
    )
    provider = BatchAnalysisToolProvider()
    raw_args = {"binaryPath": str(sample_binary)}
    result = await provider._handle_run_batch_sast_scan({n(k): v for k, v in raw_args.items()})
    assert len(result) == 1
    payload = json.loads(result[0].text)
    assert payload["action"] == "run-batch-sast-scan"


def test_run_batch_sast_scan_advertised_with_max_tier_two(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_cli.registry import get_advertised_tools_for_list

    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    listed = get_advertised_tools_for_list()
    assert Tool.RUN_BATCH_SAST_SCAN.value in listed
