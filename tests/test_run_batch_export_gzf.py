"""Unit tests for Tier 1 run-batch-export-gzf MCP tool."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.batch_analysis import BatchAnalysisToolProvider
from agentdecompile_cli.mcp_server.tool_providers import n
from agentdecompile_cli.mcp_utils.batch_gzf import build_batch_gzf_payload
from agentdecompile_cli.registry import Tool, get_tool_analysis_tier

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF\x02\x01\x01\x00batch-gzf-test\x00")
    return path


def test_run_batch_export_gzf_is_tier_one() -> None:
    assert get_tool_analysis_tier(Tool.RUN_BATCH_EXPORT_GZF) == 1


def test_build_batch_gzf_payload_collects_gzf_files(
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_root = tmp_path / "out"
    bin_name = "sample.bin-deadbeef"

    def fake_decompile(args: SimpleNamespace) -> None:
        assert args.gzf is True
        assert args.gzf_path == "gzfs"
        gzf_dir = output_root / "gzfs"
        gzf_dir.mkdir(parents=True, exist_ok=True)
        (gzf_dir / f"{bin_name}.gzf").write_bytes(b"GZIF")

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.batch_gzf.gen_proj_bin_name_from_path",
        lambda _path: bin_name,
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.batch_gzf.get_bin_output_path",
        lambda root, name: Path(root) / "results" / "bins" / name,
    )

    payload = build_batch_gzf_payload(
        sample_binary,
        output_path=output_root,
        decompile_runner=fake_decompile,
    )
    assert payload["action"] == "run-batch-export-gzf"
    assert payload["counts"]["gzfFiles"] == 1
    assert payload["gzfFiles"][0].endswith(f"{bin_name}.gzf")
    assert payload["gzfPath"] == str((output_root / "gzfs").resolve())
    assert payload["suggestedTierEscalation"]["recommendedTier"] == 2


def test_build_batch_gzf_payload_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    with pytest.raises(FileNotFoundError):
        build_batch_gzf_payload(missing, decompile_runner=lambda _args: None)


@pytest.mark.asyncio
async def test_provider_run_batch_export_gzf_success(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_payload(*_args, **_kwargs):
        return {
            "action": "run-batch-export-gzf",
            "binaryPath": str(sample_binary),
            "gzfFiles": ["/tmp/sample.gzf"],
            "counts": {"gzfFiles": 1},
            "suggestedTierEscalation": {"recommendedTier": 2},
        }

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.batch_analysis.build_batch_gzf_payload",
        fake_payload,
    )
    provider = BatchAnalysisToolProvider()
    raw_args = {"binaryPath": str(sample_binary)}
    result = await provider._handle_run_batch_export_gzf({n(k): v for k, v in raw_args.items()})
    assert len(result) == 1
    payload = json.loads(result[0].text)
    assert payload["action"] == "run-batch-export-gzf"
    assert payload["counts"]["gzfFiles"] == 1


def test_run_batch_export_gzf_advertised_with_max_tier_two(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_cli.registry import get_advertised_tools_for_list

    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    listed = get_advertised_tools_for_list()
    assert Tool.RUN_BATCH_EXPORT_GZF.value in listed
