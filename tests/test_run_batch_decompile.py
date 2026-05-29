"""Unit tests for Tier 1 run-batch-decompile MCP tool."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.batch_analysis import BatchAnalysisToolProvider
from agentdecompile_cli.mcp_server.tool_providers import n
from agentdecompile_cli.mcp_utils.batch_decompile import (
    build_batch_decompile_payload,
    build_ghidrecomp_namespace,
)
from agentdecompile_cli.registry import Tool, get_tool_analysis_tier

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF\x02\x01\x01\x00batch-decompile-test\x00")
    return path


def test_run_batch_decompile_is_tier_one() -> None:
    assert get_tool_analysis_tier(Tool.RUN_BATCH_DECOMPILE) == 1


def test_build_ghidrecomp_namespace_defaults(sample_binary: Path) -> None:
    ns = build_ghidrecomp_namespace(sample_binary)
    assert ns.bin == str(sample_binary.resolve())
    assert ns.output_path == "ghidrecomps"
    assert ns.skip_symbols is True
    assert ns.callgraphs is False


def test_build_batch_decompile_payload_collects_artifacts(
    sample_binary: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_root = tmp_path / "out"
    bin_name = "sample.bin-deadbeef"

    def fake_decompile(_args: SimpleNamespace) -> None:
        decomp_dir = output_root / "results" / "bins" / bin_name / "decomp"
        decomp_dir.mkdir(parents=True, exist_ok=True)
        (decomp_dir / "main-0x1000.c").write_text("int main(){return 0;}", encoding="utf-8")

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.batch_decompile.gen_proj_bin_name_from_path",
        lambda _path: bin_name,
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.batch_decompile.get_bin_output_path",
        lambda root, name: Path(root) / "results" / "bins" / name,
    )

    payload = build_batch_decompile_payload(
        sample_binary,
        output_path=output_root,
        decompile_runner=fake_decompile,
    )
    assert payload["action"] == "run-batch-decompile"
    assert payload["counts"]["decompiledFiles"] == 1
    assert payload["decompiledFiles"][0].endswith("main-0x1000.c")
    assert payload["suggestedTierEscalation"]["recommendedTier"] == 2


def test_build_batch_decompile_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    with pytest.raises(FileNotFoundError):
        build_batch_decompile_payload(missing, decompile_runner=lambda _args: None)


@pytest.mark.asyncio
async def test_provider_run_batch_decompile_success(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_payload(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "action": "run-batch-decompile",
            "binaryPath": str(sample_binary),
            "outputPath": "/tmp/out",
            "decompiledFiles": [],
            "callgraphFiles": [],
            "counts": {"decompiledFiles": 0, "callgraphFiles": 0},
            "suggestedTierEscalation": {"recommendedTier": 2},
        }

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.batch_analysis.build_batch_decompile_payload",
        fake_payload,
    )
    provider = BatchAnalysisToolProvider()
    result = await provider._handle_run_batch_decompile({n("binaryPath"): str(sample_binary)})
    payload = json.loads(result[0].text)
    assert payload["action"] == "run-batch-decompile"


def test_run_batch_decompile_advertised_with_max_tier_two(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_cli.registry import get_advertised_tools_for_list

    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    listed = get_advertised_tools_for_list()
    assert Tool.RUN_BATCH_DECOMPILE.value in listed
    assert Tool.RUN_FILE_TRIAGE.value in listed
