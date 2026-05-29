"""Unit tests for Tier 1 run-batch-bsim-signatures MCP tool."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentdecompile_cli.mcp_server.providers.batch_analysis import BatchAnalysisToolProvider
from agentdecompile_cli.mcp_server.tool_providers import n
from agentdecompile_cli.mcp_utils.batch_bsim import build_batch_bsim_payload
from agentdecompile_cli.registry import Tool, get_tool_analysis_tier

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"\x7fELF\x02\x01\x01\x00batch-bsim-test\x00")
    return path


def test_run_batch_bsim_signatures_is_tier_one() -> None:
    assert get_tool_analysis_tier(Tool.RUN_BATCH_BSIM_SIGNATURES) == 1


def test_build_batch_bsim_payload_unavailable_skips_runner(
    sample_binary: Path,
    tmp_path: Path,
) -> None:
    ran = {"value": False}

    def should_not_run(_args: SimpleNamespace) -> None:
        ran["value"] = True

    payload = build_batch_bsim_payload(
        sample_binary,
        output_path=tmp_path / "out",
        decompile_runner=should_not_run,
        bsim_checker=lambda: False,
    )
    assert payload["action"] == "run-batch-bsim-signatures"
    assert payload["bsim"]["available"] is False
    assert payload["signatureFiles"] == []
    assert ran["value"] is False


def test_build_batch_bsim_payload_collects_signatures(
    sample_binary: Path,
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "out"
    bin_name = "sample.bin-deadbeef"
    sig_name = "sigs_deadbeef_sample.bin"

    def fake_decompile(args: SimpleNamespace) -> None:
        assert args.bsim is True
        assert args.bsim_template == "medium_nosize"
        assert args.bsim_cat == ["family:test"]
        sig_dir = output_root / "bsim-xmls"
        sig_dir.mkdir(parents=True, exist_ok=True)
        (sig_dir / sig_name).write_text("<xml/>", encoding="utf-8")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.batch_bsim.gen_proj_bin_name_from_path",
        lambda _path: bin_name,
    )
    monkeypatch.setattr(
        "agentdecompile_cli.mcp_utils.batch_bsim.get_bin_output_path",
        lambda root, name: Path(root) / "results" / "bins" / name,
    )
    try:
        payload = build_batch_bsim_payload(
            sample_binary,
            output_path=output_root,
            bsim_categories=["family:test"],
            decompile_runner=fake_decompile,
            bsim_checker=lambda: True,
        )
    finally:
        monkeypatch.undo()

    assert payload["bsim"]["available"] is True
    assert payload["counts"]["signatureFiles"] == 1
    assert payload["signatureFiles"][0].endswith(sig_name)
    assert payload["bsimCategories"] == ["family:test"]


def test_build_batch_bsim_payload_missing_file_raises(tmp_path: Path) -> None:
    missing = tmp_path / "missing.bin"
    with pytest.raises(FileNotFoundError):
        build_batch_bsim_payload(missing, bsim_checker=lambda: True, decompile_runner=lambda _args: None)


@pytest.mark.asyncio
async def test_provider_run_batch_bsim_signatures_success(
    sample_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_payload(*_args, **_kwargs):
        return {
            "action": "run-batch-bsim-signatures",
            "binaryPath": str(sample_binary),
            "signatureFiles": ["/tmp/sigs.xml"],
            "counts": {"signatureFiles": 1},
            "bsim": {"available": True},
            "suggestedTierEscalation": {"recommendedTier": 2},
        }

    monkeypatch.setattr(
        "agentdecompile_cli.mcp_server.providers.batch_analysis.build_batch_bsim_payload",
        fake_payload,
    )
    provider = BatchAnalysisToolProvider()
    raw_args = {"binaryPath": str(sample_binary)}
    result = await provider._handle_run_batch_bsim_signatures({n(k): v for k, v in raw_args.items()})
    assert len(result) == 1
    payload = json.loads(result[0].text)
    assert payload["action"] == "run-batch-bsim-signatures"


def test_run_batch_bsim_signatures_advertised_with_max_tier_two(monkeypatch: pytest.MonkeyPatch) -> None:
    from agentdecompile_cli.registry import get_advertised_tools_for_list

    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    listed = get_advertised_tools_for_list()
    assert Tool.RUN_BATCH_BSIM_SIGNATURES.value in listed
