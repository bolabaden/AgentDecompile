"""Unit tests for Tier 1 run-decomp-match MCP tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentdecompile_cli.mcp_server.providers.decomp_match import DecompMatchToolProvider
from agentdecompile_cli.mcp_server.tool_providers import n
from agentdecompile_cli.mcp_utils.decomp_match import (
    build_decomp_match_bundle_payload,
    build_decomp_match_payload,
)
from agentdecompile_cli.registry import Tool, get_advertised_tools_for_list, get_tool_analysis_tier

pytestmark = pytest.mark.unit


@pytest.fixture
def sample_asm(tmp_path: Path) -> Path:
    path = tmp_path / "func.s"
    path.write_text(
        ".section .text\n"
        ".global test\n"
        "test:\n"
        "    li r3, 1\n"
        "    blr\n",
        encoding="utf-8",
    )
    return path


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


def test_run_decomp_match_is_tier_one() -> None:
    assert get_tool_analysis_tier(Tool.RUN_DECOMP_MATCH) == 1


def test_build_decomp_match_m2c_success(
    sample_asm: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")
    payload = build_decomp_match_payload(
        tool="m2c",
        assembly_path=sample_asm,
        function_name="test",
        target="ppc-mwcc-c++",
        command_runner=_fake_runner("int test(void) { return 1; }"),
    )
    assert payload["tool"] == "m2c"
    assert payload["decompiledC"] == "int test(void) { return 1; }"
    assert payload["routing"]["bytecodeMatchTool"] == "objdiff"
    assert payload["routing"]["notBytecodeMatch"] == "match-function"


def test_build_decomp_match_m2c_missing_asm_raises() -> None:
    with pytest.raises(ValueError, match="assemblyPath"):
        build_decomp_match_payload(tool="m2c")


def test_build_decomp_match_m2c_missing_binary(
    sample_asm: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda _name: None)
    payload = build_decomp_match_payload(tool="m2c", assembly_path=sample_asm)
    assert payload["scan"]["available"] is False


def test_build_decomp_match_objdiff_report_parsed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "decomp"
    project.mkdir()
    (project / "objdiff.json").write_text("{}", encoding="utf-8")
    report = {
        "units": [
            {
                "name": "d_a_wall",
                "measures": {"fuzzy_match_percent": 42.5, "total_functions": 10, "matched_functions": 4},
                "functions": [
                    {"name": "fn_a", "fuzzy_match_percent": 100.0, "size": 32},
                    {"name": "fn_b", "fuzzy_match_percent": 80.0, "size": 64},
                ],
            }
        ]
    }
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")
    payload = build_decomp_match_payload(
        tool="objdiff",
        project_path=project,
        unit_name="d_a_wall",
        command_runner=_fake_runner(json.dumps(report)),
    )
    assert payload["tool"] == "objdiff"
    assert payload["summary"]["overallMatchPercent"] == 42.5
    assert payload["summary"]["units"][0]["nonmatchingCount"] == 1
    assert payload["suggestedTierEscalation"]["recommendedTier"] == 2


def test_build_decomp_match_objdiff_100_percent_suggests_tier1(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "decomp"
    project.mkdir()
    report = {
        "units": [
            {
                "name": "tu",
                "measures": {"fuzzy_match_percent": 100.0},
                "functions": [{"name": "fn", "fuzzy_match_percent": 100.0, "size": 8}],
            }
        ]
    }
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")
    payload = build_decomp_match_payload(
        tool="objdiff",
        project_path=project,
        command_runner=_fake_runner(json.dumps(report)),
    )
    assert payload["suggestedTierEscalation"]["recommendedTier"] == 1


def test_build_decomp_match_objdiff_requires_project_or_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")
    with pytest.raises(ValueError, match="projectPath"):
        build_decomp_match_payload(tool="objdiff", objdiff_mode="report")


def test_build_decomp_match_permuter_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    perm_dir = tmp_path / "perm"
    perm_dir.mkdir()
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")
    payload = build_decomp_match_payload(
        tool="permuter",
        permuter_dir=perm_dir,
        jobs=2,
        command_runner=_fake_runner("score 0\n"),
    )
    assert payload["tool"] == "permuter"
    assert payload["scan"]["exitCode"] == 0


def test_build_decomp_match_bundle_skips_missing_inputs(
    sample_asm: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")
    payload = build_decomp_match_bundle_payload(
        tools=["m2c", "objdiff", "permuter"],
        assembly_path=sample_asm,
        command_runner=_fake_runner("ok"),
    )
    assert payload["mode"] == "bundle"
    assert "m2c" in payload["scans"]
    assert payload["scans"]["objdiff"]["scan"]["skipped"]
    assert payload["scans"]["permuter"]["scan"]["skipped"]


def test_build_decomp_match_unsupported_tool_raises() -> None:
    with pytest.raises(ValueError, match="Unsupported tool"):
        build_decomp_match_payload(tool="radare2")


def test_build_decomp_match_permuter_requires_dir() -> None:
    with pytest.raises(ValueError, match="permuterDir"):
        build_decomp_match_payload(tool="permuter")


def test_build_decomp_match_objdiff_diff_project_requires_unit_or_symbol(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "decomp"
    project.mkdir()
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda name: f"/usr/bin/{name}")
    with pytest.raises(ValueError, match="unitName or symbol"):
        build_decomp_match_payload(
            tool="objdiff",
            project_path=project,
            objdiff_mode="diff",
        )


def test_analysis_gate_exempt_run_decomp_match() -> None:
    from agentdecompile_cli.mcp_utils.program_analysis import analysis_gate_exempt_tool

    assert analysis_gate_exempt_tool("rundecompmatch") is True


def test_run_decomp_match_advertised_with_max_tier_two(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENTDECOMPILE_MAX_ANALYSIS_TIER", "2")
    listed = get_advertised_tools_for_list()
    assert Tool.RUN_DECOMP_MATCH.value in listed


@pytest.mark.asyncio
async def test_provider_run_decomp_match_m2c(
    sample_asm: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agentdecompile_cli.mcp_utils.decomp_match.shutil.which", lambda _name: "/usr/bin/m2c")
    provider = DecompMatchToolProvider(program_info=None)
    raw_args = {"tool": "m2c", "assemblyPath": str(sample_asm), "functionName": "test"}
    result = await provider._handle_run_decomp_match({n(k): v for k, v in raw_args.items()})
    payload = json.loads(result[0].text)
    assert payload["action"] == "run-decomp-match"
    assert payload["tool"] == "m2c"


@pytest.mark.asyncio
async def test_provider_run_decomp_match_missing_tool_or_tools() -> None:
    provider = DecompMatchToolProvider(program_info=None)
    result = await provider._handle_run_decomp_match({})
    payload = json.loads(result[0].text)
    assert payload["success"] is False
    assert "tool or tools is required" in payload["error"].lower()


def test_run_decomp_match_advertised() -> None:
    listed = get_advertised_tools_for_list()
    assert Tool.RUN_DECOMP_MATCH.value in listed
