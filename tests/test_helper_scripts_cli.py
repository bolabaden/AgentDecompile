from __future__ import annotations

import json
import subprocess
import sys

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "helper_scripts"


def _run_helper(script_name: str, *args: str, timeout: int = 40) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(HELPERS / script_name), *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class TestHelperScriptsCLI:
    def test_integration_test_help(self) -> None:
        proc = _run_helper("integration_test.py", "--help")
        assert proc.returncode == 0
        assert "--checks" in proc.stdout
        assert "--json" in proc.stdout

    def test_integration_test_json_single_check(self) -> None:
        proc = _run_helper("integration_test.py", "--checks", "normalization", "--json")
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["failed"] == 0
        assert payload["passed"] == 1
        assert payload["results"][0]["name"] == "normalization"

    def test_integration_test_rejects_unknown_check(self) -> None:
        proc = _run_helper("integration_test.py", "--checks", "nope")
        assert proc.returncode == 2
        assert "Unknown checks" in proc.stderr

    def test_performance_benchmark_help(self) -> None:
        proc = _run_helper("performance_benchmark.py", "--help")
        assert proc.returncode == 0
        assert "--iterations" in proc.stdout
        assert "--output" in proc.stdout

    def test_performance_benchmark_json(self, tmp_path: Path) -> None:
        out = tmp_path / "bench.json"
        proc = _run_helper(
            "performance_benchmark.py",
            "--iterations",
            "1",
            "--json",
            "--output",
            str(out),
            timeout=90,
        )
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["total"] >= 4
        assert out.exists()
        saved = json.loads(out.read_text(encoding="utf-8"))
        assert saved["total"] == payload["total"]

    def test_update_headers_help(self) -> None:
        proc = _run_helper("update_headers.py", "--help")
        assert proc.returncode == 0
        assert "--base" in proc.stdout
        assert "--dry-run" in proc.stdout

    def test_update_headers_dry_run_missing_base(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist"
        proc = _run_helper("update_headers.py", "--base", str(missing), "--dry-run")
        assert proc.returncode == 1
        assert "missing file" in proc.stdout.lower()


@pytest.mark.parametrize(
    "script_name",
    ["integration_test.py", "performance_benchmark.py", "update_headers.py", "mcp_remote_matrix.py"],
)
def test_helper_scripts_are_present(script_name: str) -> None:
    assert (HELPERS / script_name).exists()


def test_mcp_remote_matrix_help() -> None:
    proc = _run_helper("mcp_remote_matrix.py", "--help")
    assert proc.returncode == 0
    assert "--server-url" in proc.stdout
    assert "--print-cases" in proc.stdout


def test_mcp_remote_matrix_print_cases_json() -> None:
    proc = _run_helper("mcp_remote_matrix.py", "--print-cases", "--json")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "cases" in payload
    assert isinstance(payload["cases"], list)
    assert len(payload["cases"]) >= 8


def test_mcp_remote_matrix_noop_without_run_or_print() -> None:
    proc = _run_helper("mcp_remote_matrix.py", "--json")
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert "Nothing executed" in payload["message"]
