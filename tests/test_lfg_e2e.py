"""Pytest entry for strict ``/lfg`` validation (see ``scripts/lfg_validation.py``).

Fast tests in this module run in normal CI (``-m "not lfg"``). The full Ghidra Server +
MCP collaboration stack is opt-in::

    LFG_RUN=1 uv run pytest tests/test_lfg_e2e.py -m lfg -v --timeout=900
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_LFG_SCRIPT = _REPO_ROOT / "scripts" / "lfg_validation.py"


def _load_lfg_validation() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lfg_validation", _LFG_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {_LFG_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def lfg() -> ModuleType:
    return _load_lfg_validation()


@pytest.mark.unit
def test_lfg_run_lfg_cli_missing_ghidra_install_dir(lfg: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    rc = lfg.run_lfg_cli(["--run-id", "pytest-smoke-missing-ghidra"])
    assert rc == 2


@pytest.mark.unit
def test_lfg_run_lfg_cli_invalid_phase_range(lfg: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ghidra = tmp_path / "ghidra_fake"
    ghidra.mkdir()
    (ghidra / "server").mkdir()
    (ghidra / "server" / "server.conf").write_text("-p25100\n", encoding="utf-8")
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(ghidra))
    rc = lfg.run_lfg_cli(
        [
            "--run-id",
            "pytest-smoke-bad-phase",
            "--from-phase",
            "10",
            "--to-phase",
            "9",
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
        ],
    )
    assert rc == 2


def _lfg_full_stack_enabled() -> bool:
    return os.environ.get("LFG_RUN", "").strip().lower() in {"1", "true", "yes"}


@pytest.mark.lfg
@pytest.mark.timeout(900)
@pytest.mark.skipif(not _lfg_full_stack_enabled(), reason="Set LFG_RUN=1 to run full /lfg stack")
def test_lfg_full_stack_via_run_lfg_cli(lfg: ModuleType) -> None:
    """Run ``scripts/lfg_validation.run_lfg_cli`` (manage MCP + optional Ghidra Server)."""
    run_id = os.environ.get("LFG_RUN_ID", "pytest_lfg_e2e")
    argv = [
        "--run-id",
        run_id,
        "--manage-mcp",
        "--prepare-local-dir",
    ]
    if os.environ.get("LFG_MANAGE_GHIDRA_SERVER", "").strip().lower() in {"1", "true", "yes"}:
        argv.append("--manage-ghidra-server")
    rc = lfg.run_lfg_cli(argv)
    assert rc == 0
