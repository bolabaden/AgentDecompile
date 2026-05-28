"""Pytest entry for strict ``/lfg`` validation (see ``scripts/lfg_validation.py``).

Fast tests in this module run in normal CI (``-m "not lfg"``). The full Ghidra Server +
MCP collaboration stack is opt-in::

    LFG_RUN=1 uv run pytest tests/test_lfg_e2e.py -m lfg -v --timeout=900
"""

from __future__ import annotations

import importlib.util
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_LFG_SCRIPT = _REPO_ROOT / "scripts" / "lfg_validation.py"

_EXIT_OK = 0
_EXIT_BAD_ARGS_OR_ENV = 2  # run_lfg_cli: bad args or environment

_TRUTHY_ENV = frozenset({"1", "true", "yes"})


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY_ENV


def _load_lfg_validation() -> ModuleType:
    spec = importlib.util.spec_from_file_location("lfg_validation", _LFG_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {_LFG_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    # Required: lfg_validation uses @dataclass during import (needs module in sys.modules).
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_lfg = _load_lfg_validation()


def _run(argv: Sequence[str]) -> int:
    return _lfg.run_lfg_cli(list(argv))


@pytest.mark.unit
def test_lfg_run_lfg_cli_missing_ghidra_install_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    assert _run(["--run-id", "pytest-smoke-missing-ghidra"]) == _EXIT_BAD_ARGS_OR_ENV


@pytest.mark.unit
def test_lfg_run_lfg_cli_invalid_phase_range(tmp_path: Path) -> None:
    assert (
        _run(
            [
                "--run-id",
                "pytest-smoke-bad-phase",
                "--ghidra-install-dir",
                str(tmp_path / "unused"),
                "--from-phase",
                "10",
                "--to-phase",
                "9",
            ]
        )
        == _EXIT_BAD_ARGS_OR_ENV
    )


@pytest.mark.lfg
@pytest.mark.timeout(900)
@pytest.mark.skipif(not _env_flag("LFG_RUN"), reason="Set LFG_RUN=1 to run full /lfg stack")
def test_lfg_full_stack_via_run_lfg_cli() -> None:
    argv = [
        "--run-id",
        os.environ.get("LFG_RUN_ID", "pytest_lfg_e2e"),
        "--manage-mcp",
        "--prepare-local-dir",
    ]
    if _env_flag("LFG_MANAGE_GHIDRA_SERVER"):
        argv.append("--manage-ghidra-server")
    assert _run(argv) == _EXIT_OK
