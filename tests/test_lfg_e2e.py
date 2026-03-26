"""Strict ``/lfg`` stack — **sharded** so each pytest case can stay within **120s** (pytest-timeout).

Why the old monolithic run took many minutes (not “10s + 10s + one tool”):

- **Eight** orchestrated steps: shared Track A (import + 3 checkout/mutate/checkin cycles + read-back +
  four ``sync-project`` calls), MCP restarts, local Track B (import + 3 cycles), **Ghidra Server restart**,
  MCP restarts again, §7a persistence proof, **another** MCP restart (strict §0.2), §7b proof.
- Each ``tool-seq`` is **many** tools; ``import-binary`` runs analysis.
- **Nested pytest** runs 27 transport/session tests in a subprocess.

To honor **120 seconds per pytest test**, :func:`run_lfg_cli` supports ``--artifacts-dir`` and
``--from-phase`` / ``--to-phase`` (phase **1..8** = tool blocks in order; **9** = nested pytest).
These tests run **six** slices in order under one shared artifact directory.

Run::

    uv run pytest tests/test_lfg_e2e.py -m lfg -v --timeout=120

Override per-test ceiling with ``LFG_OUTER_PYTEST_TIMEOUT`` (default **120**).

Deselect in quick CI::

    pytest -m "not lfg"

Environment:

- ``GHIDRA_INSTALL_DIR`` — required (skip if unset).
- ``LFG_SKIP=1`` — skip the whole module.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
LFG_SCRIPT = REPO_ROOT / "scripts" / "lfg_validation.py"
_LFG_DRIVER_NAME = "_agentdecompile_lfg_validation_driver"

LFG_SHARD_DIR = REPO_ROOT / ".lfg_run" / "lfg_pytest_sharded"
RUN_ID_FILE = LFG_SHARD_DIR / "run_id.txt"

_PER_TEST_TIMEOUT = int(float(os.environ.get("LFG_OUTER_PYTEST_TIMEOUT", "120")))
# Track A/B include ``checkout-status`` + extra ``search-symbols`` and JSON strict verify — allow more wall time
# than the default (MCP JVM boot + ``import-binary`` + long ``tool-seq`` can exceed 180s wall).
_PER_TEST_TIMEOUT_HEAVY_TOOL_SEQ = max(_PER_TEST_TIMEOUT, 420)

pytestmark = [
    pytest.mark.lfg,
    pytest.mark.e2e,
    pytest.mark.slow,
]


def _load_lfg_module():
    existing = sys.modules.get(_LFG_DRIVER_NAME)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(_LFG_DRIVER_NAME, LFG_SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_LFG_DRIVER_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


def _shard_argv(
    run_id: str,
    ghidra: str,
    *,
    from_phase: int,
    to_phase: int,
    prepare_local_dir: bool,
    skip_pytest: bool,
    nested_pytest_timeout: float | None = None,
    nested_inner: float | None = None,
) -> list[str]:
    argv: list[str] = [
        "--run-id",
        run_id,
        "--ghidra-install-dir",
        ghidra,
        "--manage-mcp",
        "--mcp-port",
        "8099",
        "--manage-ghidra-server",
        "--artifacts-dir",
        str(LFG_SHARD_DIR),
        "--from-phase",
        str(from_phase),
        "--to-phase",
        str(to_phase),
        "--max-wall-seconds",
        "0",
    ]
    if prepare_local_dir:
        argv.append("--prepare-local-dir")
    if skip_pytest:
        argv.append("--skip-pytest")
    if nested_pytest_timeout is not None:
        argv.extend(["--nested-pytest-timeout", str(nested_pytest_timeout)])
    if nested_inner is not None:
        argv.extend(["--nested-pytest-inner-timeout", str(nested_inner)])
    return argv


@pytest.mark.timeout(_PER_TEST_TIMEOUT_HEAVY_TOOL_SEQ)
def test_lfg_shard_01_track_a_shared_only() -> None:
    """Phase 1: shared Track A (import, cycles, read-back, sync-project)."""
    if os.environ.get("LFG_SKIP", "").strip().lower() in ("1", "true", "yes", "on"):
        pytest.skip("LFG_SKIP is set")
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra:
        pytest.skip("GHIDRA_INSTALL_DIR not set — required for LFG stack test")

    shutil.rmtree(LFG_SHARD_DIR, ignore_errors=True)
    LFG_SHARD_DIR.mkdir(parents=True, exist_ok=True)
    run_id = f"lfgpytest_{uuid.uuid4().hex[:12]}"
    RUN_ID_FILE.write_text(run_id, encoding="utf-8")

    mod = _load_lfg_module()
    rc = mod.run_lfg_cli(
        _shard_argv(
            run_id,
            ghidra,
            from_phase=1,
            to_phase=1,
            prepare_local_dir=True,
            skip_pytest=True,
        )
    )
    assert rc == 0, f"shard 01 failed rc={rc}; see {LFG_SHARD_DIR}/lfg_validation.driver.log"


@pytest.mark.timeout(_PER_TEST_TIMEOUT_HEAVY_TOOL_SEQ)
def test_lfg_shard_02_mcp_restart_and_track_b_local() -> None:
    """Phases 2–3: MCP restart, local .gpr Track B."""
    if os.environ.get("LFG_SKIP", "").strip().lower() in ("1", "true", "yes", "on"):
        pytest.skip("LFG_SKIP is set")
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra:
        pytest.skip("GHIDRA_INSTALL_DIR not set — required for LFG stack test")
    assert RUN_ID_FILE.is_file(), "run test_lfg_shard_01_track_a_shared_only first"
    run_id = RUN_ID_FILE.read_text(encoding="utf-8").strip()
    assert run_id, "empty run_id.txt"

    mod = _load_lfg_module()
    rc = mod.run_lfg_cli(
        _shard_argv(
            run_id,
            ghidra,
            from_phase=2,
            to_phase=3,
            prepare_local_dir=False,
            skip_pytest=True,
        )
    )
    assert rc == 0, f"shard 02 failed rc={rc}; see {LFG_SHARD_DIR}/lfg_validation.driver.log"


@pytest.mark.timeout(_PER_TEST_TIMEOUT)
def test_lfg_shard_03_restart_ghidra_and_mcp() -> None:
    """Phases 4–5: Ghidra Server restart, MCP restart (post-Ghidra)."""
    if os.environ.get("LFG_SKIP", "").strip().lower() in ("1", "true", "yes", "on"):
        pytest.skip("LFG_SKIP is set")
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra:
        pytest.skip("GHIDRA_INSTALL_DIR not set — required for LFG stack test")
    assert RUN_ID_FILE.is_file(), "run sharded LFG tests in order from shard 01"
    run_id = RUN_ID_FILE.read_text(encoding="utf-8").strip()

    mod = _load_lfg_module()
    rc = mod.run_lfg_cli(
        _shard_argv(
            run_id,
            ghidra,
            from_phase=4,
            to_phase=5,
            prepare_local_dir=False,
            skip_pytest=True,
        )
    )
    assert rc == 0, f"shard 03 failed rc={rc}; see {LFG_SHARD_DIR}/lfg_validation.driver.log"


@pytest.mark.timeout(_PER_TEST_TIMEOUT)
def test_lfg_shard_04_persist_shared_and_mcp_before_7b() -> None:
    """Phases 6–7: §7a shared persistence proof, MCP restart before §7b."""
    if os.environ.get("LFG_SKIP", "").strip().lower() in ("1", "true", "yes", "on"):
        pytest.skip("LFG_SKIP is set")
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra:
        pytest.skip("GHIDRA_INSTALL_DIR not set — required for LFG stack test")
    assert RUN_ID_FILE.is_file(), "run sharded LFG tests in order from shard 01"
    run_id = RUN_ID_FILE.read_text(encoding="utf-8").strip()

    mod = _load_lfg_module()
    rc = mod.run_lfg_cli(
        _shard_argv(
            run_id,
            ghidra,
            from_phase=6,
            to_phase=7,
            prepare_local_dir=False,
            skip_pytest=True,
        )
    )
    assert rc == 0, f"shard 04 failed rc={rc}; see {LFG_SHARD_DIR}/lfg_validation.driver.log"


@pytest.mark.timeout(_PER_TEST_TIMEOUT)
def test_lfg_shard_05_persist_local_7b() -> None:
    """Phase 8: §7b local persistence proof."""
    if os.environ.get("LFG_SKIP", "").strip().lower() in ("1", "true", "yes", "on"):
        pytest.skip("LFG_SKIP is set")
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra:
        pytest.skip("GHIDRA_INSTALL_DIR not set — required for LFG stack test")
    assert RUN_ID_FILE.is_file(), "run sharded LFG tests in order from shard 01"
    run_id = RUN_ID_FILE.read_text(encoding="utf-8").strip()

    mod = _load_lfg_module()
    rc = mod.run_lfg_cli(
        _shard_argv(
            run_id,
            ghidra,
            from_phase=8,
            to_phase=8,
            prepare_local_dir=False,
            skip_pytest=True,
        )
    )
    assert rc == 0, f"shard 05 failed rc={rc}; see {LFG_SHARD_DIR}/lfg_validation.driver.log"


@pytest.mark.timeout(_PER_TEST_TIMEOUT)
def test_lfg_shard_06_nested_transport_and_session_pytest() -> None:
    """Phase 9: nested ``tests/test_mcp_transport_sdk.py`` + ``tests/test_session_context.py``."""
    if os.environ.get("LFG_SKIP", "").strip().lower() in ("1", "true", "yes", "on"):
        pytest.skip("LFG_SKIP is set")
    ghidra = os.environ.get("GHIDRA_INSTALL_DIR", "").strip()
    if not ghidra:
        pytest.skip("GHIDRA_INSTALL_DIR not set — required for LFG stack test")
    assert RUN_ID_FILE.is_file(), "run sharded LFG tests in order from shard 01"
    run_id = RUN_ID_FILE.read_text(encoding="utf-8").strip()

    mod = _load_lfg_module()
    nested_to = float(os.environ.get("LFG_NESTED_PYTEST_TIMEOUT", "110"))
    inner = float(os.environ.get("LFG_NESTED_PYTEST_INNER_TIMEOUT", "25"))
    rc = mod.run_lfg_cli(
        _shard_argv(
            run_id,
            ghidra,
            from_phase=9,
            to_phase=9,
            prepare_local_dir=False,
            skip_pytest=False,
            nested_pytest_timeout=nested_to,
            nested_inner=inner,
        )
    )
    assert rc == 0, f"shard 06 failed rc={rc}; see {LFG_SHARD_DIR}/lfg_validation.driver.log"

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=120"])