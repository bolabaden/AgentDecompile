from __future__ import annotations

from pathlib import Path

from agentdecompile_recovery.cli import build_parser as build_recover_parser
from agentdecompile_recovery.cli import default_work_dir as recover_default_work_dir
from agentdecompile_recovery.frontdoor import build_parser as build_frontdoor_parser
from agentdecompile_recovery.frontdoor import default_work_dir as frontdoor_default_work_dir
from agentdecompile_recovery.tools import inspect_capabilities


def test_recovery_parsers_expose_integrated_commands() -> None:
    recover = build_recover_parser()
    subparsers = next(action for action in recover._actions if getattr(action, "choices", None))
    recover_commands = set(subparsers.choices)
    assert "recover" in recover_commands
    assert "source-parity-synthesize" in recover_commands

    frontdoor = build_frontdoor_parser()
    option_dests = {action.dest for action in frontdoor._actions}
    assert "input" in option_dests
    assert "source_synthesis" in option_dests


def test_recovery_script_surface_is_present_in_agentdecompile_repo() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    capabilities = inspect_capabilities(repo_root)
    local = capabilities["localSurfaces"]

    assert local["oneShotSource"] is True
    assert local["sourceParityOneShot"] is True
    assert local["swkotorInventorySlice"] is True
    assert local["verifyObjdiff"] is True


def test_recovery_defaults_use_agentdecompile_owned_target_roots(tmp_path: Path) -> None:
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ" + b"\0" * 8192)

    recover_dir = recover_default_work_dir(binary)
    frontdoor_dir = frontdoor_default_work_dir(binary)

    assert recover_dir.parts[:2] == ("target", "agentdecompile-recover")
    assert frontdoor_dir.parts[:2] == ("target", "agentdecompile-reconstruct")
