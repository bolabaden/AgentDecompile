from __future__ import annotations

from pathlib import Path

from mizuchi_re.cli import build_parser as build_recover_parser
from mizuchi_re.mizuchi_cli import build_parser as build_frontdoor_parser
from mizuchi_re.tools import inspect_capabilities


def test_mizuchi_recovery_parsers_expose_integrated_commands() -> None:
    recover = build_recover_parser()
    subparsers = next(action for action in recover._actions if getattr(action, "choices", None))
    recover_commands = set(subparsers.choices)
    assert "recover" in recover_commands
    assert "source-parity-synthesize" in recover_commands

    frontdoor = build_frontdoor_parser()
    option_dests = {action.dest for action in frontdoor._actions}
    assert "input" in option_dests
    assert "source_synthesis" in option_dests


def test_mizuchi_recovery_script_surface_is_present_in_agentdecompile_repo() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    capabilities = inspect_capabilities(repo_root)
    local = capabilities["localSurfaces"]

    assert local["oneShotSource"] is True
    assert local["sourceParityOneShot"] is True
    assert local["swkotorInventorySlice"] is True
    assert local["verifyObjdiff"] is True
