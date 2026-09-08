"""Mechanical checks for secondary doc surfaces (not the landing-page set)."""

from __future__ import annotations

import os
import re
from pathlib import Path

from agentdecompile_cli.registry import DISABLED_GUI_ONLY_TOOLS, Tool

REPO = Path(__file__).resolve().parents[1]

_ENV_CLEAR = (
    "AGENTDECOMPILE_TOOL_SURFACE",
    "AGENT_DECOMPILE_TOOL_SURFACE",
    "AGENTDECOMPILE_ENABLE_TOOLS",
    "AGENT_DECOMPILE_ENABLE_TOOLS",
    "AGENTDECOMPILE_DISABLE_TOOLS",
    "AGENT_DECOMPILE_DISABLE_TOOLS",
    "AGENTDECOMPILE_AUTO_CHECKIN",
    "AGENT_DECOMPILE_AUTO_CHECKIN",
)

_PREAMBLE_END = re.compile(r"^## Canonical Tool Docs\s*$", re.M)


def _cleared_registry_triple() -> tuple[int, int, int]:
    saved = {key: os.environ.pop(key, None) for key in _ENV_CLEAR}
    try:
        canonical = len(list(Tool))
        gui_only = len(DISABLED_GUI_ONLY_TOOLS)
        return canonical, gui_only, canonical - gui_only
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _tools_list_preamble() -> str:
    text = (REPO / "TOOLS_LIST.md").read_text(encoding="utf-8")
    match = _PREAMBLE_END.search(text)
    assert match, "TOOLS_LIST.md is missing Canonical Tool Docs"
    return text[: match.start()]


def test_tools_list_preamble_registry_triple_and_hops() -> None:
    preamble = _tools_list_preamble()
    canonical, gui_only, advertised = _cleared_registry_triple()
    assert str(canonical) in preamble
    assert str(advertised) in preamble
    assert str(gui_only) in preamble
    assert "72 canonical" not in preamble
    assert "README.md" in preamble
    assert "USAGE.md" in preamble
    assert "Do not hand-edit" in preamble


def test_strategy_and_vision_hops() -> None:
    strategy = (REPO / "STRATEGY.md").read_text(encoding="utf-8")
    vision = (REPO / "VISION.md").read_text(encoding="utf-8")
    assert "VISION.md" in strategy
    assert "README.md" in strategy
    assert "README.md" in vision
    assert "STRATEGY.md" in vision
    assert "rhardcode" not in vision


def test_plans_and_solutions_hubs() -> None:
    plans = (REPO / "docs/plans/README.md").read_text(encoding="utf-8")
    solutions = (REPO / "docs/solutions/README.md").read_text(encoding="utf-8")
    assert "Frozen" in plans
    assert "living" in plans.lower()
    assert "2026-08-30-corpus-semantic-pipeline-living-plan.md" in plans
    assert "```mermaid" in plans
    assert "```mermaid" in solutions
    assert "workflow-learnings" in solutions
    assert "72 canonical" not in solutions


def test_skills_catalog() -> None:
    catalog = (REPO / "skills/README.md").read_text(encoding="utf-8")
    assert "source-recovery" in catalog
    assert "tiered-re-analysis" in catalog
    assert "README.md" in catalog
    source = (REPO / "skills/source-recovery/SKILL.md").read_text(encoding="utf-8")
    agents = (REPO / ".agents/skills/source-recovery/SKILL.md").read_text(encoding="utf-8")
    assert source == agents


def test_webui_hero_matches_hero_doc() -> None:
    hero = (REPO / "docs/HERO.md").read_text(encoding="utf-8")
    html = (REPO / "src/agentdecompile_cli/webui_assets/index.html").read_text(
        encoding="utf-8"
    )
    assert "Connect AI to Ghidra" in hero
    assert "Connect AI to Ghidra" in html
    assert "List functions, decompile code, rename symbols" in html
