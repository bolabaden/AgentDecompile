"""Mechanical checks for agent-rule files, tests/examples hubs, prototypes, audits."""

from __future__ import annotations

import os
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


def test_agent_rule_files_exist_and_hop() -> None:
    for rel in (
        "AGENTS.md",
        "GEMINI.md",
        "CLAUDE.md",
        "src/CLAUDE.md",
        "src/agentdecompile_cli/CLAUDE.md",
        ".cursorrules",
        "skills/agentdecompile-server-env/SKILL.md",
        ".agents/skills/agentdecompile-server-env/SKILL.md",
    ):
        assert (REPO / rel).is_file(), rel
    agents = (REPO / "AGENTS.md").read_text(encoding="utf-8")
    assert "USAGE.md" in agents
    assert "skills/agentdecompile-server-env/SKILL.md" in agents
    gemini = (REPO / "GEMINI.md").read_text(encoding="utf-8")
    assert "README.md" in gemini
    assert "BEGIN MCP Memory Service" in gemini
    root_claude = (REPO / "CLAUDE.md").read_text(encoding="utf-8")
    assert "src/CLAUDE.md" in root_claude
    assert "src/agentdecompile_cli/CLAUDE.md" in root_claude


def test_cursorrules_registry_triple() -> None:
    canonical, gui_only, advertised = _cleared_registry_triple()
    text = (REPO / ".cursorrules").read_text(encoding="utf-8")
    assert str(canonical) in text
    assert str(advertised) in text
    assert str(gui_only) in text
    assert "72 canonical" not in text
    assert "docs/INDEX.md" in text


def test_tests_and_examples_hubs() -> None:
    tests = (REPO / "tests/README.md").read_text(encoding="utf-8")
    assert "CONTRIBUTING.md" in tests
    assert "README.md" in tests
    examples = (REPO / "examples/README.md").read_text(encoding="utf-8")
    assert "TOOLS_LIST.md" in examples
    assert "historical" in examples.lower() or "snapshot" in examples.lower()
    dump = (REPO / "examples/mcp_responses/mcp_tools_list.md").read_text(encoding="utf-8")
    assert "37 tools" not in dump
    notebook = (REPO / "examples/usage_validation.ipynb").read_text(encoding="utf-8")
    assert "k1_win_gog" not in notebook
    assert "swkotor" not in notebook


def test_prototype_and_audit_hubs() -> None:
    proto = (REPO / "docs/prototypes/README.md").read_text(encoding="utf-8")
    audits = (REPO / "docs/audits/README.md").read_text(encoding="utf-8")
    assert "```mermaid" in proto
    assert "```mermaid" in audits
    assert "feel.md" in proto
    assert "2026-05-24-agent-native-audit.md" in audits
    flow = (REPO / "docs/prototypes/dashboard-flow-evolution/decisions.md").read_text(
        encoding="utf-8"
    )
    assert "2026-08-31-1029-feat-dashboard-flow-evolution-plan.md" in flow
    assert "2026-08-31-0528" not in flow
