"""Mechanical checks for in-scope user-facing docs (docs consolidation U10)."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

from agentdecompile_cli.registry import DISABLED_GUI_ONLY_TOOLS, Tool

REPO = Path(__file__).resolve().parents[1]

IN_SCOPE_MD = [
    "README.md",
    "USAGE.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CONCEPTS.md",
    "docs/INDEX.md",
    "docs/HERO.md",
    "docs/CORPUS_PIPELINE.md",
    "docs/corpus/README.md",
    "docs/CRITICAL_PATH.md",
    "docs/IMPORT_EXPORT_GUIDE.md",
    "docs/QUICKSTART_IMPORT_EXPORT.md",
    "docs/MCP_CONFIGURATION_SECURITY.md",
    "docs/session-handling.md",
    "docs/SharedProjectCLI.md",
    "docs/CONTEXT_FUSION.md",
    "docs/Podman-Windows-Complete-Setup-Guide.md",
]

FORBIDDEN = (
    "k1_win_gog",
    "swkotor",
    "C:/GitHub",
    ".venv/Scripts",
    "Session-Validated",
    "MCP_AGENTDECOMPILE_USAGE",
    "SRC_ENTRYPOINTS_CALL_GRAPH",
    "72 canonical",
)

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

_MD_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
_HTML_HREF = re.compile(r"""href=["']([^"']+)["']""", re.I)
_BACKTICK_PATH = re.compile(r"`([^`]+?\.(?:md|html))`")
_MERMAID_PATH = re.compile(r"(?:docs/|[\w./-]+/)?[\w.-]+\.(?:md|html)")


def _cleared_registry_triple() -> tuple[int, int, int]:
    saved = {key: os.environ.pop(key, None) for key in _ENV_CLEAR}
    try:
        canonical = len(list(Tool))
        gui_only = len(DISABLED_GUI_ONLY_TOOLS)
        advertised = canonical - gui_only
        return canonical, gui_only, advertised
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _extract_relative_paths(text: str, source: Path) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    candidates: list[str] = []
    for match in _MD_LINK.finditer(text):
        candidates.append(match.group(1).split()[0])
    for match in _HTML_HREF.finditer(text):
        candidates.append(match.group(1))
    for match in _BACKTICK_PATH.finditer(text):
        candidates.append(match.group(1))
    if "```mermaid" in text:
        for block in re.findall(r"```mermaid(.*?)```", text, re.S):
            for token in _MERMAID_PATH.findall(block):
                if "/" in token or token.endswith((".md", ".html")):
                    candidates.append(token)
    for raw in candidates:
        url = raw.strip().split("#", 1)[0]
        if not url or url.startswith(("http://", "https://", "mailto:", "ghidra://")):
            continue
        if url.startswith(("data:", "javascript:")):
            continue
        target = (source.parent / url).resolve()
        found.append((raw, target))
    return found


@pytest.fixture(scope="module")
def registry_triple() -> tuple[int, int, int]:
    return _cleared_registry_triple()


def test_in_scope_relative_links_resolve() -> None:
    missing: list[str] = []
    for rel in IN_SCOPE_MD + ["docs/index.html"]:
        path = REPO / rel
        assert path.is_file(), f"missing in-scope file {rel}"
        for raw, target in _extract_relative_paths(path.read_text(encoding="utf-8"), path):
            if not target.exists():
                missing.append(f"{rel}: {raw}")
    assert missing == [], "broken relative paths:\n" + "\n".join(missing)


def test_forbidden_tokens_absent() -> None:
    hits: list[str] = []
    for rel in IN_SCOPE_MD:
        text = (REPO / rel).read_text(encoding="utf-8")
        for token in FORBIDDEN:
            if token in text:
                hits.append(f"{rel}: {token}")
    assert hits == [], "forbidden tokens still present:\n" + "\n".join(hits)


def test_required_security_substrings() -> None:
    security = (REPO / "SECURITY.md").read_text(encoding="utf-8").lower()
    assert "do not open a public github issue" in security
    session = (REPO / "docs/session-handling.md").read_text(encoding="utf-8")
    usage = (REPO / "USAGE.md").read_text(encoding="utf-8")
    assert "Session IDs must not be used for authentication" in session or (
        "session IDs are not authentication" in usage
    )
    mcp_sec = (REPO / "docs/MCP_CONFIGURATION_SECURITY.md").read_text(encoding="utf-8")
    assert (
        "AGENT_DECOMPILE_AUTH_ENABLED" in mcp_sec
        or "127.0.0.1" in mcp_sec
        or "0.0.0.0" in mcp_sec
    )


def test_readme_line_count_and_start_recipes() -> None:
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert readme.count("\n") + 1 < 350
    lowered = readme.lower()
    assert "stdio" in lowered
    assert "streamable-http" in lowered or "/mcp" in lowered
    assert "docker" in lowered
    assert re.search(r"^## installation\b", readme, re.I | re.M)


def test_readme_registry_triple(registry_triple: tuple[int, int, int]) -> None:
    canonical, gui_only, advertised = registry_triple
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert str(canonical) in readme
    assert str(advertised) in readme
    assert str(gui_only) in readme


def test_usage_does_not_own_foreign_surfaces() -> None:
    usage = (REPO / "USAGE.md").read_text(encoding="utf-8")
    assert not re.search(r"^## installation\b", usage, re.I | re.M)
    assert "extract → identify → merge" not in usage.lower()
    assert "canonical MCP tools" not in usage


def test_quickstart_is_stub() -> None:
    text = (REPO / "docs/QUICKSTART_IMPORT_EXPORT.md").read_text(encoding="utf-8")
    assert text.count("\n") + 1 < 30
    assert "IMPORT_EXPORT_GUIDE.md" in text


def test_pages_hero_copy_and_installation_fragment() -> None:
    hero = (REPO / "docs/HERO.md").read_text(encoding="utf-8")
    html = (REPO / "docs/index.html").read_text(encoding="utf-8")
    headline = "Connect AI to Ghidra"
    assert headline in hero
    assert headline in html
    assert "Analyze with agents" in html
    assert "Recover rebuildable C" in html
    assert "Run your way" in html
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert re.search(r"^## installation\b", readme, re.I | re.M)
    for match in _HTML_HREF.finditer(html):
        href = match.group(1)
        if "github.com" in href and "#installation" in href:
            assert re.search(r"^## installation\b", readme, re.I | re.M)
