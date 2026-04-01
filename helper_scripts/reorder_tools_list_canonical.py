"""Reorder TOOLS_LIST.md canonical tool sections to match registry.TOOLS (Tool enum).

Drops sections whose headings are not in TOOLS. Inserts placeholder sections for any
missing tool. Rewrites the Table of Contents tool bullets under Canonical Tool Docs.

Run from repo root: uv run python helper_scripts/reorder_tools_list_canonical.py

After reordering, run ``helper_scripts/generate_tools_list.py`` and ensure it prints
``MATCH_EXACT True`` (or add any missing **Overloads** blocks it expects).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

from agentdecompile_cli.registry import TOOL_PARAMS, TOOLS, Tool  # noqa: E402


def _make_placeholder(tool: str, params: list[str]) -> str:
    params_md = "\n".join(
        f"- `{p}` (string, optional): See MCP schema / `registry.py` TOOL_PARAMS."
        for p in params
    )
    if not params_md:
        params_md = "- None."
    sig = f"{tool}({', '.join(params)})" if params else f"{tool}()"
    return (
        f"### `{tool}`\n\n"
        "**Description**: Auto-generated stub; see `src/agentdecompile_cli/registry.py` "
        "and the MCP implementation for full behavior.\n\n"
        "**Parameters**:\n"
        f"{params_md}\n\n"
        "**Overloads**:\n"
        f"- `{sig}` canonical signature.\n\n"
        f"**Synonyms**: `{tool}`\n\n"
        "**Examples**:\n"
        f"- `{tool}`\n\n"
    )


def _parse_canonical_sections(canonical_region: str) -> dict[str, str]:
    header_re = re.compile(r"^### `([^`]+)`\s*$", re.M)
    matches = list(header_re.finditer(canonical_region))
    sections: dict[str, str] = {}
    for i, m in enumerate(matches):
        name = m.group(1)
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(canonical_region)
        sections[name] = canonical_region[start:end]
    return sections


def _rewrite_toc(text: str, tools: list[str]) -> str:
    start = text.index("  - [Canonical Tool Docs](#canonical-tool-docs)\n")
    end = text.index("  - [Usage Tips](#usage-tips)", start)
    prefix = text[:start]
    suffix = text[end:]
    middle = "  - [Canonical Tool Docs](#canonical-tool-docs)\n" + "\n".join(
        f"    - [`{t}`](#{t})" for t in tools
    )
    return prefix + middle + "\n" + suffix


def main() -> None:
    path = REPO / "TOOLS_LIST.md"
    text = path.read_text(encoding="utf-8")

    usage_idx = text.index("## Usage Tips")
    canon_m = re.search(r"^## Canonical Tool Docs\s*\n", text, re.M)
    if not canon_m:
        raise SystemExit("TOOLS_LIST.md: missing ## Canonical Tool Docs heading")

    start_body = canon_m.end()
    canonical_region = text[start_body:usage_idx]
    preamble = text[:start_body]
    tail = text[usage_idx:]

    sections = _parse_canonical_sections(canonical_region)
    tools_set = set(TOOLS)
    for name in list(sections):
        if name not in tools_set:
            del sections[name]

    ordered: list[str] = []
    for tool in TOOLS:
        if tool in sections:
            ordered.append(sections[tool])
        else:
            t_enum = Tool(tool)
            params = list(TOOL_PARAMS.get(t_enum, []))
            ordered.append(_make_placeholder(tool, params))

    new_canonical = "".join(ordered).rstrip() + "\n\n"
    new_text = preamble + new_canonical + tail
    new_text = _rewrite_toc(new_text, TOOLS)

    path.write_text(new_text, encoding="utf-8")
    print(f"Wrote {path} ({len(TOOLS)} canonical tools, TOC updated)")


if __name__ == "__main__":
    main()
