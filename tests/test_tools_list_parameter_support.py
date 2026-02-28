from __future__ import annotations

import re

from pathlib import Path

from agentdecompile_cli.registry import TOOLS, TOOL_PARAMS, ToolRegistry, normalize_identifier


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _parse_tools_list() -> dict[str, dict[str, set[str]]]:
    text = (_repo_root() / "TOOLS_LIST.md").read_text(encoding="utf-8")
    parts = re.split(r"^### `([^`]+)`(?: \(forwards to `([^`]+)`\))?\n", text, flags=re.M)

    result: dict[str, dict[str, set[str]]] = {}
    for idx in range(1, len(parts), 3):
        tool_name: str = parts[idx]
        forwarded_to: str | None = parts[idx + 1]
        body: str = parts[idx + 2]
        canonical_tool: str = forwarded_to or tool_name

        params_match: re.Match[str] | None = re.search(
            r"\*\*Parameters\*\*:\n(.*?)(?:\n\*\*Overloads\*\*|\n\*\*Synonyms\*\*|\n\*\*Examples\*\*)",
            body,
            flags=re.S,
        )
        if not params_match:
            continue

        param_block: str = params_match.group(1)
        lines: list[str] = param_block.splitlines()
        params: dict[str, set[str]] = {}

        current_param: str | None = None
        for line in lines:
            param_match = re.match(r"^- `([^`]+)` \(", line)
            if param_match:
                current_param = param_match.group(1)
                params.setdefault(current_param, set()).add(current_param)
                continue

            if current_param is not None and "Synonyms:" in line:
                for alias in re.findall(r"`([^`]+)`", line):
                    params[current_param].add(alias)

        if params:
            result.setdefault(canonical_tool, {})
            for param_name, aliases in params.items():
                result[canonical_tool].setdefault(param_name, set()).update(aliases)

    return result


def test_tools_list_tools_and_params_are_supported_by_registry() -> None:
    docs = _parse_tools_list()
    registry = ToolRegistry()

    assert docs, "Expected parsed tools/params from TOOLS_LIST.md"

    known_tools = set(TOOLS)

    missing_tools: list[str] = []
    missing_params: list[tuple[str, str]] = []
    unmapped_aliases: list[tuple[str, str, str]] = []

    for tool_name, params in docs.items():
        if tool_name not in known_tools:
            missing_tools.append(tool_name)
            continue

        canonical_params: list[str] = TOOL_PARAMS.get(tool_name, [])
        by_norm: dict[str, str] = {normalize_identifier(param): param for param in canonical_params}

        for param_name, aliases in params.items():
            canonical_param: str | None = by_norm.get(normalize_identifier(param_name))
            if canonical_param is None:
                missing_params.append((tool_name, param_name))
                continue

            for alias in aliases:
                sentinel: str = f"value-for-{tool_name}-{canonical_param}-{alias}"
                parsed: dict[str, str] = registry.parse_arguments({alias: sentinel}, tool_name)
                if parsed.get(canonical_param) != sentinel:
                    unmapped_aliases.append((tool_name, canonical_param, alias))

    assert not missing_tools, f"Documented tools missing from TOOLS: {sorted(set(missing_tools))}"
    assert not missing_params, f"Documented params missing from TOOL_PARAMS: {missing_params[:25]}"
    assert not unmapped_aliases, f"Documented aliases not parsed to canonical params: {unmapped_aliases[:25]}"
