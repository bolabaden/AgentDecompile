from __future__ import annotations

import ast
import difflib
import re

from pathlib import Path
from typing import Any

ROOT = Path(r"c:/GitHub/agentdecompile")
TOOLS_LIST = ROOT / "TOOLS_LIST.md"
TOOLS_LIST_GENERATED = ROOT / "TOOLS_LIST_GENERATED.md"
DIFF_OUT = ROOT / "tmp" / "TOOLS_LIST_GENERATED.diff"

REGISTRY_PATH = ROOT / "src/agentdecompile_cli/registry.py"


def parse_registry_tools_and_params() -> tuple[list[str], dict[str, list[str]]]:
    src = REGISTRY_PATH.read_text(encoding="utf-8", errors="ignore")
    module = ast.parse(src)

    tools: list[str] = []
    tool_params: dict[str, list[str]] = {}

    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "TOOLS":
                    tools = ast.literal_eval(node.value)

                if isinstance(target, ast.Name) and target.id == "TOOL_PARAMS":
                    if not isinstance(node.value, ast.Dict):
                        continue
                    for key_node, value_node in zip(node.value.keys, node.value.values):
                        if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
                            continue
                        key = key_node.value

                        if isinstance(value_node, ast.Call) and isinstance(value_node.func, ast.Name) and value_node.func.id == "_params":
                            values = []
                            for arg in value_node.args:
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    values.append(arg.value)
                            tool_params[key] = values
                        elif isinstance(value_node, ast.List):
                            values = []
                            for elt in value_node.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    values.append(elt.value)
                            tool_params[key] = values

    return tools, tool_params


def parse_map() -> dict[str, str]:
    """Returns an empty mapping; vendor matrix no longer in use."""
    return {}


def collect_vendor_rows() -> dict[str, list[dict[str, Any]]]:
    """Returns empty; vendor source directories have been removed."""
    return {}


def collect_overloads(vendors: dict[str, list[dict[str, Any]]], mapping: dict[str, str]) -> dict[str, list[tuple[str, tuple[str, ...], str]]]:
    grouped: dict[str, list[tuple[str, tuple[str, ...], str]]] = {}

    for vendor_name, rows in vendors.items():
        for row in rows:
            tool_name = str(row.get("tool_name", "")).strip()
            if not tool_name:
                continue
            canonical: str | None = mapping.get(tool_name)
            if canonical is None or not canonical.strip():
                continue

            params: list[str] = []
            for k in ("mcp_params", "params", "properties"):
                v = row.get(k)
                if isinstance(v, list):
                    params.extend([str(x) for x in v if x])

            sig: tuple[str, tuple[str, ...], str] = (tool_name, tuple(params), vendor_name)
            grouped.setdefault(canonical, [])
            if sig not in grouped[canonical]:
                grouped[canonical].append(sig)

    for canonical in list(grouped):
        grouped[canonical] = sorted(grouped[canonical], key=lambda x: (x[2], x[0]))

    return grouped


def parse_sections(full_text: str) -> tuple[str, list[tuple[str, str, str | None]]]:
    header_re: re.Pattern[str] = re.compile(r"^### `([^`]+)`(?: \(forwards to `([^`]+)`\))?\n", re.M)
    matches: list[re.Match[str]] = list(header_re.finditer(full_text))
    if not matches:
        raise RuntimeError("No tool sections were found in TOOLS_LIST.md")

    preamble: str = full_text[: matches[0].start()]
    sections: list[tuple[str, str, str | None]] = []

    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[start:end]
        sections.append((m.group(1), body, m.group(2)))

    return preamble, sections


def build_overload_block(
    tool_name: str,
    forward_target: str | None,
    section_body: str,
    overloads: dict[str, list[tuple[str, tuple[str, ...], str]]],
    canonical_params: dict[str, list[str]],
) -> str:
    lines = ["**Overloads**:"]

    if forward_target:
        lines.append(f"- `{tool_name}(...)` alias entry → forwards to `{forward_target}` with the same supported parameters.")
        return "\n".join(lines) + "\n\n"

    if tool_name in overloads:
        for vendor_tool, params, source in overloads[tool_name]:
            signature: str = f"{vendor_tool}({', '.join(params)})" if params else f"{vendor_tool}()"
            lines.append(f"- `{signature}` → forwards to `{tool_name}`.")
        return "\n".join(lines) + "\n\n"

    params = canonical_params.get(tool_name)
    if params is None:
        params = re.findall(r"^- `([^`]+)` \([^\n]+\):", section_body, flags=re.M)

    signature: str = f"{tool_name}({', '.join(params)})" if params else f"{tool_name}()"
    lines.append(f"- `{signature}` canonical signature.")
    return "\n".join(lines) + "\n\n"


def replace_or_insert_overloads(section_body: str, overload_block: str) -> str:
    if "**Overloads**:" in section_body:
        return re.sub(
            r"\*\*Overloads\*\*:\n(?:- .*\n)+\n",
            overload_block,
            section_body,
            count=1,
            flags=re.M,
        )

    insert_anchor = None
    for anchor in ("\n**Synonyms**:", "\n**Examples**:"):
        idx = section_body.find(anchor)
        if idx != -1:
            insert_anchor = idx
            break

    if insert_anchor is None:
        return section_body.rstrip() + "\n" + overload_block

    return section_body[:insert_anchor] + "\n" + overload_block + section_body[insert_anchor:]


def generate_tools_list() -> tuple[str, str]:
    registry_tools, registry_params = parse_registry_tools_and_params()
    mapping = parse_map()
    vendor_rows = collect_vendor_rows()
    overloads = collect_overloads(vendor_rows, mapping)

    original = TOOLS_LIST.read_text(encoding="utf-8")
    preamble, sections = parse_sections(original)

    generated_sections: list[str] = []
    seen_names: set[str] = set()

    for name, body, forward_target in sections:
        seen_names.add(name)
        block = build_overload_block(name, forward_target, body, overloads, registry_params)
        generated_sections.append(replace_or_insert_overloads(body, block))

    missing_from_doc = [tool for tool in registry_tools if tool not in seen_names]
    for tool in missing_from_doc:
        params: list[str] = registry_params.get(tool, [])
        params_md = "\n".join([f"- `{p}` (string, optional): Auto-generated parameter placeholder." for p in params])
        section = (
            f"\n### `{tool}`\n\n"
            f"**Description**: Auto-generated placeholder section from `agentdecompile_cli/registry.py`.\n\n"
            f"**Parameters**:\n"
            + (params_md + "\n" if params_md else "- None.\n")
            + "\n"
            + build_overload_block(tool, None, "", overloads, registry_params)
            + f"**Synonyms**: `{tool}`\n\n"
            + f"**Examples**:\n- `{tool}`\n"
        )
        generated_sections.append(section)

    generated_text = preamble + "".join(generated_sections)
    return original, generated_text


def compare_and_write(original: str, generated: str) -> None:
    TOOLS_LIST_GENERATED.write_text(generated, encoding="utf-8")

    if original == generated:
        DIFF_OUT.write_text("", encoding="utf-8")
        print("MATCH_EXACT True")
        print(f"WROTE {TOOLS_LIST_GENERATED}")
        return

    diff_lines = list(
        difflib.unified_diff(
            original.splitlines(),
            generated.splitlines(),
            fromfile="TOOLS_LIST.md",
            tofile="TOOLS_LIST_GENERATED.md",
            lineterm="",
        )
    )

    DIFF_OUT.write_text("\n".join(diff_lines) + "\n", encoding="utf-8")
    print("MATCH_EXACT False")
    print(f"ORIGINAL_LINES {len(original.splitlines())}")
    print(f"GENERATED_LINES {len(generated.splitlines())}")
    print(f"DIFF_LINES {len(diff_lines)}")
    print(f"WROTE {TOOLS_LIST_GENERATED}")
    print(f"WROTE_DIFF {DIFF_OUT}")


def main() -> None:
    original, generated = generate_tools_list()
    compare_and_write(original, generated)


if __name__ == "__main__":
    main()
