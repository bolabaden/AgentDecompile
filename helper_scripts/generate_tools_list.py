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
VERIFY_MATRIX_PATH = ROOT / "tmp/_verify_explicit_vendor_matrix.py"

PYGHIDRA_SERVER = ROOT / "vendor/pyghidra-mcp/src/pyghidra_mcp/server.py"
PYGHIDRA_MCP_TOOLS = ROOT / "vendor/pyghidra-mcp/src/pyghidra_mcp/mcp_tools.py"
PYGHIDRA_TOOLS = ROOT / "vendor/pyghidra-mcp/src/pyghidra_mcp/tools.py"

GHIDRAMCP_BRIDGE = ROOT / "vendor/GhidraMCP/bridge_mcp_ghidra.py"
REVA_TOOLS_BASE = ROOT / "vendor/reverse-engineering-assistant/src/main/java/reva/tools"


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
    src = VERIFY_MATRIX_PATH.read_text(encoding="utf-8", errors="ignore")
    module = ast.parse(src)
    for node in module.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "MAP":
                    return ast.literal_eval(node.value)
    raise RuntimeError("MAP was not found in _verify_explicit_vendor_matrix.py")


def extract_vendor_pyghidra() -> list[dict[str, Any]]:
    server_text = PYGHIDRA_SERVER.read_text(encoding="utf-8", errors="ignore")
    registered = re.findall(r"mcp\.tool\(\)\(mcp_tools\.(\w+)\)", server_text)

    mcp_tools_src: str = PYGHIDRA_MCP_TOOLS.read_text(encoding="utf-8", errors="ignore")
    mcp_tree = ast.parse(mcp_tools_src)

    sigs: dict[str, list[str]] = {}
    backing: dict[str, list[str]] = {}

    for node in mcp_tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in registered:
            continue

        params: list[str] = []
        for arg in node.args.args:
            if arg.arg not in {"ctx", "context"}:
                params.append(arg.arg)
        for arg in node.args.kwonlyargs:
            if arg.arg not in {"ctx", "context"}:
                params.append(arg.arg)
        sigs[node.name] = params

        node_src = ast.get_source_segment(mcp_tools_src, node) or ""
        calls = sorted(set(re.findall(r"\btools\.(\w+)\(", node_src)))
        if calls:
            backing[node.name] = calls

    tools_tree: ast.Module = ast.parse(PYGHIDRA_TOOLS.read_text(encoding="utf-8", errors="ignore"))
    tool_methods: dict[str, list[str]] = {}
    for node in tools_tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "GhidraTools":
            for fn in node.body:
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    params = [a.arg for a in fn.args.args if a.arg != "self"]
                    params.extend([a.arg for a in fn.args.kwonlyargs])
                    tool_methods[fn.name] = params

    rows: list[dict[str, Any]] = []
    for tool in registered:
        methods = backing.get(tool, [])
        rows.append(
            {
                "tool_name": tool,
                "mcp_params": sigs.get(tool, []),
                "logic_paths": [
                    "vendor/pyghidra-mcp/src/pyghidra_mcp/server.py",
                    "vendor/pyghidra-mcp/src/pyghidra_mcp/mcp_tools.py",
                    "vendor/pyghidra-mcp/src/pyghidra_mcp/tools.py",
                ],
                "backing_methods": [{m: tool_methods.get(m, [])} for m in methods],
            }
        )

    return rows


def extract_vendor_ghidramcp() -> list[dict[str, Any]]:
    text = GHIDRAMCP_BRIDGE.read_text(encoding="utf-8", errors="ignore")
    tree = ast.parse(text)
    rows: list[dict[str, Any]] = []

    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue

        decorated: bool = False
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == "tool":
                decorated = True
                break
        if not decorated:
            continue

        params: list[str] = [a.arg for a in node.args.args]
        rows.append(
            {
                "tool_name": node.name,
                "params": params,
                "logic_path": "vendor/GhidraMCP/bridge_mcp_ghidra.py",
            }
        )

    return rows


def extract_vendor_reva() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def dedup(seq: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    for p in REVA_TOOLS_BASE.rglob("*.java"):
        rel: str = p.relative_to(ROOT).as_posix()
        lines: list[str] = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        name_idxs: list[int] = [i for i, line in enumerate(lines) if re.search(r'\.name\("([^"]+)"\)', line)]

        for idx_pos, i in enumerate(name_idxs):
            m = re.search(r'\.name\("([^"]+)"\)', lines[i])
            if not m:
                continue
            tool: str = m.group(1)
            prev_name: int = name_idxs[idx_pos - 1] if idx_pos > 0 else -1
            search_start: int = prev_name + 1

            prop_decl: int = -1
            for j in range(i, search_start - 1, -1):
                if "Map<String, Object> properties" in lines[j]:
                    prop_decl = j
                    break

            start: int = prop_decl if prop_decl != -1 else search_start
            end: int = i
            for j in range(i, len(lines)):
                if ".build()" in lines[j]:
                    end = j
                    break

            chunk = lines[start : end + 1]
            chunk_text = "\n".join(chunk)

            props: list[str] = []
            req: list[str] = []

            for cl in chunk:
                props.extend(re.findall(r'properties\.put\("([^"]+)"', cl))
                req.extend(re.findall(r'required\.add\("([^"]+)"\)', cl))

            for lm in re.finditer(r"required\s*=\s*List\.of\((.*?)\)", chunk_text, re.S):
                req.extend(re.findall(r'"([^"]+)"', lm.group(1)))

            for lm in re.finditer(r"createSchema\(\s*properties\s*,\s*List\.of\((.*?)\)\s*\)", chunk_text, re.S):
                req.extend(re.findall(r'"([^"]+)"', lm.group(1)))

            rows.append(
                {
                    "tool_name": tool,
                    "logic_path": rel,
                    "required": dedup(req),
                    "properties": dedup(props),
                }
            )

    rows.sort(key=lambda r: (str(r.get("tool_name", "")), str(r.get("logic_path", ""))))
    return rows


def collect_vendor_rows() -> dict[str, list[dict[str, Any]]]:
    return {
        "vendor_pyghidra": extract_vendor_pyghidra(),
        "vendor_reva": extract_vendor_reva(),
        "vendor_ghidramcp": extract_vendor_ghidramcp(),
    }


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
        lines.append(f"- `{tool_name}(...)` vendor/alias entry → forwards to `{forward_target}` with the same supported parameters.")
        return "\n".join(lines) + "\n\n"

    if tool_name in overloads:
        for vendor_tool, params, source in overloads[tool_name]:
            signature: str = f"{vendor_tool}({', '.join(params)})" if params else f"{vendor_tool}()"
            lines.append(f"- `{signature}` from `{source}` → forwards to `{tool_name}`.")
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
