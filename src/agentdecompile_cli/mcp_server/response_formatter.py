"""Rich markdown response formatter for MCP tool output.

Transforms raw JSON tool responses into human/agent-readable markdown with:
- Structured headers, metadata blocks, code fences, tables
- Dynamic "About This Tool" sections with RE workflow guidance
- Per-tool custom renderers for the top tools + generic fallback


Architecture:
  Provider handler → create_success_response({...})  (unchanged)
  ToolProvider.call_tool() intercept →
    if format != "json":
        data = json.loads(text_content.text)
        markdown = render_tool_response(tool_name, data)
        return [TextContent(type="text", text=markdown)]

All rendering is purely a presentation layer — zero changes to handler logic.
"""

from __future__ import annotations

import re

from collections.abc import Callable
from typing import Any, cast

from agentdecompile_cli.registry import is_tool_advertised, normalize_identifier

# ---------------------------------------------------------------------------
# Markdown building helpers
# ---------------------------------------------------------------------------


def _md_heading(level: int, text: str) -> str:
    return f"{'#' * level} {text}"


def _md_bold_kv(key: str, value: Any) -> str:
    return f"**{key}:** {value}"


def _md_code_inline(text: str) -> str:
    return f"`{text}`"


def _md_code_block(code: str, lang: str = "") -> str:
    return f"```{lang}\n{code}\n```"


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    if not headers:
        return ""
    header_row: str = "| " + " | ".join(headers) + " |"
    sep_row: str = "| " + " | ".join("---" for _ in headers) + " |"
    body: str = "\n".join("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return f"{header_row}\n{sep_row}\n{body}" if body else f"{header_row}\n{sep_row}"


def _md_bullet_list(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _truncate(s: str, max_len: int = 120) -> str:
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _pagination_footer(data: dict[str, Any]) -> str:
    parts: list[str] = []
    count: int = data.get("count", 0)
    total: int = data.get("total", count)
    offset: int = data.get("offset", 0)
    has_more: bool = data.get("hasMore", False)
    parts.append(f"Showing **{count}** of **{total}** results (offset {offset}).")
    if has_more:
        next_offset: int = offset + count
        parts.append(f"More results available — use `offset={next_offset}` to continue.")
    return " ".join(parts)


_DISABLABLE_RECOMMENDATION_TOOLS: set[str] = {
    normalize_identifier("get-functions"),
    normalize_identifier("manage-bookmarks"),
    normalize_identifier("manage-comments"),
    normalize_identifier("manage-data-types"),
    normalize_identifier("manage-files"),
    normalize_identifier("manage-function"),
    normalize_identifier("manage-strings"),
    normalize_identifier("manage-structures"),
    normalize_identifier("manage-symbols"),
}


def _filter_disabled_tool_recommendations(steps: list[str]) -> list[str]:
    """Drop recommendation lines that reference tools disabled via env configuration."""
    filtered: list[str] = []
    for step in steps:
        mentioned = re.findall(r"`([A-Za-z0-9_-]+)`", step)
        blocked = False
        for token in mentioned:
            token_norm = normalize_identifier(token)
            if token_norm in _DISABLABLE_RECOMMENDATION_TOOLS and not is_tool_advertised(token):
                blocked = True
                break
        if not blocked:
            filtered.append(step)
    return filtered


# ---------------------------------------------------------------------------
# Tool guidance registry: maps normalized tool name → (description, next_steps_fn)
# next_steps_fn(data) → list[str]
# ---------------------------------------------------------------------------


def _next_steps_execute_script(data: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    has_error = bool(data.get("stderr"))
    has_output = bool(data.get("stdout") or data.get("result"))
    if has_error and not has_output:
        steps.append("Review the traceback above and fix the script, then call `execute-script` again.")
    if has_output:
        steps.append("If the script retrieved function/address data, use `get-functions mode=decompile` to inspect specific functions.")
        steps.append("Use `manage-comments` or `manage-bookmarks` to annotate interesting findings.")
    steps.append("For batch analysis across many functions, combine `list-functions` output with `execute-script` loops.")
    return steps


def _next_steps_decompile(data: dict[str, Any]) -> list[str]:
    func_name: str = data.get("function", "")
    addr: str = data.get("address", "")
    steps: list[str] = []
    if func_name:
        steps.append(f"Call `get-call-graph function={func_name} mode=graph` to see who calls this and what it calls.")
    if addr:
        steps.append(f'Call `manage-comments address={addr} mode=set comment="..."` to annotate your findings.')
        steps.append(f"Call `get-references address={addr}` to find all cross-references to/from this function.")
    steps.append("If the function calls suspicious subroutines, use `get-functions mode=decompile` on those next.")
    steps.append("Use `manage-function mode=rename` to give this function a meaningful name if auto-named.")
    return steps


def _next_steps_list_functions(data: dict[str, Any]) -> list[str]:
    total: int = data.get("total", data.get("count", 0))
    results: list[dict[str, Any]] = data.get("results", [])
    steps: list[str] = []
    if results:
        first: dict[str, Any] = results[0]
        name: str = first.get("name", "")
        if name:
            steps.append(f"Call `get-functions mode=decompile function={name}` to read the pseudocode of a specific function.")
            steps.append(f"Call `get-functions function={name} view=info` for detailed metadata (params, return type).")
    if total > len(results):
        steps.append(f"Use `offset` + `limit` to paginate through all {total} functions.")
    steps.append("Use `namePattern` regex to filter (e.g. `^sub_` for unnamed, `^_` for C++ internals).")
    steps.append("Call `get-current-program` for a quick symbol/function count overview without listing.")
    return steps


def _next_steps_get_functions(data: dict[str, Any]) -> list[str]:
    view: str = data.get("view", "info")
    name: str = data.get("name", "")
    addr: str = data.get("address", "")
    steps: list[str] = []
    if view == "info":
        steps.append(f"Call `get-functions mode=decompile function={name}` to see the C pseudocode.")
        steps.append(f"Call `get-call-graph function={name} mode=graph` to map call relationships.")
        steps.append(f"Call `get-functions function={name} view=disassemble` for raw assembly instructions.")
    elif view == "calls":
        callers: list[dict[str, Any]] = data.get("callers", [])
        callees: list[dict[str, Any]] = data.get("callees", [])
        if callees:
            steps.append(f"Decompile called functions: try `get-functions mode=decompile function={callees[0].get('name', '')}`.")
        if callers:
            steps.append(f"Trace callers: try `get-functions mode=decompile function={callers[0].get('name', '')}`.")
        steps.append(f"For a full call tree, use `get-call-graph function={name} mode=tree depth=3`.")
    elif view == "decompile":
        steps.append(f"Call `get-call-graph function={name} mode=graph` to see call relationships.")
        steps.append(f"Call `manage-comments address={addr} mode=set` to annotate your analysis.")
    elif view == "disassemble":
        steps.append("Look for interesting patterns: `CALL`, `JMP` targets, or unusual `MOV` operands.")
        steps.append(f"Call `get-functions mode=decompile function={name}` for a higher-level C view of this assembly.")
        steps.append(f"Call `get-references address={addr}` to trace cross-references from specific instructions.")
    return steps


def _next_steps_symbols(data: dict[str, Any]) -> list[str]:
    mode: str = data.get("mode", "symbols")
    results: list[dict[str, Any]] = data.get("results", [])
    steps: list[str] = []
    if mode in ("symbols", "search"):
        if results:
            first_name: str = results[0].get("name", "")
            first_addr: str = results[0].get("address", "")
            if first_name:
                steps.append(f"Decompile a symbol: `get-functions mode=decompile function={first_name}`.")
            if first_addr:
                steps.append(f"Get cross-references: `get-references address={first_addr}`.")
        steps.append("Use `query` to filter symbols by pattern (supports regex).")
    elif mode == "imports":
        if results:
            imp_name: str = results[0].get("name", "")
            steps.append(f"Trace import usage: `get-references mode=import importName={imp_name}`.")
        steps.append("Import patterns reveal what OS APIs the binary uses (crypto, network, file I/O).")
        steps.append("Call `search-everything query=<import_name>` to find all uses in decompiled code.")
    elif mode == "exports":
        if results:
            steps.append(f"Decompile an export: `get-functions mode=decompile function={results[0].get('name', '')}`.")
        steps.append("Exports are the binary's public API — start analysis from these entry points.")
    elif mode == "classes":
        if results:
            steps.append(f"Explore class symbols: `search-symbols query={results[0].get('name', '')}`.")
        steps.append("Look for vtable addresses with `analyze-vtables` to map virtual method tables.")
    elif mode == "create_label":
        steps.append("Labels improve readability. Continue annotating with `manage-comments` and `manage-bookmarks`.")
    elif mode == "count":
        steps.append("For a full listing, use `search-symbols query=.*` or `list-functions`.")
    return steps


def _next_steps_search_everything(data: dict[str, Any]) -> list[str]:
    results: list[dict[str, Any]] = data.get("results", [])
    steps: list[str] = []
    if results:
        first: dict[str, Any] = results[0]
        rt: str = first.get("resultType", "")
        next_tools: list[dict[str, Any]] = first.get("nextTools", [])
        if next_tools:
            nt: dict[str, Any]
            for nt in next_tools[:2]:
                tool: str = nt.get("tool", "")
                args_str: str = " ".join(f"{k}={v}" for k, v in nt.get("args", {}).items())
                steps.append(f"Follow up: `{tool} {args_str}`")
        if not next_tools:
            if rt == "function":
                steps.append(f"Decompile: `get-functions mode=decompile function={first.get('name', first.get('function', ''))}`.")
            elif rt in ("symbol", "export", "import"):
                steps.append(f"Cross-refs: `get-references address={first.get('address', '')}`.")
    steps.append('Narrow results with `scopes` param (e.g. `scopes=["functions","strings"]`).')
    steps.append("Try `searchMode=regex` for pattern matching or `searchMode=fuzzy` for approximate matches.")
    return steps


def _next_steps_memory(data: dict[str, Any]) -> list[str]:
    mode: str = data.get("mode", "blocks")
    steps: list[str] = []
    if mode == "blocks":
        blocks: list[dict[str, Any]] = data.get("blocks", [])
        text_block: dict[str, Any] | None = next((b for b in blocks if str(b.get("permissions", "")).endswith("x")), None)
        data_block: dict[str, Any] | None = next((b for b in blocks if "data" in str(b.get("name", "")).lower()), None)
        if text_block:
            steps.append(f"Read code section: `inspect-memory mode=read address={text_block['start']} length=256`.")
        if data_block:
            steps.append(f"Inspect data section: `inspect-memory mode=read address={data_block['start']} length=256`.")
        steps.append("Memory blocks reveal the binary's layout — `.text` is code, `.data`/`.rdata` hold globals/constants.")
        steps.append("Call `list-functions` to see what functions exist in the executable sections.")
    elif mode == "read":
        addr: str = data.get("address", "")
        steps.append(f"Interpret this data: `inspect-memory mode=data_at address={addr}` to see if Ghidra has typed it.")
        steps.append("Look for ASCII strings in the hex dump — they often reveal string literals or format strings.")
        steps.append("Use `manage-strings` to find all defined strings, or `search-strings query=...` for specific ones.")
    elif mode == "data_at":
        steps.append("If the data type is a pointer, follow it with another `inspect-memory mode=data_at`.")
        steps.append("Apply a different type with `apply-data-type` if the current interpretation is wrong.")
    elif mode == "data_items":
        steps.append("Defined data items show Ghidra's interpretation of memory regions.")
        steps.append("Use `apply-data-type` to retype items, or `manage-structures` to create custom struct types.")
    return steps


def _next_steps_callgraph(data: dict[str, Any]) -> list[str]:
    mode: str = data.get("mode", "graph")
    func_name: str = data.get("function", data.get("functionName", ""))
    steps: list[str] = []
    if mode in ("graph", "tree"):
        callees: list[dict[str, Any]] = data.get("callees", [])
        callers: list[dict[str, Any]] = data.get("callers", [])
        if callees:
            steps.append(f"Decompile a callee: `get-functions mode=decompile function={callees[0].get('name', '')}`.")
        if callers:
            steps.append(f"Trace a caller: `get-functions mode=decompile function={callers[0].get('name', '')}`.")
        steps.append("Look for leaf functions (no callees) — they often implement core logic.")
        steps.append("Look for hub functions (many callers) — they're likely utility/API wrappers.")
    elif mode == "callers":
        callers = data.get("callers", data.get("commonCallers", []))
        if callers:
            steps.append(f"Decompile caller: `get-functions mode=decompile function={callers[0].get('name', '')}`.")
        steps.append(f"Get full graph: `get-call-graph function={func_name} mode=graph`.")
    elif mode == "callees":
        callees = data.get("callees", [])
        if callees:
            steps.append(f"Decompile callee: `get-functions mode=decompile function={callees[0].get('name', '')}`.")
    if func_name:
        steps.append('Annotate: `manage-comments address=<addr> mode=set comment="analyzed call graph"`.')
    return steps


def _next_steps_comments(data: dict[str, Any]) -> list[str]:
    action: str = data.get("action", data.get("mode", ""))
    steps: list[str] = []
    if action == "set":
        addr: str = data.get("address", "")
        steps.append("Comment added. Continue annotating nearby addresses or use `manage-bookmarks` to flag the location.")
        if addr:
            steps.append(f"Call `get-functions mode=decompile address={addr}` to verify the comment in context.")
    elif action == "get":
        addr = data.get("address", "")
        steps.append(f'To modify: `manage-comments address={addr} mode=set type=eol comment="new text"`.')
        steps.append(f"To remove: `manage-comments address={addr} mode=remove type=eol`.")
    elif action == "search":
        steps.append("Comment search results show previously annotated locations — useful for resuming analysis.")
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            steps.append(f"Decompile annotated function: `get-functions mode=decompile address={results[0].get('address', '')}`.")
    elif action == "search_decomp":
        steps.append("Decompilation search found pattern matches in C pseudocode.")
        results = data.get("results", [])
        if results:
            steps.append(f"Read full decompilation: `get-functions mode=decompile function={results[0].get('function', '')}`.")
    return steps


def _next_steps_bookmarks(data: dict[str, Any]) -> list[str]:
    action: str = data.get("action", data.get("mode", ""))
    steps: list[str] = []
    if action in ("set", "add_batch"):
        steps.append("Bookmark set. Use `manage-bookmarks mode=get` to list all bookmarks.")
        steps.append("Bookmarks persist across sessions — use them to track analysis progress.")
    elif action == "remove":
        steps.append("Bookmark removed. Use `manage-bookmarks mode=get` to verify.")
    elif action in ("get", "search"):
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            first_addr: str = results[0].get("address", "")
            steps.append(f"Resume analysis: `get-functions mode=decompile address={first_addr}`.")
            steps.append(f"Read comments: `manage-comments address={first_addr} mode=get`.")
        steps.append("Filter bookmarks with `query` or `category` parameters.")
    elif action == "categories":
        categories: list[str] = data.get("categories", [])
        if categories:
            steps.append(f"List bookmarks in category: `manage-bookmarks mode=get category={categories[0]}`.")
    return steps


def _next_steps_structures(data: dict[str, Any]) -> list[str]:
    action: str = data.get("action", "")
    steps: list[str] = []
    if action == "list":
        structs: list[dict[str, Any]] = data.get("structures", [])
        if structs:
            steps.append(f"Inspect structure: `manage-structures mode=info name={structs[0].get('name', '')}`.")
        steps.append("Create new: `manage-structures mode=create name=MyStruct size=64`.")
        steps.append('Parse from C: `manage-structures mode=parse code="struct MyStruct {{ int x; char y[32]; }}"`.')
    elif action == "info":
        name = data.get("name", "")
        steps.append(f"Apply to memory: `manage-structures mode=apply structure={name} address=0x...`.")
        steps.append(f"Add fields: `manage-structures mode=add_field structure={name} field=newField type=int offset=0`.")
        steps.append("Use `search-symbols query=<name>` to find where this struct type is used.")
    elif action == "create":
        name = data.get("name", "")
        steps.append(f"Add fields: `manage-structures mode=add_field structure={name} field=firstField type=int offset=0`.")
        steps.append(f'Or parse C header: `manage-structures mode=parse code="struct {name} {{ ... }}"`.')
    elif action in ("modify_from_c", "parse"):
        steps.append("Structure updated from C definition. Use `manage-structures mode=info` to verify.")
    elif action == "apply":
        steps.append("Structure applied. Decompile the function at that address to see typed variables.")
    return steps


def _next_steps_constants(data: dict[str, Any]) -> list[str]:
    mode: str = data.get("mode", "")
    results: list[dict[str, Any]] = data.get("results", [])
    steps: list[str] = []
    if results:
        first_addr: str = results[0].get("address", "") if results else ""
        if first_addr:
            steps.append(f"Decompile containing function: `get-functions mode=decompile address={first_addr}`.")
            steps.append(f"Cross-references: `get-references address={first_addr}`.")
    if mode == "common":
        steps.append("Common constants often include buffer sizes, error codes, Windows API flags, and crypto constants.")
    steps.append("Search for specific values: `search-constants mode=specific value=0xDEADBEEF`.")
    steps.append("Search ranges: `search-constants mode=range minValue=0x400000 maxValue=0x500000` for pointer-like values.")
    return steps


def _next_steps_dataflow(data: dict[str, Any]) -> list[str]:
    direction: str = data.get("direction", "")
    steps: list[str] = []
    if direction == "backward":
        steps.append("Backward data flow traces where values come from — follow the inputs to find data origins.")
        steps.append("Use `get-functions` with mode='decompile' to see the full function context around these P-code operations.")
    elif direction == "forward":
        steps.append("Forward data flow shows where values are consumed — useful for tracking output/side effects.")
    elif direction == "variable_accesses":
        steps.append("Variable access analysis shows all reads/writes to local variables in a function.")
        steps.append("Use `get-functions` with mode='decompile' to see these variables in the C pseudocode context.")
    func_name: str = data.get("function", "")
    if func_name:
        steps.append(f"Call `get-call-graph function={func_name}` to trace data flow across function boundaries.")
    return steps


def _next_steps_datatypes(data: dict[str, Any]) -> list[str]:
    action: str = data.get("action", "")
    steps: list[str] = []
    if action == "list":
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            first: dict[str, Any] = results[0]
            if first.get("isCategory"):
                steps.append(f"Browse category: `manage-data-types mode=list categoryPath={first.get('path', '')}`.")
            else:
                steps.append(f"Inspect type: `manage-data-types mode=by_string dataTypeString={first.get('name', '')}`.")
        steps.append("Data types are organized in categories — browse `/` (root) to see top-level categories.")
    elif action == "by_string":
        steps.append("Apply this type to memory: `apply-data-type address=0x... dataType=<name>`.")
    elif action == "apply":
        steps.append("Type applied. Decompile the function at that address to see the effect.")
    elif action == "archives":
        steps.append("Archives contain pre-defined type libraries. Use `manage-data-types mode=list` to browse them.")
    return steps


def _next_steps_vtable(data: dict[str, Any]) -> list[str]:
    mode: str = data.get("mode", "")
    steps: list[str] = []
    if mode == "containing":
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            steps.append(f"Analyze vtable: `analyze-vtables mode=analyze address={results[0].get('address', '')}`.")
        steps.append("Vtables contain pointers to virtual methods — analyzing them reveals class hierarchies.")
    elif mode == "analyze":
        entries: list[dict[str, Any]] = data.get("entries", [])
        if entries:
            first_target = entries[0].get("function", entries[0].get("target", ""))
            if first_target:
                steps.append(f"Decompile virtual method: `get-functions mode=decompile function={first_target}`.")
        steps.append("Each vtable entry is a function pointer — decompile targets to understand the class interface.")
    elif mode == "callers":
        steps.append("Vtable callers show where virtual dispatch happens — these are polymorphic call sites.")
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            steps.append(f"Decompile call site: `get-functions mode=decompile address={results[0].get('fromAddress', '')}`.")
    return steps


def _next_steps_strings(data: dict[str, Any]) -> list[str]:
    mode: str = data.get("mode", "")
    results: list[dict[str, Any]] = data.get("results", [])
    steps: list[str] = []
    if mode == "count":
        steps.append("Use `manage-strings mode=list` to see actual string values.")
    elif results:
        first: dict[str, Any] = results[0]
        addr = first.get("address", "")
        val = first.get("value", "")  # noqa: F841
        if addr:
            steps.append(f"Find references to this string: `get-references address={addr}`.")
            steps.append(f"Decompile containing function: `get-functions mode=decompile address={addr}`.")
        steps.append("Strings are goldmines for RE: error messages reveal logic, format strings reveal data structures.")
    steps.append("Search for keywords: `search-strings query=password` or `search-strings query=error`.")
    return steps


def _next_steps_import_export(data: dict[str, Any]) -> list[str]:
    action = data.get("action", data.get("operation", ""))
    steps: list[str] = []
    if action == "import":
        programs: list[dict[str, Any]] = data.get("importedPrograms", [])
        if programs:
            path = programs[0].get("programName", "")
            steps.append(f"Open imported program: `open path={path}`.")
        steps.append("Run analysis: `analyze-program` to let Ghidra's analyzers process the binary.")
    elif action == "export":
        steps.append("Export complete. The file is saved to the specified output path.")
    elif action == "analyze":
        steps.append("Analysis complete. Use `list-functions`, `search-symbols`, `list-imports`, and `list-exports` to explore results.")
    elif action == "checkin":
        steps.append("Program checked in to shared repository. Other users can now access it.")
    return steps


def _next_steps_project(data: dict[str, Any]) -> list[str]:
    action = data.get("action", data.get("operation", ""))
    loaded = data.get("loaded")
    steps: list[str] = []
    if action == "open-project":
        steps.append("Project opened. Call `list-project-files` to see available programs in the project.")
        steps.append("Start with `list-functions` for function overview or `inspect-memory mode=blocks` for memory layout.")
    elif loaded is True:
        steps.append("Use `list-functions` to survey the binary's functions.")
        steps.append("Use `inspect-memory mode=blocks` to understand the memory layout.")
        steps.append("Use `get-references mode=import` to see import/library dependencies.")
    elif loaded is False:
        steps.append("Project failed to load for some reason! Check the file path and format, and ensure the Ghidra project is set up correctly.")
    elif action == "list":
        files: list[dict[str, Any]] = data.get("files", data.get("entries", []))
        if files:
            steps.append(f"Open a file: `open-project path={files[0].get('path', files[0].get('name', ''))}`.")
    return steps


def _next_steps_search_code(data: dict[str, Any]) -> list[str]:
    results = data.get("results", [])
    steps: list[str] = []
    if results:
        first: dict[str, Any] = results[0]
        func_name = first.get("function", "")
        if func_name:
            steps.append(f"Decompile matching function: `get-functions mode=decompile function={func_name}`.")
    steps.append("Use `searchMode=regex` for pattern matching, or `searchMode=literal` for exact text.")
    return steps


def _next_steps_data(data: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    if "definedType" in data:
        steps.append("Use `apply-data-type` to change the interpretation if the type is wrong.")
    if data.get("hex"):
        steps.append("Examine surrounding bytes with `inspect-memory mode=read` at nearby addresses.")
    if data.get("success"):
        steps.append("Type applied. Decompile nearby functions to see the effect on variable types.")
    return steps


def _next_steps_suggestions(data: dict[str, Any]) -> list[str]:
    return [
        "The suggest tool provides AI-suggested names/types — review and apply with `manage-function mode=rename`.",
        "Use `manage-comments` to document your naming decisions.",
    ]


def _next_steps_match_function(data: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    error = data.get("error", "")
    results = data.get("results", [])
    
    # If function not found, suggest searching first
    if "not found" in error.lower() or "not exist" in error.lower():
        steps.append("The function wasn't found. First, use `search-everything query={function_name}` to locate it in the binary.")
        steps.append("Once found, use `search-code` for decompiled code search, or `list-functions` to browse all functions.")
        steps.append("Then retry `match-function` with the correct function address or symbol name.")
    # If successful matches
    elif results:
        steps.append("Compare matched functions across binaries to identify similarities (reused code, shared libraries).")
        steps.append("Use `decompile function={name}` on matched functions to examine them side-by-side in detail.")
        steps.append("Tag matched functions with `manage-function-tags` to group them by library or purpose.")
    # Generic case
    else:
        steps.append("Use `search-everything` to find the function you want to match across builds/versions.")
        steps.append("Once you have a function identifier (address or symbol), call `match-function` with it.")
    
    return steps


# ---------------------------------------------------------------------------
# TOOL_GUIDANCE: normalized tool name → (short description, next_steps_fn)
# ---------------------------------------------------------------------------

TOOL_GUIDANCE: dict[str, tuple[str, Callable[[dict[str, Any]], list[str]]]] = {
    "decompile": (
        "Converts machine code into C-like pseudocode using Ghidra's decompiler engine. The decompiled output shows control flow, variable usage, function calls, and data access patterns. Read the signature line first to understand parameters and return type.",
        _next_steps_decompile,
    ),
    "decompilefunction": (
        "Converts machine code into C-like pseudocode using Ghidra's decompiler engine. The decompiled output shows control flow, variable usage, function calls, and data access patterns. Read the signature line first to understand parameters and return type.",
        _next_steps_decompile,
    ),
    "executescript": (
        "Executes arbitrary Python/Jython code in the Ghidra scripting environment with full API access. Use for custom analysis, batch operations, or anything not covered by dedicated tools. The namespace includes `currentProgram`, `flatApi`, decompiler access, and 30+ Ghidra helper methods.",
        _next_steps_execute_script,
    ),
    "listfunctions": (
        "Lists all functions defined in the binary with their addresses, sizes, and basic metadata. Functions with default names like `FUN_00401000` or `sub_*` haven't been analyzed yet — decompile them to understand their purpose and rename accordingly.",
        _next_steps_list_functions,
    ),
    "getfunctions": (
        "Retrieves detailed information about a specific function. The `view` parameter controls what you see: `info` for metadata (params, return type, calling convention), `decompile` for C pseudocode, `disassemble` for raw assembly, `calls` for caller/callee relationships.",
        _next_steps_get_functions,
    ),
    "managesymbols": (
        "Manages the binary's symbol table — names, labels, imports, exports, classes, and namespaces. Symbols are the naming backbone of reverse engineering: every function, variable, and data label is a symbol. Import symbols reveal library dependencies; export symbols are the binary's public interface.",
        _next_steps_symbols,
    ),
    "searcheverything": (
        "Searches across 18+ scopes simultaneously: functions, symbols, strings, comments, decompiled code, imports, exports, namespaces, data types, structures, bookmarks, and more. This is the best starting point when you're looking for something but don't know where it is.",
        _next_steps_search_everything,
    ),
    "globalsearch": (
        "Searches across 18+ scopes simultaneously (alias for search-everything).",
        _next_steps_search_everything,
    ),
    "searchanything": (
        "Searches across 18+ scopes simultaneously (alias for search-everything).",
        _next_steps_search_everything,
    ),
    "inspectmemory": (
        "Examines the binary's memory layout and contents. `blocks` shows memory sections (.text, .data, .bss), `read` dumps raw bytes from an address, `data_at` interprets typed data at an address, `data_items` lists all memory locations with applied data types.",
        _next_steps_memory,
    ),
    "readbytes": (
        "Reads raw binary bytes from a memory address. Shortcut for `inspect-memory mode=read`.",
        _next_steps_memory,
    ),
    "getcallgraph": (
        "Maps function call relationships — who calls whom. Essential for understanding program architecture. `graph` shows immediate callers+callees, `tree` traverses the full call tree to a given depth, `callers` traces only incoming calls, `callees` traces only outgoing calls.",
        _next_steps_callgraph,
    ),
    "gencallgraph": (
        "Generates a visual call graph. Use this for visual output (Mermaid diagrams, etc.).",
        _next_steps_callgraph,
    ),
    "managecomments": (
        "Read, write, and search code comments in the Ghidra database. Comments persist across sessions and are visible in the listing and decompiler views. Types: `eol` (end-of-line), `pre`, `post`, `plate` (function header), `repeatable` (shown at all references).",
        _next_steps_comments,
    ),
    "managebookmarks": (
        "Set, list, and search analysis bookmarks. Bookmarks flag interesting locations for later review and persist across sessions. Use categories to organize by analysis phase (e.g., 'suspicious', 'crypto', 'network', 'todo').",
        _next_steps_bookmarks,
    ),
    "managestructures": (
        "Create, modify, and apply C-style struct/union definitions. Structures let you type raw memory regions so the decompiler shows field names instead of byte offsets. Parse C header syntax or build field-by-field.",
        _next_steps_structures,
    ),
    "searchconstants": (
        "Scans instructions for numeric constants/immediates. Finds magic numbers, buffer sizes, API flags, and crypto constants. Use `specific` for exact values, `range` for value ranges, `common` for frequently-occurring constants.",
        _next_steps_constants,
    ),
    "analyzedataflow": (
        "Traces how data flows through a function using Ghidra's P-code intermediate representation. `backward` traces where a value at an address comes from, `forward` traces where it goes, `variable_accesses` lists all variable reads/writes in a function.",
        _next_steps_dataflow,
    ),
    "managedatatypes": (
        "Browse and apply Ghidra's data type library — primitives, structs, enums, typedefs, and archives. Proper typing is critical for accurate decompilation.",
        _next_steps_datatypes,
    ),
    "analyzevtables": (
        "Analyzes C++ virtual function tables (vtables). Vtables are arrays of function pointers used for polymorphic dispatch. Understanding vtable layout reveals class hierarchies and virtual method signatures.",
        _next_steps_vtable,
    ),
    "managestrings": (
        "Find, list, and search strings embedded in the binary. Strings are one of the most valuable artifacts in RE — error messages, debug logs, API names, and format strings all reveal program logic.",
        _next_steps_strings,
    ),
    "liststrings": (
        "Lists all defined strings in the binary.",
        _next_steps_strings,
    ),
    "searchstrings": (
        "Searches for strings matching a query pattern.",
        _next_steps_strings,
    ),
    "searchcode": (
        "Searches through decompiled code and function names.",
        _next_steps_search_code,
    ),
    "getdata": (
        "Reads data at a memory address with type interpretation.",
        _next_steps_data,
    ),
    "applydatatype": (
        "Applies a data type to a memory address, changing how Ghidra interprets those bytes.",
        _next_steps_data,
    ),
    "importbinary": (
        "Imports a binary file into the Ghidra project for analysis.",
        _next_steps_import_export,
    ),
    "export": (
        "Exports analysis results in various formats (C/C++, GZF, SARIF, XML, HTML).",
        _next_steps_import_export,
    ),
    "analyzeprogram": (
        "Runs Ghidra's auto-analysis on the current program.",
        _next_steps_import_export,
    ),
    "checkinprogram": (
        "Checks in the current program to a shared Ghidra server repository.",
        _next_steps_import_export,
    ),
    "changeprocessor": (
        "Changes the processor/language for the current program.",
        _next_steps_import_export,
    ),
    "listprocessors": (
        "Lists available processor definitions.",
        _next_steps_import_export,
    ),
    "openproject": (
        "Opens a binary or Ghidra project for analysis.",
        _next_steps_project,
    ),
    "getcurrentprogram": (
        "Shows the currently loaded program's metadata.",
        _next_steps_project,
    ),
    "listprojectfiles": (
        "Lists files in the current Ghidra project directory.",
        _next_steps_project,
    ),
    "managefiles": (
        "File management: list, rename, move, delete, import, export, checkout.",
        _next_steps_project,
    ),
    "syncsharedproject": (
        "Synchronizes with a shared Ghidra server repository.",
        _next_steps_project,
    ),
    "suggest": (
        "Gets AI-powered suggestions for naming and typing.",
        _next_steps_suggestions,
    ),
    "getsuggestions": (
        "Gets AI-powered suggestions for naming and typing.",
        _next_steps_suggestions,
    ),
    "matchfunction": (
        "Matches functions across different builds/versions of a binary.",
        _next_steps_match_function,
    ),
    "managefunctiontags": (
        "Manages tags on functions for categorization.",
        lambda d: ["Use `list-functions` to see tagged functions.", "Tags help organize analysis progress."],
    ),
    "managefunction": (
        "Rename, set prototype, or modify function properties.",
        lambda d: [
            "After renaming, use `get-functions mode=decompile` to verify the new name appears correctly.",
            "Use `manage-comments` to document why you renamed/retyped.",
        ],
    ),
}


# ---------------------------------------------------------------------------
# Per-tool custom renderers
# ---------------------------------------------------------------------------


def _render_execute_script(data: dict[str, Any]) -> str:
    """Render execute-script response as rich markdown."""
    lines: list[str] = []
    lines.append(_md_heading(2, "Script Execution Result"))
    lines.append("")

    success = data.get("success", True)
    lines.append(_md_bold_kv("Status", "Success" if success else "Error"))

    stdout_text = str(data.get("stdout", ""))
    stderr_text = str(data.get("stderr", ""))
    result_text = str(data.get("result", ""))

    if stdout_text or stderr_text:
        lines.append("")
        lines.append(_md_heading(3, "Output"))
        lines.append("")
        # Interleave stdout and stderr like a real terminal
        combined: str = ""
        if stdout_text:
            combined += stdout_text
        if stderr_text:
            if combined and not combined.endswith("\n"):
                combined += "\n"
            combined += stderr_text
        if combined.strip():
            lines.append(_md_code_block(combined.rstrip(), ""))

    if result_text and result_text != "None":
        lines.append("")
        lines.append(_md_heading(3, "Return Value"))
        lines.append("")
        # Try to detect if result looks like structured data
        if result_text.startswith("{") or result_text.startswith("["):
            lines.append(_md_code_block(result_text, "json"))
        else:
            lines.append(_md_code_block(result_text, ""))

    return "\n".join(lines)


def _render_decompile(data: dict[str, Any]) -> str:
    """Render get-functions response in decompile mode as rich markdown."""
    lines: list[str] = []
    func_name = data.get("function", data.get("name", "unknown"))
    addr = data.get("address", "")

    lines.append(_md_heading(2, f"Decompiled Function: `{func_name}`"))
    lines.append("")

    if addr:
        lines.append(_md_bold_kv("Address", _md_code_inline(addr)))
    sig = data.get("signature", "")
    if sig:
        lines.append(_md_bold_kv("Signature", _md_code_inline(sig)))
    lines.append("")

    code = str(data.get("decompilation", ""))
    if code:
        lines.append(_md_heading(3, "C Pseudocode"))
        lines.append("")
        lines.append(_md_code_block(code.rstrip(), "c"))
    else:
        note = data.get("note", "")
        if note:
            lines.append(f"> **Note:** {note}")

    return "\n".join(lines)


def _render_list_functions(data: dict[str, Any]) -> str:
    """Render list-functions response as markdown table."""
    lines: list[str] = []
    lines.append(_md_heading(2, "Function Listing"))
    lines.append("")
    lines.append(_pagination_footer(data))
    lines.append("")

    results: list[dict[str, Any]] = data.get("results", [])
    if results:
        headers = ["Name", "Address", "Size", "Params", "External", "Thunk"]
        rows = [
            [
                f.get("name", ""),
                f.get("address", ""),
                str(f.get("size", "")),
                str(f.get("parameterCount", "")),
                "Yes" if f.get("isExternal") else "",
                "Yes" if f.get("isThunk") else "",
            ]
            for f in results
        ]
        lines.append(_md_table(headers, rows))
    else:
        lines.append("*No functions found matching the criteria.*")

    return "\n".join(lines)


def _render_get_functions(data: dict[str, Any]) -> str:
    """Render get-functions response based on view."""
    view = data.get("view", "info")
    if view == "decompile":
        return _render_decompile(data)
    if view == "disassemble":
        return _render_disassemble(data)
    if view == "calls":
        return _render_function_calls(data)
    return _render_function_info(data)


def _render_function_info(data: dict[str, Any]) -> str:
    lines: list[str] = []
    name = data.get("name", "unknown")
    lines.append(_md_heading(2, f"Function Info: `{name}`"))
    lines.append("")
    lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
    lines.append(_md_bold_kv("Signature", _md_code_inline(data.get("signature", ""))))
    lines.append(_md_bold_kv("Size", f"{data.get('size', 0)} bytes"))
    lines.append(_md_bold_kv("Return Type", _md_code_inline(data.get("returnType", "void"))))
    lines.append(_md_bold_kv("Calling Convention", data.get("callingConvention", "unknown")))
    flags = []
    if data.get("isExternal"):
        flags.append("External")
    if data.get("isThunk"):
        flags.append("Thunk")
    if data.get("hasVarArgs"):
        flags.append("VarArgs")
    if flags:
        lines.append(_md_bold_kv("Flags", ", ".join(flags)))
    lines.append("")

    params = data.get("parameters", [])
    if params:
        lines.append(_md_heading(3, "Parameters"))
        lines.append("")
        headers = ["#", "Name", "Type"]
        rows = [[str(p.get("ordinal", i)), p.get("name", ""), p.get("type", "")] for i, p in enumerate(params)]
        lines.append(_md_table(headers, rows))

    return "\n".join(lines)


def _render_function_calls(data: dict[str, Any]) -> str:
    lines: list[str] = []
    name = data.get("name", "unknown")
    lines.append(_md_heading(2, f"Call Relationships: `{name}`"))
    lines.append("")
    lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
    lines.append("")

    callers: list[dict[str, Any]] = data.get("callers", [])
    callees: list[dict[str, Any]] = data.get("callees", [])

    lines.append(_md_heading(3, f"Callers ({data.get('callerCount', len(callers))})"))
    lines.append("")
    if callers:
        headers = ["Function", "Address"]
        rows = [[c.get("name", ""), c.get("address", "")] for c in callers]
        lines.append(_md_table(headers, rows))
    else:
        lines.append("*No callers found (may be an entry point or dead code).*")
    lines.append("")

    lines.append(_md_heading(3, f"Callees ({data.get('calleeCount', len(callees))})"))
    lines.append("")
    if callees:
        headers = ["Function", "Address"]
        rows = [[c.get("name", ""), c.get("address", "")] for c in callees]
        lines.append(_md_table(headers, rows))
    else:
        lines.append("*No callees found (leaf function).*")

    return "\n".join(lines)


def _render_disassemble(data: dict[str, Any]) -> str:
    lines: list[str] = []
    name = data.get("name", "unknown")
    lines.append(_md_heading(2, f"Disassembly: `{name}`"))
    lines.append("")
    lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
    lines.append(_md_bold_kv("Instructions", str(data.get("instructionCount", 0))))
    lines.append("")

    instructions: list[dict[str, Any]] = data.get("instructions", [])
    if instructions:
        # Render as assembly code block
        asm_lines: list[str] = []
        for instr in instructions:
            addr = instr.get("address", "")
            operands = instr.get("operands", "")
            hex_bytes = instr.get("bytes", "")
            asm_lines.append(f"{addr}  {hex_bytes:<24s} {operands}")
        lines.append(_md_code_block("\n".join(asm_lines), "asm"))

    return "\n".join(lines)


def _render_symbols(data: dict[str, Any]) -> str:
    """Render manage-symbols response."""
    mode = data.get("mode", "symbols")
    lines: list[str] = []

    if mode == "count":
        lines.append(_md_heading(2, "Symbol Count"))
        lines.append("")
        lines.append(_md_bold_kv("Total Symbols", data.get("totalSymbols", 0)))
        return "\n".join(lines)

    if mode == "create_label":
        lines.append(_md_heading(2, "Label Created"))
        lines.append("")
        if data.get("batch"):
            results: list[dict[str, Any]] = data.get("results", [])
            for r in results:
                status = "OK" if r.get("success") else f"FAIL: {r.get('error', '')}"
                lines.append(f"- `{r.get('address', '')}` → `{r.get('label', '')}`: {status}")
        else:
            lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
            lines.append(_md_bold_kv("Label", _md_code_inline(data.get("label", ""))))
        return "\n".join(lines)

    if mode == "rename_data":
        lines.append(_md_heading(2, "Data Renamed"))
        lines.append("")
        lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
        lines.append(_md_bold_kv("New Name", _md_code_inline(data.get("newName", ""))))
        return "\n".join(lines)

    if mode == "demangle":
        lines.append(_md_heading(2, "Demangled Symbols"))
        lines.append("")
        results = data.get("results", [])
        if results:
            headers = ["Original", "Demangled", "Address"]
            rows = [[r.get("original", ""), r.get("demangled", ""), r.get("address", "")] for r in results]
            lines.append(_md_table(headers, rows))
        else:
            note = data.get("note", "")
            lines.append(f"*{note}*" if note else "*No results.*")
        return "\n".join(lines)

    # Paginated listing (symbols, imports, exports, classes, namespaces)
    mode_titles: dict[str, str] = {
        "symbols": "Symbol Listing",
        "imports": "Import Listing",
        "exports": "Export Listing",
        "classes": "Class Listing",
        "namespaces": "Namespace Listing",
        "search": "Symbol Search Results",
    }
    lines.append(_md_heading(2, mode_titles.get(mode, f"Symbols ({mode})")))
    lines.append("")
    lines.append(_pagination_footer(data))
    lines.append("")

    results = data.get("results", [])
    if results:
        # Detect columns from first result
        sample = results[0]
        if "type" in sample:
            headers = ["Name", "Address", "Type", "Namespace"]
            rows = [[r.get("name", ""), r.get("address", ""), r.get("type", ""), r.get("namespace", "")] for r in results]
        elif "namespace" in sample:
            headers = ["Name", "Address", "Namespace"]
            rows = [[r.get("name", ""), r.get("address", ""), r.get("namespace", "")] for r in results]
        else:
            headers = ["Name", "Address"]
            rows = [[r.get("name", ""), r.get("address", "")] for r in results]
        lines.append(_md_table(headers, rows))
    else:
        lines.append("*No results found.*")

    return "\n".join(lines)


def _render_search_everything(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(_md_heading(2, "Search Results"))
    lines.append("")

    query = data.get("queries", data.get("query", ""))
    search_mode = data.get("searchMode", "auto")
    scopes: list[str] = data.get("scopes", [])

    lines.append(_md_bold_kv("Query", _md_code_inline(str(query))))
    lines.append(_md_bold_kv("Mode", search_mode))
    if scopes:
        lines.append(_md_bold_kv("Scopes", ", ".join(str(s) for s in scopes)))
    lines.append(_pagination_footer(data))
    lines.append("")

    results: list[dict[str, Any]] = data.get("results", [])
    if results:
        headers = ["Type", "Name", "Address", "Context"]
        rows = []
        for r in results:
            rtype = r.get("resultType", r.get("type", ""))
            name = r.get("name", r.get("function", ""))
            addr = r.get("address", r.get("functionAddress", ""))
            context = r.get("match", r.get("snippet", r.get("value", "")))
            rows.append([rtype, str(name), str(addr), _truncate(str(context))])
        lines.append(_md_table(headers, rows))
    else:
        lines.append("*No results found.*")

    return "\n".join(lines)


def _render_memory(data: dict[str, Any]) -> str:
    mode = data.get("mode", "blocks")
    lines: list[str] = []

    if mode == "blocks":
        lines.append(_md_heading(2, "Memory Blocks"))
        lines.append("")
        blocks: list[dict[str, Any]] = data.get("blocks", [])
        lines.append(_md_bold_kv("Block Count", len(blocks)))
        lines.append("")
        if blocks:
            headers = ["Name", "Start", "End", "Size", "Perms", "Init", "Type"]
            rows: list[list[str]] = [
                [
                    b.get("name", ""),
                    b.get("start", ""),
                    b.get("end", ""),
                    str(b.get("size", "")),
                    b.get("permissions", ""),
                    "Yes" if b.get("initialized") else "No",
                    b.get("type", ""),
                ]
                for b in blocks
            ]
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    if mode == "read":
        lines.append(_md_heading(2, "Memory Read"))
        lines.append("")
        lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
        lines.append(_md_bold_kv("Length", f"{data.get('length', 0)} bytes"))
        lines.append("")
        hex_str: str = data.get("hex", "")
        ascii_str: str = data.get("ascii", "")
        if hex_str:
            lines.append(_md_heading(3, "Hex Dump"))
            lines.append("")
            # Format as 16-byte rows
            hex_bytes = hex_str.split()
            hex_lines = []
            for i in range(0, len(hex_bytes), 16):
                chunk = hex_bytes[i : i + 16]
                offset = i
                hex_part = " ".join(chunk)
                ascii_part = ascii_str[i : i + 16] if ascii_str else ""
                hex_lines.append(f"{offset:04x}  {hex_part:<48s}  |{ascii_part}|")
            lines.append(_md_code_block("\n".join(hex_lines), ""))
        return "\n".join(lines)

    if mode == "data_at":
        lines.append(_md_heading(2, "Data At Address"))
        lines.append("")
        lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
        dt = data.get("dataType")
        if dt:
            lines.append(_md_bold_kv("Data Type", _md_code_inline(str(dt))))
            lines.append(_md_bold_kv("Length", f"{data.get('length', 0)} bytes"))
            val = data.get("value")
            if val is not None:
                lines.append(_md_bold_kv("Value", _md_code_inline(str(val))))
            label = data.get("label")
            if label:
                lines.append(_md_bold_kv("Label", _md_code_inline(label)))
        else:
            note = data.get("note", "No defined data at this address")
            lines.append(f"> {note}")
        return "\n".join(lines)

    if mode == "data_items":
        lines.append(_md_heading(2, "Defined Data Items"))
        lines.append("")
        lines.append(_pagination_footer(data))
        lines.append("")
        results = data.get("results", [])
        if results:
            headers = ["Address", "Data Type", "Length", "Label"]
            rows: list[list[str]] = [[r.get("address", ""), r.get("dataType", ""), str(r.get("length", "")), r.get("label", "") or ""] for r in results]
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    # Fallback for unrecognized mode
    return _render_generic(data, "inspect-memory")


def _render_callgraph(data: dict[str, Any]) -> str:
    mode = data.get("mode", "graph")
    func_name = data.get("function", data.get("functionName", ""))
    lines: list[str] = []

    if mode in ("graph", "tree"):
        lines.append(_md_heading(2, f"Call Graph: `{func_name}`"))
        lines.append("")

        # Graph data from CallGraphTool
        graph_data: dict[str, Any] = data.get("graph", {})
        direction = data.get("direction", "")
        if direction:
            lines.append(_md_bold_kv("Direction", direction))

        # If we have callers/callees directly
        callers: list[dict[str, Any]] = data.get("callers", [])
        callees: list[dict[str, Any]] = data.get("callees", [])

        if callers or (callees and not graph_data):
            return _render_function_calls(data)

        # Rendered graph from CallGraphTool
        if graph_data:
            mermaid = data.get("mermaidUrl", "")  # noqa: F841
            # Render as bullet tree
            nodes: list[dict[str, Any]] = graph_data.get("nodes", [])
            edges: list[dict[str, Any]] = graph_data.get("edges", [])
            if nodes:
                lines.append(_md_heading(3, f"Nodes ({len(nodes)})"))
                lines.append("")
                for node in nodes[:50]:
                    name = node.get("name", node.get("label", ""))
                    addr = node.get("address", "")
                    lines.append(f"- `{name}` at `{addr}`")
            if edges:
                lines.append("")
                lines.append(_md_heading(3, f"Edges ({len(edges)})"))
                lines.append("")
                for edge in edges[:50]:
                    src = edge.get("source", edge.get("from", ""))
                    tgt = edge.get("target", edge.get("to", ""))
                    lines.append(f"- `{src}` → `{tgt}`")
        else:
            note = data.get("note", "")
            if note:
                lines.append(f"> {note}")

        return "\n".join(lines)

    if mode == "callers":
        lines.append(_md_heading(2, f"Callers of `{func_name}`"))
        lines.append("")
        callers: list[dict[str, Any]] = data.get("callers", data.get("commonCallers", []))
        second: str = data.get("secondFunction", "")
        if second:
            lines.append(_md_bold_kv("Common callers with", _md_code_inline(second)))
            lines.append("")
        if callers:
            headers = ["Function", "Address"]
            rows: list[list[str]] = [[c.get("name", ""), c.get("address", "")] for c in callers]
            lines.append(_md_table(headers, rows))
        else:
            lines.append("*No callers found.*")
        return "\n".join(lines)

    if mode == "callees":
        lines.append(_md_heading(2, f"Callees of `{func_name}`"))
        lines.append("")
        callees: list[dict[str, Any]] = data.get("callees", [])
        if callees:
            headers = ["Function", "Address"]
            rows = [[c.get("name", ""), c.get("address", "")] for c in callees]
            lines.append(_md_table(headers, rows))
        else:
            lines.append("*No callees found (leaf function).*")
        return "\n".join(lines)

    return _render_generic(data, "get-call-graph")


def _render_comments(data: dict[str, Any]) -> str:
    action = data.get("action", data.get("mode", ""))
    lines: list[str] = []

    if action == "set":
        lines.append(_md_heading(2, "Comment Set"))
        lines.append("")
        if data.get("batch"):
            results: list[dict[str, Any]] = data.get("results", [])
            for r in results:
                status = "OK" if r.get("success") else f"FAIL: {r.get('error', '')}"
                lines.append(f"- `{r.get('address', '')}`: {status}")
            lines.append("")
            lines.append(_md_bold_kv("Batch Size", data.get("count", len(results))))
        else:
            lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
            lines.append(_md_bold_kv("Type", data.get("type", "eol")))
            lines.append(_md_bold_kv("Comment", data.get("comment", "")))
        return "\n".join(lines)

    if action == "get":
        addr = data.get("address", "")
        lines.append(_md_heading(2, f"Comments at `{addr}`"))
        lines.append("")
        comments: dict[str, str] = data.get("comments", {})
        if any(v for v in comments.values() if v):
            for ctype, ctext in comments.items():
                if ctext:
                    lines.append(_md_bold_kv(ctype.upper(), ctext))
        else:
            lines.append("*No comments at this address.*")
        return "\n".join(lines)

    if action == "remove":
        lines.append(_md_heading(2, "Comment Removed"))
        lines.append("")
        lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
        lines.append(_md_bold_kv("Type", data.get("type", "")))
        return "\n".join(lines)

    if action in ("search", "search_decomp"):
        lines.append(_md_heading(2, "Comment Search Results"))
        lines.append("")
        query = data.get("query", "")
        if query:
            lines.append(_md_bold_kv("Query", _md_code_inline(query)))
        if "total" in data:
            lines.append(_pagination_footer(data))
        lines.append("")
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            if action == "search_decomp":
                headers = ["Function", "Address", "Snippet"]
                rows: list[list[str]] = [[r.get("function", ""), r.get("address", ""), _truncate(r.get("snippet", ""))] for r in results]
            else:
                headers = ["Address", "Type", "Comment"]
                rows = [[r.get("address", ""), r.get("type", ""), _truncate(r.get("comment", ""))] for r in results]
            lines.append(_md_table(headers, rows))
        else:
            lines.append("*No matching comments found.*")
        return "\n".join(lines)

    return _render_generic(data, "manage-comments")


def _render_bookmarks(data: dict[str, Any]) -> str:
    action = data.get("action", data.get("mode", ""))
    lines: list[str] = []

    if action in ("set", "add_batch"):
        lines.append(_md_heading(2, "Bookmark Set"))
        lines.append("")
        if data.get("batch") or action == "add_batch":
            results: list[dict[str, Any]] = data.get("results", [])
            for r in results:
                status = "OK" if r.get("success") else "FAIL"
                lines.append(f"- `{r.get('address', '')}` [{r.get('category', '')}]: {status}")
        else:
            lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
            lines.append(_md_bold_kv("Type", data.get("type", "")))
            lines.append(_md_bold_kv("Category", data.get("category", "")))
            note = data.get("note")
            if note:
                lines.append(_md_bold_kv("Note", note))
        return "\n".join(lines)

    if action == "remove":
        lines.append(_md_heading(2, "Bookmark Removed"))
        lines.append("")
        lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
        return "\n".join(lines)

    if action == "remove_all":
        lines.append(_md_heading(2, "All Bookmarks Removed"))
        return "\n".join(lines)

    if action == "categories":
        lines.append(_md_heading(2, "Bookmark Categories"))
        lines.append("")
        categories = data.get("categories", [])
        if categories:
            for cat in categories:
                lines.append(f"- {cat}")
        else:
            lines.append("*No bookmark categories defined.*")
        return "\n".join(lines)

    # get/search mode — paginated listing
    lines.append(_md_heading(2, "Bookmarks"))
    lines.append("")
    lines.append(_pagination_footer(data))
    lines.append("")
    results = data.get("results", [])
    if results:
        sample = results[0]
        cols = ["address", "type", "category", "comment"]
        headers = [c.capitalize() for c in cols if c in sample]
        rows = [[str(r.get(c, "")) for c in cols if c in sample] for r in results]
        lines.append(_md_table(headers, rows))
    else:
        lines.append("*No bookmarks found.*")

    return "\n".join(lines)


def _render_structures(data: dict[str, Any]) -> str:
    action = data.get("action", "")
    lines: list[str] = []

    if action == "list":
        lines.append(_md_heading(2, "Structure Listing"))
        lines.append("")
        structs: list[dict[str, Any]] = data.get("structures", [])
        lines.append(_md_bold_kv("Count", data.get("count", len(structs))))
        lines.append("")
        if structs:
            headers: list[str] = ["Name", "Path", "Size", "Fields", "Union"]
            rows: list[list[str]] = [
                [
                    s.get("name", ""),
                    s.get("path", ""),
                    str(s.get("length", "")),
                    str(s.get("numComponents", "")),
                    "Yes" if s.get("isUnion") else "",
                ]
                for s in structs
            ]
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    if action == "info":
        name = data.get("name", "")
        lines.append(_md_heading(2, f"Structure: `{name}`"))
        lines.append("")
        lines.append(_md_bold_kv("Size", f"{data.get('length', 0)} bytes"))
        lines.append(_md_bold_kv("Fields", data.get("numComponents", 0)))
        desc = data.get("description")
        if desc:
            lines.append(_md_bold_kv("Description", desc))
        lines.append("")

        fields: list[dict[str, Any]] = data.get("fields", [])
        if fields:
            lines.append(_md_heading(3, "Fields"))
            lines.append("")
            headers = ["Offset", "Name", "Type", "Size", "Comment"]
            rows: list[list[str]] = [
                [
                    str(f.get("offset", "")),
                    f.get("name", ""),
                    f.get("dataType", ""),
                    str(f.get("length", "")),
                    f.get("comment", "") or "",
                ]
                for f in fields
            ]
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    if action in ("create", "add_field", "modify_field", "modify_from_c", "delete", "apply"):
        lines.append(_md_heading(2, f"Structure {action.replace('_', ' ').title()}"))
        lines.append("")
        success = data.get("success", True)
        lines.append(_md_bold_kv("Status", "Success" if success else "Failed"))
        name = data.get("name", data.get("structure", ""))
        if name:
            lines.append(_md_bold_kv("Structure", _md_code_inline(name)))
        if data.get("batch"):
            results: list[dict[str, Any]] = data.get("results", [])
            for r in results:
                status = "OK" if r.get("success") else f"FAIL: {r.get('error', '')}"
                lines.append(f"- `{r.get('name', r.get('address', ''))}`: {status}")
        return "\n".join(lines)

    if action == "validate":
        lines.append(_md_heading(2, "Structure Validation"))
        lines.append("")
        if data.get("valid"):
            lines.append(f"**`{data.get('name', '')}`** is valid.")
        else:
            lines.append(f"**Validation failed:** {data.get('error', 'unknown error')}")
        return "\n".join(lines)

    return _render_generic(data, "manage-structures")


def _render_constants(data: dict[str, Any]) -> str:
    lines: list[str] = []
    mode = data.get("mode", "")
    lines.append(_md_heading(2, f"Constant Search ({mode})"))
    lines.append("")
    lines.append(_pagination_footer(data))
    scanned: int = data.get("instructionsScanned", 0)
    if scanned:
        lines.append(_md_bold_kv("Instructions Scanned", f"{scanned:,}"))
    lines.append("")

    results: list[dict[str, Any]] = data.get("results", [])
    if results:
        sample = results[0]
        if "value" in sample:
            headers: list[str] = ["Address", "Value", "Function", "Mnemonic"]
            rows: list[list[str]] = [
                [
                    r.get("address", ""),
                    str(r.get("value", "")),
                    r.get("function", ""),
                    r.get("mnemonic", ""),
                ]
                for r in results
            ]
        else:
            headers = list(sample.keys())
            rows = [[str(r.get(h, "")) for h in headers] for r in results]
        lines.append(_md_table(headers, rows))
    else:
        lines.append("*No constants found matching the criteria.*")

    return "\n".join(lines)


def _render_dataflow(data: dict[str, Any]) -> str:
    lines: list[str] = []
    direction = data.get("direction", "")
    func_name = data.get("function", "")
    addr = data.get("address", "")

    lines.append(_md_heading(2, f"Data Flow Analysis ({direction})"))
    lines.append("")
    if func_name:
        lines.append(_md_bold_kv("Function", _md_code_inline(func_name)))
    if addr:
        lines.append(_md_bold_kv("Address", _md_code_inline(addr)))
    lines.append("")

    if direction == "variable_accesses":
        variables: list[dict[str, Any]] = data.get("variables", [])
        if variables:
            headers: list[str] = ["Name", "Type", "Storage", "Size"]
            rows: list[list[str]] = [[v.get("name", ""), v.get("dataType", ""), v.get("storage", ""), str(v.get("size", ""))] for v in variables]
            lines.append(_md_table(headers, rows))
        else:
            lines.append("*No variable accesses found.*")
    else:
        pcodes: list[dict[str, Any]] = data.get("pcode", [])
        if pcodes:
            lines.append(_md_heading(3, f"P-Code Operations ({data.get('count', len(pcodes))})"))
            lines.append("")
            headers = ["Address", "Mnemonic", "Output", "Inputs"]
            rows = [
                [
                    p.get("address", ""),
                    p.get("mnemonic", ""),
                    p.get("output", ""),
                    ", ".join(p.get("inputs", [])) if isinstance(p.get("inputs"), list) else str(p.get("inputs", "")),
                ]
                for p in pcodes
            ]
            lines.append(_md_table(headers, rows))
        else:
            note = data.get("note", data.get("error", ""))
            lines.append(f"*{note}*" if note else "*No data flow information available.*")

    return "\n".join(lines)


def _render_strings(data: dict[str, Any]) -> str:
    mode = data.get("mode", "")
    lines: list[str] = []

    if mode == "count":
        lines.append(_md_heading(2, "String Count"))
        lines.append("")
        lines.append(_md_bold_kv("Total Strings", data.get("totalStrings", 0)))
        return "\n".join(lines)

    lines.append(_md_heading(2, "Strings"))
    lines.append("")
    lines.append(_pagination_footer(data))
    lines.append("")

    results: list[dict[str, Any]] = data.get("results", [])
    if results:
        headers: list[str] = ["Address", "Value"]
        sample = results[0]
        if "referencingFunctions" in sample:
            headers.append("References")
        rows: list[list[str]] = []
        for r in results:
            row = [r.get("address", ""), _truncate(r.get("value", ""), 80)]
            if "referencingFunctions" in sample:
                refs = r.get("referencingFunctions", [])
                row.append(str(len(refs)) if isinstance(refs, list) else str(refs))
            rows.append(row)
        lines.append(_md_table(headers, rows))
    else:
        lines.append("*No strings found.*")

    return "\n".join(lines)


def _render_datatypes(data: dict[str, Any]) -> str:
    action = data.get("action", "")
    lines: list[str] = []

    if action == "archives":
        lines.append(_md_heading(2, "Data Type Archives"))
        lines.append("")
        archives: list[dict[str, Any]] = data.get("archives", [])
        lines.append(_md_bold_kv("Count", data.get("count", len(archives))))
        lines.append("")
        if archives:
            for arch in archives:
                if isinstance(arch, dict):
                    lines.append(f"- **{arch.get('name', '')}**: {arch.get('path', '')}")
                else:
                    lines.append(f"- {arch}")
        return "\n".join(lines)

    if action == "list":
        category = data.get("category", "/")
        lines.append(_md_heading(2, f"Data Types in `{category}`"))
        lines.append("")
        lines.append(_md_bold_kv("Count", data.get("count", 0)))
        lines.append("")
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            headers: list[str] = ["Name", "Path", "Size"]
            rows: list[list[str]] = []
            for r in results:
                name_display = f"📁 {r.get('name', '')}" if r.get("isCategory") else r.get("name", "")
                rows.append([name_display, r.get("path", ""), str(r.get("length", "")) if not r.get("isCategory") else ""])
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    if action == "by_string":
        resolved: dict[str, Any] = data.get("resolved", {})
        lines.append(_md_heading(2, f"Data Type: `{data.get('input', '')}`"))
        lines.append("")
        if resolved:
            lines.append(_md_bold_kv("Name", resolved.get("name", "")))
            lines.append(_md_bold_kv("Path", resolved.get("path", "")))
            lines.append(_md_bold_kv("Size", f"{resolved.get('length', 0)} bytes"))
            desc = resolved.get("description")
            if desc:
                lines.append(_md_bold_kv("Description", desc))
        return "\n".join(lines)

    if action == "apply":
        lines.append(_md_heading(2, "Data Type Applied"))
        lines.append("")
        if data.get("batch"):
            results: list[dict[str, Any]] = data.get("results", [])
            for r in results:
                status = "OK" if r.get("success") else f"FAIL: {r.get('error', '')}"
                lines.append(f"- `{r.get('address', '')}`: {status}")
        else:
            lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
            lines.append(_md_bold_kv("Type", _md_code_inline(data.get("dataType", ""))))
        return "\n".join(lines)

    return _render_generic(data, "manage-data-types")


def _render_vtable(data: dict[str, Any]) -> str:
    mode = data.get("mode", "")
    lines: list[str] = []

    if mode == "containing":
        lines.append(_md_heading(2, "Vtable Search Results"))
        lines.append("")
        lines.append(_pagination_footer(data))
        lines.append("")
        results = data.get("results", [])
        if results:
            headers = ["Address", "Name", "Type", "Size"]
            rows = [[r.get("address", ""), r.get("name", ""), r.get("type", ""), str(r.get("size", ""))] for r in results]
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    if mode == "analyze":
        vtable_addr = data.get("vtableAddress", "")
        lines.append(_md_heading(2, f"Vtable Analysis at `{vtable_addr}`"))
        lines.append("")
        lines.append(_md_bold_kv("Pointer Size", f"{data.get('pointerSize', 0)} bytes"))
        lines.append(_md_bold_kv("Entry Count", data.get("count", 0)))
        lines.append("")
        entries: list[dict[str, Any]] = data.get("entries", [])
        if entries:
            headers = ["#", "Address", "Target", "Function"]
            rows: list[list[str]] = [[str(e.get("index", "")), e.get("address", ""), e.get("target", ""), e.get("function", "")] for e in entries]
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    if mode == "callers":
        lines.append(_md_heading(2, "Vtable Callers"))
        lines.append("")
        vtable_addr = data.get("vtableAddress", "")
        if vtable_addr:
            lines.append(_md_bold_kv("Vtable", _md_code_inline(vtable_addr)))
        lines.append(_pagination_footer(data))
        lines.append("")
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            headers: list[str] = ["From Address", "Function", "Ref Type"]
            rows: list[list[str]] = [[r.get("fromAddress", ""), r.get("function", ""), r.get("refType", "")] for r in results]
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    return _render_generic(data, "analyze-vtables")


def _render_import_export(data: dict[str, Any]) -> str:
    action = data.get("action", data.get("operation", ""))
    lines: list[str] = []

    if action == "import":
        lines.append(_md_heading(2, "Binary Import Results"))
        lines.append("")
        lines.append(_md_bold_kv("Source", data.get("importedFrom", "")))
        lines.append(_md_bold_kv("Files Discovered", data.get("filesDiscovered", 0)))
        lines.append(_md_bold_kv("Files Imported", data.get("filesImported", 0)))
        lines.append(_md_bold_kv("Analysis Requested", "Yes" if data.get("analysisRequested") else "No"))
        programs: list[dict[str, Any]] = data.get("importedPrograms", [])
        if programs:
            lines.append("")
            lines.append(_md_heading(3, "Imported Programs"))
            lines.append("")
            for p in programs:
                lines.append(f"- `{p.get('programName', '')}` from `{p.get('sourcePath', '')}`")
        errors: list[str] = data.get("errors", [])
        if errors:
            lines.append("")
            lines.append(_md_heading(3, "Errors"))
            for e in errors:
                lines.append(f"- {e}")
        return "\n".join(lines)

    if action == "export":
        lines.append(_md_heading(2, "Export Results"))
        lines.append("")
        lines.append(_md_bold_kv("Format", data.get("format", "")))
        lines.append(_md_bold_kv("Output Path", _md_code_inline(data.get("outputPath", ""))))
        lines.append(_md_bold_kv("Status", "Success" if data.get("success") else "Failed"))
        err: str = data.get("error", "")
        if err:
            lines.append(_md_bold_kv("Error", err))
        return "\n".join(lines)

    if action == "analyze":
        lines.append(_md_heading(2, "Analysis Results"))
        lines.append("")
        lines.append(_md_bold_kv("Program", data.get("programName", "")))
        lines.append(_md_bold_kv("Status", "Success" if data.get("success") else "Failed"))
        analyzers: list[str] = data.get("analyzers", [])
        if analyzers:
            lines.append(_md_bold_kv("Analyzers", analyzers))
        return "\n".join(lines)

    if action == "checkin":
        lines.append(_md_heading(2, "Check-in Result"))
        lines.append("")
        lines.append(_md_bold_kv("Program", data.get("program", "")))
        lines.append(_md_bold_kv("Message", data.get("message", "")))
        lines.append(_md_bold_kv("Status", "Success" if data.get("success") else "Failed"))
        return "\n".join(lines)

    if action in ("change_processor", "list_processors"):
        lines.append(_md_heading(2, action.replace("_", " ").title()))
        lines.append("")
        if action == "list_processors":
            processors: list[str] = data.get("processors", [])
            lines.append(_md_bold_kv("Count", data.get("count", len(processors))))
            lines.append("")
            for p in processors[:50]:
                lines.append(f"- {p}")
        else:
            lines.append(_md_bold_kv("Language", data.get("language", "")))
            lines.append(_md_bold_kv("Compiler", data.get("compiler", "")))
            lines.append(_md_bold_kv("Status", "Success" if data.get("success") else "Failed"))
        return "\n".join(lines)

    return _render_generic(data, "import-export")


def _render_project(data: dict[str, Any]) -> str:
    action = data.get("action", data.get("operation", ""))
    loaded = data.get("loaded")
    lines: list[str] = []

    if action == "open-project":
        mode: str = data.get("mode", "")
        lines.append(_md_heading(2, "Program Opened"))
        lines.append("")
        lines.append(_md_bold_kv("Mode", mode or "local"))
        msg: str = data.get("message", "")
        if msg:
            lines.append(_md_bold_kv("Message", msg))
        path: str = data.get("path", data.get("serverHost", ""))
        if path:
            lines.append(_md_bold_kv("Path/Host", _md_code_inline(str(path))))
        programs: list[dict[str, Any]] = data.get("programs", [])
        if programs:
            lines.append("")
            lines.append(_md_heading(3, f"Programs ({data.get('programCount', len(programs))})"))
            lines.append("")
            for p in programs[:20]:
                if isinstance(p, dict):
                    lines.append(f"- `{p.get('name', '')}`")
                else:
                    lines.append(f"- `{p}`")
        return "\n".join(lines)

    if loaded is True:
        lines.append(_md_heading(2, "Current Program"))
        lines.append("")
        lines.append(_md_bold_kv("Name", _md_code_inline(data.get("name", ""))))
        lines.append(_md_bold_kv("Path", _md_code_inline(data.get("path", ""))))
        lines.append(_md_bold_kv("Language", data.get("language", "")))
        lines.append(_md_bold_kv("Compiler", data.get("compiler", "")))
        lines.append(_md_bold_kv("Image Base", _md_code_inline(str(data.get("imageBase", "")))))
        lines.append(_md_bold_kv("Functions", data.get("functionCount", 0)))
        lines.append(_md_bold_kv("Symbols", data.get("symbolCount", 0)))
        blocks: list[dict[str, Any]] = data.get("memoryBlocks", [])
        if blocks:
            lines.append(_md_bold_kv("Memory Blocks", blocks))
        return "\n".join(lines)

    if loaded is False:
        lines.append(_md_heading(2, "No Program Loaded"))
        lines.append("")
        lines.append(f"> {data.get('note', 'No program is currently loaded.')}")
        return "\n".join(lines)

    if action == "list" or "files" in data or "entries" in data:
        lines.append(_md_heading(2, "Project Files"))
        lines.append("")
        folder: str = data.get("folder", "")
        if folder:
            lines.append(_md_bold_kv("Folder", _md_code_inline(folder)))
        files: list[dict[str, Any]] = data.get("files", data.get("entries", []))
        lines.append(_md_bold_kv("Count", data.get("count", len(files))))
        lines.append("")
        if files:
            headers = ["Name", "Path", "Type/Size"]
            rows: list[list[str]] = []
            for f in files:
                name = f.get("name", "")
                path = f.get("path", "")
                type_or_size = f.get("type", "")
                if not type_or_size:
                    size = f.get("size", "")
                    is_dir = f.get("isDirectory", False)
                    type_or_size = "directory" if is_dir else str(size)
                rows.append([name, path, type_or_size])
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    return _render_generic(data, "project")


def _render_suggestions(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(_md_heading(2, "Suggestion Context"))
    lines.append("")
    lines.append(_md_bold_kv("Type", data.get("suggestionType", "")))
    addr = data.get("address")
    if addr:
        lines.append(_md_bold_kv("Address", _md_code_inline(addr)))
    var = data.get("variableName")
    if var:
        lines.append(_md_bold_kv("Variable", _md_code_inline(var)))
    context = data.get("context", {})
    if isinstance(context, dict):
        note = context.get("note", "")
        if note:
            lines.append(f"> {note}")
    return "\n".join(lines)


def _render_data(data: dict[str, Any]) -> str:
    lines: list[str] = []
    if data.get("success") is not None and "address" in data and "dataType" in data:
        # apply-data-type response
        lines.append(_md_heading(2, "Data Type Applied"))
        lines.append("")
        lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
        lines.append(_md_bold_kv("Type", _md_code_inline(data.get("dataType", ""))))
        return "\n".join(lines)

    # get-data response
    lines.append(_md_heading(2, "Data At Address"))
    lines.append("")
    lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
    if data.get("definedType"):
        lines.append(_md_bold_kv("Type", _md_code_inline(data.get("definedType", ""))))
    if data.get("value"):
        lines.append(_md_bold_kv("Value", _md_code_inline(str(data.get("value", "")))))
    if data.get("length"):
        lines.append(_md_bold_kv("Length", f"{data['length']} bytes"))
    hex_str = data.get("hex", "")
    ascii_str = data.get("ascii", "")
    if hex_str:
        lines.append("")
        lines.append(_md_heading(3, "Raw Bytes"))
        lines.append("")
        lines.append(_md_code_block(f"Hex:   {hex_str}\nASCII: {ascii_str}", ""))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Error renderer
# ---------------------------------------------------------------------------


def _render_error(data: dict[str, Any]) -> str:
    """Render an error response as readable markdown."""
    lines: list[str] = []
    lines.append(_md_heading(2, "Error"))
    lines.append("")
    lines.append(f"> **{data.get('error', 'Unknown error')}**")
    lines.append("")

    context = data.get("context", {})
    state = data.get("state", context.get("state", ""))
    if state:
        lines.append(_md_bold_kv("State", _md_code_inline(state)))

    tool = data.get("tool", context.get("tool", ""))
    if tool:
        lines.append(_md_bold_kv("Tool", _md_code_inline(tool)))

    detail_keys = [
        ("Provider", "provider"),
        ("Connection Stage", "connectionStage"),
        ("Server Host", "serverHost"),
        ("Server Port", "serverPort"),
        ("Server Reachable", "serverReachable"),
        ("Auth Provided", "authProvided"),
        ("Server Username", "serverUsername"),
        ("Repository", "repository"),
        ("Adapter Error Type", "adapterErrorType"),
        ("Adapter Error", "adapterError"),
        ("Wrapper Error", "wrapperError"),
    ]
    for label, key in detail_keys:
        value = data.get(key, context.get(key, ""))
        if value in ("", None, []):
            continue
        lines.append(_md_bold_kv(label, value))

    next_steps = data.get("nextSteps", [])
    if next_steps:
        lines.append("")
        lines.append(_md_heading(3, "How to Fix"))
        lines.append("")
        for i, step in enumerate(next_steps, 1):
            lines.append(f"{i}. {step}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Generic fallback renderer
# ---------------------------------------------------------------------------


def _render_generic(data: dict[str, Any], tool_name: str = "") -> str:
    """Smart generic renderer for tools without a custom renderer.

    Detects pagination envelopes, single items, and error responses,
    and renders them appropriately.
    """
    lines: list[str] = []

    # Title from mode/action or tool name
    mode = data.get("mode", data.get("action", data.get("operation", "")))
    title = tool_name.replace("-", " ").title()
    if mode:
        title = f"{title} ({mode})"
    lines.append(_md_heading(2, title))
    lines.append("")

    # Check for pagination envelope
    if "results" in data and isinstance(data["results"], list):
        lines.append(_pagination_footer(data))
        lines.append("")
        results: list[dict[str, Any]] = data["results"]
        if results:
            if isinstance(results[0], dict):
                headers = list(results[0].keys())
                # Filter out very long/nested fields
                headers = [h for h in headers if h not in ("nextTools",)]
                rows: list[list[str]] = [[_truncate(str(r.get(h, "")), 60) for h in headers] for r in results]
                lines.append(_md_table(headers, rows))
            else:
                for r in results:
                    lines.append(f"- {r}")
        else:
            lines.append("*No results.*")
    else:
        # Single item — render as key-value pairs
        skip_keys = {"success", "nextSteps", "context", "nextTools"}
        for key, value in data.items():
            if key in skip_keys:
                continue
            if isinstance(value, (list, dict)):
                if isinstance(value, list) and value and not isinstance(value[0], dict):
                    lines.append(_md_bold_kv(key, ", ".join(str(v) for v in value)))
                elif isinstance(value, list) and value and isinstance(value[0], dict):
                    lines.append("")
                    lines.append(_md_heading(3, key.replace("_", " ").title()))
                    lines.append("")
                    headers = list(value[0].keys())
                    rows: list[list[str]] = [[_truncate(str(item.get(h, "")), 60) for h in headers] for item in cast("list[dict[str, Any]]", value)]
                    lines.append(_md_table(headers, rows))
                elif isinstance(value, dict):
                    lines.append("")
                    lines.append(_md_heading(3, key.replace("_", " ").title()))
                    lines.append("")
                    for k2, v2 in value.items():
                        lines.append(_md_bold_kv(k2, v2))
                else:
                    lines.append(_md_bold_kv(key, str(value)))
            else:
                lines.append(_md_bold_kv(key, value))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool renderer registry: normalized name → render function
# ---------------------------------------------------------------------------

TOOL_RENDERERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "executescript": _render_execute_script,
    "decompile": _render_decompile,
    "decompilefunction": _render_decompile,
    "listfunctions": _render_list_functions,
    "getfunctions": _render_get_functions,
    "managesymbols": _render_symbols,
    "searchsymbolsbyname": _render_symbols,
    "searchsymbols": _render_symbols,
    "listimports": _render_symbols,
    "listexports": _render_symbols,
    "createlabel": _render_symbols,
    "searcheverything": _render_search_everything,
    "globalsearch": _render_search_everything,
    "searchanything": _render_search_everything,
    "inspectmemory": _render_memory,
    "readbytes": _render_memory,
    "getcallgraph": _render_callgraph,
    "gencallgraph": _render_callgraph,
    "managecomments": _render_comments,
    "managebookmarks": _render_bookmarks,
    "managestructures": _render_structures,
    "searchconstants": _render_constants,
    "analyzedataflow": _render_dataflow,
    "managedatatypes": _render_datatypes,
    "analyzevtables": _render_vtable,
    "managestrings": _render_strings,
    "liststrings": _render_strings,
    "searchstrings": _render_strings,
    "searchcode": _render_strings,
    "getdata": _render_data,
    "applydatatype": _render_data,
    "importbinary": _render_import_export,
    "export": _render_import_export,
    "analyzeprogram": _render_import_export,
    "checkinprogram": _render_import_export,
    "changeprocessor": _render_import_export,
    "listprocessors": _render_import_export,
    "openproject": _render_project,
    "getcurrentprogram": _render_project,
    "listprojectfiles": _render_project,
    "managefiles": _render_project,
    "syncsharedproject": _render_project,
    "listprojectbinaries": _render_project,
    "listprojectbinarymetadata": _render_project,
    "deleteprojectbinary": _render_project,
    "listopenprograms": _render_project,
    "getcurrentaddress": _render_project,
    "getcurrentfunction": _render_project,
    "suggest": _render_suggestions,
    "getsuggestions": _render_suggestions,
    "matchfunction": _render_generic,
    "managefunctiontags": _render_generic,
    "managefunction": _render_generic,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------


def render_tool_response(normalized_tool_name: str, data: dict[str, Any]) -> str:
    """Render a tool's JSON response data as rich markdown.

    This is the single entry point used by the ToolProvider.call_tool() intercept.

    Args:
        normalized_tool_name: The normalized (lowercase, alpha-only) tool name.
        data: The raw response dict that would normally be JSON-serialized.

    Returns:
        A markdown string suitable for returning as TextContent.text.
    """
    # Check for error responses first
    if data.get("success") is False:
        body: str = _render_error(data)
    else:
        renderer = TOOL_RENDERERS.get(normalized_tool_name)
        if renderer is not None:
            try:
                body = renderer(data)
            except Exception:
                body = _render_generic(data, normalized_tool_name)
        else:
            body = _render_generic(data, normalized_tool_name)

    # Append About This Tool / Next Steps section
    guidance: tuple[str, Callable[[dict[str, Any]], list[str]]] | None = TOOL_GUIDANCE.get(normalized_tool_name)
    lines: list[str] = [body]

    if guidance:
        description, next_steps_fn = guidance
        lines.append("")
        lines.append(_md_heading(3, "About This Tool"))
        lines.append("")
        lines.append(description)

        try:
            next_steps = next_steps_fn(data)
        except Exception:
            next_steps = []

        next_steps: list[str] = _filter_disabled_tool_recommendations(next_steps)

        if next_steps:
            lines.append("")
            lines.append(_md_heading(3, "Suggested Next Steps"))
            lines.append("")
            for i, step in enumerate(next_steps, 1):
                lines.append(f"{i}. {step}")

    return "\n".join(lines)
