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

import logging
import re

from typing import TYPE_CHECKING, Any, cast

from agentdecompile_cli.app_logger import norm_arg_keys
from agentdecompile_cli.registry import Tool, is_tool_advertised, normalize_identifier

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Markdown building helpers
# ---------------------------------------------------------------------------


def _md_heading(level: int, text: str) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_md_heading")
    return f"{'#' * level} {text}"


def _md_bold_kv(key: str, value: Any) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_md_bold_kv")
    return f"**{key}:** {value}"


def _md_code_inline(text: str) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_md_code_inline")
    return f"`{text}`"


def _md_code_block(code: str, lang: str = "") -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_md_code_block")
    return f"```{lang}\n{code}\n```"


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_md_table")
    if not headers:
        return ""
    header_row: str = "| " + " | ".join(headers) + " |"
    sep_row: str = "| " + " | ".join("---" for _ in headers) + " |"
    body: str = "\n".join("| " + " | ".join(str(c) for c in row) + " |" for row in rows)
    return f"{header_row}\n{sep_row}\n{body}" if body else f"{header_row}\n{sep_row}"


def _md_bullet_list(items: list[str]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_md_bullet_list")
    return "\n".join(f"- {item}" for item in items)


def _truncate(s: str, max_len: int = 120) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_truncate")
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _extract_searchable_ascii_token(text: str, min_len: int = 4) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_extract_searchable_ascii_token")
    if not text:
        return ""
    match = re.search(rf"[A-Za-z0-9_.$@/-]{{{min_len},}}", text)
    return match.group(0) if match else ""


def _looks_like_pointer_type(data_type: str) -> bool:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_looks_like_pointer_type")
    lowered = data_type.lower()
    return "pointer" in lowered or "ptr" in lowered or "*" in data_type


def _is_address_like(value: str) -> bool:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_is_address_like")
    return bool(re.fullmatch(r"(?:0x)?[0-9A-Fa-f]+", value.strip()))


def _prefer_function_target(entry: dict[str, Any]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_prefer_function_target")
    address = str(entry.get("address", "") or "")
    name = str(entry.get("name", "") or "")
    return address or name


def _decompilation_text_embeds_disassembly(decomp: str) -> bool:
    """True when the decompilation string already carries a disassembly listing (skip duplicate ### Disassembly)."""
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_decompilation_text_embeds_disassembly")
    if not (decomp and isinstance(decomp, str)):
        return False
    d = decomp.strip()
    if "/* Disassembly */" in d:
        return True
    return False


def _pagination_footer(data: dict[str, Any]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_pagination_footer")
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


# Tools that may be disabled via AGENTDECOMPILE_DISABLE_TOOLS etc.; if disabled,
# we omit "Suggested Next Steps" lines that mention them so the client isn't told to use unavailable tools.
_DISABLABLE_RECOMMENDATION_TOOLS: set[str] = {
    normalize_identifier("annotate-function"),
    Tool.GET_FUNCTIONS.normalized,
    Tool.LIST_STRINGS.normalized,
    Tool.MANAGE_BOOKMARKS.normalized,
    Tool.MANAGE_COMMENTS.normalized,
    Tool.MANAGE_DATA_TYPES.normalized,
    Tool.MANAGE_FILES.normalized,
    Tool.MANAGE_FUNCTION.normalized,
    Tool.MANAGE_STRUCTURES.normalized,
    Tool.MANAGE_SYMBOLS.normalized,
    Tool.SEARCH_STRINGS.normalized,
}


def _filter_disabled_tool_recommendations(steps: list[str]) -> list[str]:
    """Drop recommendation lines that reference tools disabled via env configuration.
    Also drops steps that mention get-functions (e.g. `get-functions address=...`)
    when that tool is not advertised (legacy mode off).
    """
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_filter_disabled_tool_recommendations")
    filtered: list[str] = []
    for step in steps:
        mentioned = re.findall(r"`([A-Za-z0-9_-]+)`", step)
        blocked = False
        for token in mentioned:
            token_norm = normalize_identifier(token)
            if token_norm in _DISABLABLE_RECOMMENDATION_TOOLS and not is_tool_advertised(token):
                blocked = True
                break
        # Steps like "Decompile/disassemble/inspect containing function: `get-function address=...`"
        # have the tool name inside a longer backticked phrase; the regex above won't match.
        if not blocked and "get-functions" in step and not is_tool_advertised("get-functions"):
            blocked = True
        if not blocked:
            filtered.append(step)
    return filtered


# ---------------------------------------------------------------------------
# Tool guidance registry: maps normalized tool name → (description, next_steps_fn)
# next_steps_fn(data) → list[str]
# ---------------------------------------------------------------------------


def _next_steps_execute_script(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_execute_script")
    steps: list[str] = []
    has_error = bool(data.get("stderr"))
    has_output = bool(data.get("stdout") or data.get("result"))
    if has_error and not has_output:
        steps.append("Review the traceback above and fix the script, then call `execute-script` again.")
    if has_output:
        steps.append("If the script retrieved function/address data, use `get-function address=...` to inspect specific functions.")
        steps.append("Use `manage-comments` or `manage-bookmarks` to annotate interesting findings.")
    steps.append("For batch analysis across many functions, combine `list-functions` output with `execute-script` loops.")
    return steps


def _next_steps_decompile(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_decompile")
    func_name: str = data.get("function", "")
    addr: str = data.get("address", "")
    steps: list[str] = []
    if func_name:
        steps.append(f"Call `get-call-graph function={func_name} mode=graph` to see who calls this and what it calls.")
    if addr:
        steps.append(f'Call `manage-comments address={addr} mode=set comment="..."` to annotate your findings.')
        steps.append(f"Call `get-references address={addr}` to find all cross-references to/from this function.")
    steps.append("If the function calls suspicious subroutines, use `get-function` on those next.")
    steps.append("Use `annotate-function mode=rename` to give this function a meaningful name if auto-named.")
    return steps


def _next_steps_list_functions(data: dict[str, Any]) -> list[str]:
    # Prefer get-function and get-current-program; decompile-function is legacy and regression
    # often reintroduces it in suggested next steps — do not suggest get-function here.
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_list_functions")
    total: int = data.get("total", data.get("count", 0))
    results: list[dict[str, Any]] = data.get("results", [])
    steps: list[str] = []
    if results:
        first: dict[str, Any] = results[0]
        name: str = first.get("name", "")
        if name:
            steps.append(f"Call `get-function` with `functionIdentifier={name}` to read the pseudocode of a specific function.")
            steps.append(f"Call `get-call-graph` with `function={name}` and `mode=graph` for caller/callee metadata.")
    if total > len(results):
        steps.append(f"Use `offset` and `limit` with `list-functions` to paginate through all {total} functions.")
    steps.append("Use `namePattern` with `list-functions` to filter (e.g. `^sub_` for unnamed, `^_` for C++ internals).")
    steps.append("Call `get-current-program` for a quick symbol/function count overview without listing.")
    return steps


def _next_steps_get_functions(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_get_functions")
    view: str = data.get("view", "info")
    name: str = data.get("name", "")
    addr: str = data.get("address", "")
    steps: list[str] = []
    if view == "info":
        steps.append(f"Call `get-function function={name}` to get c pseudocode, disassembly, call graph, and other details.")
    elif view == "calls":
        callers: list[dict[str, Any]] = data.get("callers", [])
        callees: list[dict[str, Any]] = data.get("callees", [])
        if callees:
            steps.append(f"Decompile/disassemble/inspect called functions: try `get-function functionIdentifier={callees[0].get('name', '')}`.")
        if callers:
            steps.append(f"Trace callers: try `get-function functionIdentifier={callers[0].get('name', '')}`.")
    elif view == "decompile":
        steps.append(f"Call `manage-comments address={addr} mode=set` to annotate your analysis.")
    elif view == "disassemble":
        steps.append("Look for interesting patterns: `CALL`, `JMP` targets, or unusual `MOV` operands.")
        steps.append(f"Call `get-function function={name}` for a higher-level C view of this assembly, disassembly, call graph, and other details.")
    return steps


def _next_steps_symbols(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_symbols")
    mode: str = data.get("mode", "symbols")
    results: list[dict[str, Any]] = data.get("results", [])
    steps: list[str] = []
    if mode in ("symbols", "search"):
        if results:
            first_name: str = results[0].get("name", "")
            first_addr: str = results[0].get("address", "")
            if first_name:
                steps.append(f"Decompile a symbol: `get-function function={first_name}`.")
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
            steps.append(f"Decompile an export: `get-function function={results[0].get('name', '')}`.")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_search_everything")
    results: list[dict[str, Any]] = data.get("results", [])
    steps: list[str] = []
    if results:
        first: dict[str, Any] = results[0]
        rt: str = first.get("resultType", "")
        next_tools: list[dict[str, Any]] = first.get("nextTools", [])
        suggested_tool_names: set[str] = {str(nt.get("tool", "")) for nt in next_tools}
        if next_tools:
            nt: dict[str, Any]
            for nt in next_tools[:2]:
                tool: str = nt.get("tool", "")
                args_str: str = " ".join(f"{k}={v}" for k, v in nt.get("args", {}).items())
                steps.append(f"Follow up: `{tool} {args_str}`")
        if not next_tools:
            if rt == "function":
                steps.append(f"Decompile: `get-function function={first.get('name', first.get('function', ''))}`.")
            elif rt in ("symbol", "export", "import"):
                steps.append(f"Cross-refs: `get-references address={first.get('address', '')}`.")
        class_like_results: list[dict[str, Any]] = [row for row in results if str(row.get("resultType", "")) in {"class", "namespace"}]
        addressful_results: list[dict[str, Any]] = [
            row for row in results if str(row.get("functionAddress") or row.get("address") or "")
        ]
        if class_like_results:
            steps.append(
                "If `get-functions` or `analyze-vtables` surfaces relevant methods, open the most interesting caller/callee with `get-function addressOrSymbol=<address_or_name>` for full context."
            )
        elif addressful_results:
            focus_address: str = str(addressful_results[0].get("functionAddress") or addressful_results[0].get("address") or "")
            if focus_address and Tool.ANALYZE_DATA_FLOW.value not in suggested_tool_names:
                steps.append(f"Trace the surrounding state with `analyze-data-flow addressOrSymbol={focus_address}` if this hit looks central to the behavior you are following.")
            steps.append(
                "After `get-function`, drill into any relevant caller/callee it reveals with `get-function addressOrSymbol=<address_or_name>`."
            )
        steps.append('Narrow results with `scopes` param (e.g. `scopes=["functions","strings"]`).')
        return steps
    steps.append('Narrow results with `scopes` param (e.g. `scopes=["functions","strings"]`).')
    steps.append("Try `searchMode=regex` for pattern matching or `searchMode=fuzzy` for approximate matches.")
    return steps


def _next_steps_memory(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_memory")
    mode: str = data.get("mode", "blocks")
    steps: list[str] = []
    if mode == "blocks":
        blocks: list[dict[str, Any]] = data.get("blocks", [])
        exec_block: dict[str, Any] | None = next((b for b in blocks if "x" in str(b.get("permissions", ""))), None)
        rodata_block: dict[str, Any] | None = next(
            (
                b
                for b in blocks
                if any(token in str(b.get("name", "")).lower() for token in ("rdata", "rodata", "cstring", "const", "literal"))
                or (str(b.get("permissions", "")) == "r--" and bool(b.get("initialized", True)))
            ),
            None,
        )
        writable_block: dict[str, Any] | None = next(
            (b for b in blocks if "w" in str(b.get("permissions", "")) and bool(b.get("initialized", True))),
            None,
        )
        if exec_block:
            steps.append(f"Sample the executable region first: `inspect-memory mode=read addressOrSymbol={exec_block['start']} length=64` to confirm code bytes before pivoting into `list-functions` or `get-function`.")
        if rodata_block and rodata_block != exec_block:
            steps.append(f"Probe the likely string/constant region: `inspect-memory mode=read addressOrSymbol={rodata_block['start']} length=128` and follow any printable data with `search-strings`.")
        if writable_block:
            steps.append("Review typed globals next with `inspect-memory mode=data_items`; writable initialized blocks usually hold state, tables, and struct instances worth naming early.")
        steps.append("Best practice: prioritize executable blocks, then read-only strings/constants, then writable globals. Ignore uninitialized regions until code or xrefs force you there.")
    elif mode == "read":
        addr: str = data.get("address", "")
        ascii_token = _extract_searchable_ascii_token(str(data.get("ascii", "") or ""))
        steps.append(f"Ask Ghidra for the typed view of these bytes: `get-data addressOrSymbol={addr}`.")
        if ascii_token:
            steps.append(f"Search for the same literal elsewhere with `search-strings query={ascii_token}` to find sibling tables, format strings, or nearby state names.")
        steps.append(f"If this looks like a pointer table or embedded structure, follow up with `inspect-memory mode=data_at addressOrSymbol={addr}` and then pivot to `get-function` for code targets or `get-data` for data targets.")
    elif mode == "data_at":
        addr = str(data.get("address", "") or "")
        data_type = str(data.get("dataType", "") or "")
        value = str(data.get("value", "") or "")
        note = str(data.get("note", "") or "")
        if note:
            steps.append(f"No typed data is defined here yet. Inspect raw bytes with `get-data addressOrSymbol={addr}` before you commit to a type.")
            steps.append("If the bytes resolve into a table, string, or struct field layout, apply a type with `apply-data-type` or model the aggregate in `manage-structures`.")
            return steps
        steps.append(f"Find the code and data that reference this location: `get-references address={addr}`.")
        if data_type and _looks_like_pointer_type(data_type) and value and _is_address_like(value):
            steps.append(f"Follow the pointed-to target with `get-data addressOrSymbol={value}`; if it resolves to code, switch to `get-function addressOrSymbol={value}`.")
        steps.append("If the current type is too coarse, refine it with `apply-data-type` or define a struct in `manage-structures` before revisiting the decompiler.")
    elif mode == "data_items":
        items: list[dict[str, Any]] = data.get("results", [])
        if items:
            first_addr = str(items[0].get("address", "") or "")
            if first_addr:
                steps.append(f"Inspect one concrete item in depth with `get-data addressOrSymbol={first_addr}`.")
                steps.append(f"Trace who uses that global or table with `get-references address={first_addr}`.")
        steps.append("Prioritize larger or named items first; they usually anchor struct recovery, string tables, and persistent global state.")
        steps.append("Retype noisy byte arrays with `apply-data-type`, and graduate recurring layouts into `manage-structures` once you see repeated field patterns.")
    return steps


def _next_steps_callgraph(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_callgraph")
    mode: str = data.get("mode", "graph")
    func_name: str = data.get("function", data.get("functionName", ""))
    steps: list[str] = []
    if mode == "overview":
        functions: list[dict[str, Any]] = data.get("functions", [])
        entry_points = [row for row in functions if bool(row.get("isEntryPoint"))]
        hubs = sorted(functions, key=lambda row: int(row.get("callerCount", 0)), reverse=True)
        if entry_points:
            entry_target = _prefer_function_target(entry_points[0])
            steps.append(f"Start from a root path, not a utility hub: `get-call-graph function={entry_target} mode=tree` to walk from an entry-point into real behavior.")
        if hubs:
            hub_target = _prefer_function_target(hubs[0])
            steps.append(f"Use the hottest hub as a router map, then inspect it with `get-function addressOrSymbol={hub_target}` to decide which branch is worth following.")
        steps.append("Best practice: use entry points to orient architecture, then descend into callees until you hit leaf functions that actually transform data or enforce logic.")
    elif mode in ("graph", "tree"):
        callees: list[dict[str, Any]] = data.get("callees", [])
        callers: list[dict[str, Any]] = data.get("callers", [])
        if callees:
            callee_target = _prefer_function_target(callees[0])
            steps.append(f"Walk downward into behavior next with `get-function addressOrSymbol={callee_target}`; direct callees usually beat wrappers for understanding intent.")
        if callers:
            caller_target = _prefer_function_target(callers[0])
            steps.append(f"Walk upward to recover purpose and reachability with `get-function addressOrSymbol={caller_target}`.")
        steps.append("Best practice: use the caller side to learn how execution reaches this code, and the callee side to find where the real work or state mutation happens.")
    elif mode == "callers":
        callers = data.get("callers", data.get("commonCallers", []))
        second_function = str(data.get("secondFunction", "") or "")
        if callers:
            caller_target = _prefer_function_target(callers[0])
            steps.append(f"Open the nearest caller in full context with `get-function addressOrSymbol={caller_target}`.")
        elif func_name:
            steps.append(f"No callers usually means a root entry, callback target, or dead code. Switch direction with `get-call-graph function={func_name} mode=callees` to see what it can reach.")
        if second_function:
            steps.append("Common callers are high-value orchestration sites; inspect one shared caller first before chasing the two target functions separately.")
        elif func_name:
            steps.append(f"Once you identify the important parent, widen the view with `get-call-graph function={func_name} mode=graph`.")
    elif mode == "callees":
        callees = data.get("callees", [])
        if callees:
            callee_target = _prefer_function_target(callees[0])
            steps.append(f"Inspect the first downstream target with `get-function addressOrSymbol={callee_target}` and keep descending until you hit a leaf or stateful helper.")
            steps.append("Best practice: prefer callees that touch strings, globals, or external APIs over thin wrappers with dozens of pass-through calls.")
        elif func_name:
            steps.append(f"No callees means this is likely a leaf. Open it directly with `get-function addressOrSymbol={func_name}` and inspect constants, strings, and data accesses inside the body.")
    if func_name and mode != "overview":
        steps.append('Once the path is clear, leave a short note with `manage-comments address=<addr> mode=set comment="call path verified"` so the traversal decision persists.')
    return steps


def _next_steps_comments(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_comments")
    action: str = data.get("action", data.get("mode", ""))
    steps: list[str] = []
    if action == "set":
        addr: str = data.get("address", "")
        comment_type: str = str(data.get("type", "") or "eol")
        steps.append("Verify the note in full context before adding more prose; comments are most useful when they capture a proven fact, not a guess.")
        if addr:
            steps.append(f"Open the containing function with `get-function addressOrSymbol={addr}` to confirm the comment still matches the code path, data use, and nearby labels.")
        if comment_type == "eol":
            steps.append(f"If this insight should survive every xref, promote it to a `repeatable` comment or add a durable marker with `manage-bookmarks addressOrSymbol={addr} mode=set`.")
        elif comment_type == "plate":
            steps.append("Plate comments are best for stable function summaries. Once the purpose is clear, follow up by naming the function or tagging it so the summary is backed by structure, not text alone.")
        else:
            steps.append("Use pre/post comments for local reasoning and reserve repeatable comments for facts that should travel with the address across references.")
    elif action == "get":
        addr = data.get("address", "")
        comments: dict[str, str] = data.get("comments", {})
        if comments:
            steps.append(f"Re-open the surrounding function with `get-function addressOrSymbol={addr}` before editing; make sure the note still matches the latest analysis state.")
            if "repeatable" in comments:
                steps.append("Repeatable comments usually mark durable facts about data or APIs. If the fact is settled, consider adding a bookmark or better symbol/type so the meaning is encoded structurally too.")
        else:
            steps.append("No comments are present here yet. Add one only if you have a concrete finding worth preserving across sessions.")
        steps.append(f'To modify: `manage-comments address={addr} mode=set type=eol comment="new text"`.')
        steps.append(f"To remove: `manage-comments address={addr} mode=remove type=eol`.")
    elif action == "remove":
        addr = str(data.get("address", "") or "")
        if addr:
            steps.append(f"Verify the cleanup with `manage-comments address={addr} mode=get` so you do not leave stale reasoning behind.")
            steps.append(f"If the removed note captured a still-valid finding, preserve it structurally with `manage-bookmarks addressOrSymbol={addr} mode=set` or a better symbol/type instead of deleting the knowledge outright.")
    elif action == "search":
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            first_addr = str(results[0].get("address", "") or "")
            first_type = str(results[0].get("type", "") or "")
            steps.append(f"Resume from the first annotated site with `get-function addressOrSymbol={first_addr}` and verify whether the comment still reflects current understanding.")
            if first_type:
                steps.append(f"Use the comment type (`{first_type}`) to judge scope: repeatable comments usually capture reusable facts, while eol/pre/post comments often need nearby-code review before reuse.")
        steps.append("Best practice: comment search is a resume tool. Use it to reopen prior conclusions, then convert stable insights into names, types, tags, or bookmarks where possible.")
    elif action == "search_decomp":
        results = data.get("results", [])
        if results:
            first_func = str(results[0].get("function", "") or "")
            first_addr = str(results[0].get("address", "") or "")
            steps.append(f"Open the matched function in full context with `get-function addressOrSymbol={first_addr or first_func}` instead of relying on the snippet alone.")
        steps.append("Decompiler comment search is best for reconnecting themes across functions. After opening a hit, leave a precise address-level comment only where the code actually justifies it.")
    return steps


def _next_steps_bookmarks(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_bookmarks")
    action: str = data.get("action", data.get("mode", ""))
    if not action and data.get("categories"):
        action = "categories"
    steps: list[str] = []
    if action in ("set", "add_batch"):
        addr = str(data.get("address", "") or "")
        bm_type = str(data.get("type", "") or "")
        category = str(data.get("category", "") or "")
        if addr:
            steps.append(f"Re-open the bookmarked location with `get-function addressOrSymbol={addr}` before you add more markers; each bookmark should correspond to a real next investigation step.")
        if category:
            steps.append(f"Keep the triage queue coherent by grouping similar findings under `category={category}` so you can reopen a whole analysis thread later.")
        if bm_type in {"TODO", "Analysis", "Warning", "Bug"}:
            steps.append("Use bookmark types to represent work state, not prose. Once the issue is understood, convert the bookmark into a better name, type, tag, or precise comment.")
        else:
            steps.append("Bookmarks persist across sessions; use them as a lightweight work queue, then promote durable conclusions into comments, symbols, tags, or data types.")
    elif action == "remove":
        addr = str(data.get("address", "") or "")
        if addr:
            steps.append(f"Verify cleanup with `manage-bookmarks addressOrSymbol={addr} mode=get` so stale queue items do not survive your review.")
            steps.append(f"If the bookmark marked a still-relevant fact, preserve it structurally with `manage-comments address={addr} mode=set` or a better symbol/type before dropping the marker.")
        else:
            steps.append("Verify cleanup with `manage-bookmarks mode=get` so stale queue items do not survive your review.")
    elif action == "remove_all":
        steps.append("Clear-all is a reset operation. Recreate only the bookmarks that still map to active analysis threads, not everything you used during exploration.")
    elif action in ("get", "search"):
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            first_addr: str = results[0].get("address", "")
            first_category: str = str(results[0].get("category", "") or "")
            first_type: str = str(results[0].get("type", "") or "")
            steps.append(f"Resume from the first queued site with `get-function addressOrSymbol={first_addr}` so you recover call context, nearby comments, and data use in one step.")
            steps.append(f"Pull any existing notes before acting with `manage-comments address={first_addr} mode=get`.")
            if first_category:
                steps.append(f"Use the category (`{first_category}`) as a workstream boundary; finish one bookmark cluster before jumping to unrelated findings.")
            if first_type:
                steps.append(f"Let the bookmark type (`{first_type}`) drive priority: Warning/Bug should be resolved or disproved first, while Note/Analysis can wait behind execution-critical paths.")
        steps.append("Filter bookmark queues with `query`, `type`, or `category` so you review one subsystem or question at a time instead of reopening random addresses.")
    elif action == "categories":
        categories: list[str] = data.get("categories", [])
        if categories:
            steps.append(f"Open one bookmark lane at a time with `manage-bookmarks mode=get category={categories[0]}`.")
        steps.append("Treat categories as analysis workstreams such as loader, UI, network, or save/load. If categories are noisy, consolidate them before adding more bookmarks.")
    return steps


def _next_steps_structures(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_structures")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_constants")
    mode: str = data.get("mode", "")
    results: list[dict[str, Any]] = data.get("results", [])
    steps: list[str] = []
    if results:
        first = results[0]
        first_addr: str = str(first.get("address", "") or "")
        first_func: str = str(first.get("function", "") or "")
        first_value = first.get("value")
        if first_addr:
            steps.append(f"Open the first hit in full context with `get-function addressOrSymbol={first_addr}` before deciding whether this constant is a flag, size, sentinel, or table index.")
        if first_func:
            steps.append(f"Use `get-call-graph function={first_func} mode=graph` to see whether this constant sits in a leaf implementation, a dispatcher, or a shared utility wrapper.")
        if mode == "specific" and first_value is not None:
            steps.append(f"Compare all uses of `{first_value}` before renaming anything; the same literal can be reused as a syscall number, loop bound, or protocol marker in different functions.")
        elif mode == "range":
            steps.append("Range hits are best treated as candidate families. Split them into pointer-like values, sizes, and bitmasks before chasing every occurrence individually.")
    if mode == "common":
        steps.append("Common-constant scans are triage tools. Separate obvious buffer sizes and API flags from true magic values before you infer an algorithm from one familiar number.")
    if not results:
        if mode == "specific":
            steps.append("No exact hit found. Broaden slightly with a small range if you suspect sign extension, masking, or nearby sentinel values in the same code path.")
        elif mode == "range":
            steps.append("No range hits found. Revisit the bounds; many binaries mix decimal sizes, page-aligned values, and sign-extended immediates that fall just outside a guessed window.")
        elif mode == "common":
            steps.append("No obvious common constants surfaced. Pivot to strings, imports, or a known literal from the protocol/format you are chasing, then come back with `mode=specific`.")
    steps.append("After confirming a constant's role, encode the finding structurally: rename the function, add a precise comment, or tag the routine instead of relying on the number alone.")
    return steps


def _next_steps_dataflow(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_dataflow")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_datatypes")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_vtable")
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
                steps.append(f"Decompile/disassemble/inspect virtual method: `get-function function={first_target}`.")
        steps.append("Each vtable entry is a function pointer — decompile targets to understand the class interface.")
    elif mode == "callers":
        steps.append("Vtable callers show where virtual dispatch happens — these are polymorphic call sites.")
        results: list[dict[str, Any]] = data.get("results", [])
        if results:
            steps.append(f"Decompile/disassemble/inspect call site: `get-function function={results[0].get('fromAddress', '')}`.")
    return steps


def _strings_no_results_suggestions(query: str) -> list[str]:
    """Build context-aware next-step suggestions when a string search returns no results."""
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_strings_no_results_suggestions")
    steps: list[str] = []
    q = (query or "").strip()
    # Partial / shorter query: try first word or first token (e.g. "patching complete" -> "patching")
    if q:
        tokens = [t for t in re.split(r"\s+", q) if len(t) > 1]
        if len(tokens) > 1:
            partial = tokens[0]
            steps.append(f'Try a shorter or partial query: `search-strings query={partial}` (e.g. first word of "{q}").')
        elif len(q) > 6:
            # Single long word: suggest substring
            steps.append(f"Try a shorter substring: `search-strings query={q[: min(8, len(q))]}` to see if the string is split or abbreviated.")
    # Related terms for status/completion messages (patcher, installer, UI feedback)
    status_like = [
        ("complete", ["done", "success", "finished", "ok", "ready"]),
        ("patching", ["patch", "patched", "install", "update"]),
        ("success", ["complete", "done", "finished", "ok"]),
        ("error", ["fail", "failed", "warning", "invalid"]),
        ("done", ["complete", "success", "finished"]),
    ]
    q_lower = q.lower()
    for keyword, related in status_like:
        if keyword in q_lower:
            for r in related[:2]:  # at most 2 related suggestions
                steps.append(f"Try a related term: `search-strings query={r}`.")
            break
    # Broader discovery
    steps.append("Use `list-strings` to see what strings exist in the binary (they may be worded differently or encoded).")
    steps.append("Use `search-code query=<your term>` to find the phrase in decompiled function names or code, in case it is built at runtime.")
    steps.append("If the binary is packed or obfuscated, strings may be decoded at runtime or stored in non-default encodings (e.g. UTF-16); consider running the program and tracing, or try `search-strings` with a regex pattern.")
    return steps


def _next_steps_strings(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_strings")
    mode: str = data.get("mode", "")
    results: list[dict[str, Any]] = data.get("results", [])
    query: str = (data.get("query") or data.get("pattern") or "").strip()
    steps: list[str] = []
    if mode == "count":
        steps.append("Use `list-strings` to see actual string values.")
    elif results:
        first: dict[str, Any] = results[0]
        addr = first.get("address", "")
        if addr:
            steps.append(f"Decompile/disassemble/inspect containing function: `get-function function={addr}`.")
        steps.append("Try other keywords with `search-strings query=<word>`, or use `list-strings` to browse all strings.")
    else:
        # No results: context-aware suggestions when the user ran a search with a query
        if query:
            steps.extend(_strings_no_results_suggestions(query))
        else:
            steps.append("Use `list-strings` to see what strings exist; use a smaller minLength if the binary has few or short strings.")
            steps.append("If you expected a specific phrase, try `search-strings query=<keyword>` or `search-code query=<keyword>` (code search finds names and decompiled text).")
    return steps


def _next_steps_import_export(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_import_export")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_project")
    action = data.get("action", data.get("operation", ""))
    loaded = data.get("loaded")
    steps: list[str] = []
    if action == Tool.OPEN.value:
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
            steps.append(f"Open a project/repository entry: `open path={files[0].get('path', files[0].get('name', ''))}`.")
            steps.append("If the target is a local binary outside a project, use `import-binary path=<binary>` instead.")
    return steps


def _next_steps_search_code(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_search_code")
    results = data.get("results", [])
    steps: list[str] = []
    if results:
        first: dict[str, Any] = results[0]
        func_name = first.get("function", "")
        if func_name:
            steps.append(f"Decompile/disassemble/inspect matching function: `get-function function={func_name}`.")
    steps.append("Use `searchMode=regex` for pattern matching, or `searchMode=literal` for exact text.")
    return steps


def _next_steps_data(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_data")
    steps: list[str] = []
    if "definedType" in data:
        steps.append("Use `apply-data-type` to change the interpretation if the type is wrong.")
    if data.get("hex"):
        steps.append("Examine surrounding bytes with `inspect-memory mode=read` at nearby addresses.")
    if data.get("success"):
        steps.append("Type applied. Decompile nearby functions to see the effect on variable types.")
    return steps


def _next_steps_suggestions(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_suggestions")
    return [
        "The suggest tool provides AI-suggested names/types — review and apply with `rename-function` or `set-function-prototype`.",
        "Use `manage-comments` to document your naming decisions.",
    ]


def _next_steps_match_function(data: dict[str, Any]) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_next_steps_match_function")
    steps: list[str] = []
    error: str = data.get("error", "")
    mode: str = data.get("mode", "")

    results: list[dict[str, Any]] = data.get("results", [])
    if mode == "cross-program-bulk":
        summary = data.get("summary") or {}
        steps.append(f"Bulk run processed {summary.get('processed', 0)} functions; see resultsByFunction and summary.matchesPerTarget.")
        steps.append("Each result entry may include functionDetails (get-function output) for the matched target function.")
        return steps

    # If function not found, suggest searching first
    if "not found" in error.lower() or "not exist" in error.lower():
        steps.append("The function wasn't found. Use `search-everything` or `list-functions` to locate it, then retry `match-function` with the correct functionIdentifier or address.")
    # Cross-program success: suggest verifying matches and propagating further
    elif mode == "cross-program" and results:
        steps.append("Use `decompile-function` with `programPath` set to each target and `functionIdentifier` set to the matched function to compare implementations.")
        steps.append("To propagate more annotations, re-run `match-function` with `propagateNames`, `propagateTags`, `propagateComments`, `propagatePrototype`, or `propagateBookmarks` set to true.")
        steps.append("Use `manage-function-tags` on matched functions to group them by subsystem or purpose.")
    # Single-program successful matches
    elif results:
        steps.append("Use `decompile-function` on matched function names to compare implementations in detail.")
        steps.append("Tag matched functions with `manage-function-tags` to group them by library or purpose.")
    # Generic case
    else:
        steps.append("For cross-program matching: call `match-function` with `functionIdentifier`, `programPath` (source), and `targetProgramPaths` (one or more target binaries).")
        steps.append("Use `search-everything` or `list-functions` to find the function to match if needed.")
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
        "Executes arbitrary Python/Jython code in the Ghidra scripting environment with full API access. Use for custom analysis, batch operations, or anything not covered by dedicated tools. See [Ghidra API Javadoc](https://ghidra.re/ghidra_docs/api/index.html) and [FlatProgramAPI](https://ghidra.re/ghidra_docs/api/ghidra/program/flatapi/FlatProgramAPI.html) for available methods and classes.",
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
    "open": (
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
            "After renaming, use `get-function function=<function_name>` to verify the new name appears correctly.",
            "Use `manage-comments` to document why you renamed/retyped.",
        ],
    ),
}


# ---------------------------------------------------------------------------
# Per-tool custom renderers
# ---------------------------------------------------------------------------
# Each _render_* function takes the tool's JSON response dict and returns a single
# markdown string. Used when format != "json" so the client sees readable output
# instead of raw JSON. Tools without a custom renderer fall back to _render_generic.


def _render_execute_script(data: dict[str, Any]) -> str:
    """Render execute-script response: status, combined stdout/stderr, and return value as code blocks."""
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_execute_script")
    lines: list[str] = []
    lines.append(_md_heading(2, "Script Execution Result"))
    lines.append("")

    success = data.get("success", True)
    lines.append(_md_bold_kv("Status", "Success" if success else "Error"))

    stdout_text = str(data.get("stdout", ""))
    stderr_text = str(data.get("stderr", ""))
    result_text = str(data.get("result", ""))
    executed_program = data.get("executedProgram")

    if isinstance(executed_program, dict):
        executed_name = str(executed_program.get("name", ""))
        executed_path = str(executed_program.get("path", ""))
        if executed_name:
            lines.append(_md_bold_kv("Executed Program", _md_code_inline(executed_name)))
        if executed_path and executed_path != executed_name:
            lines.append(_md_bold_kv("Program Path", _md_code_inline(executed_path)))

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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_decompile")
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

    code = str(data.get("decompilation") or data.get("code") or "")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_list_functions")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_get_functions")
    view = data.get("view", "info")
    if view == "decompile":
        return _render_decompile(data)
    if view == "disassemble":
        return _render_disassemble(data)
    if view == "calls":
        return _render_function_calls(data)
    return _render_function_info(data)


def _render_function_info(data: dict[str, Any]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_function_info")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_function_calls")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_disassemble")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_symbols")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_search_everything")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_memory")
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
            rows: list[list[str]] = [  # pyright: ignore[reportRedeclaration]
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
    return _render_generic(data, Tool.INSPECT_MEMORY.value)


def _render_callgraph(data: dict[str, Any]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_callgraph")
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
        callers: list[dict[str, Any]] = data.get("callers", [])  # pyright: ignore[reportRedeclaration]
        callees: list[dict[str, Any]] = data.get("callees", [])  # pyright: ignore[reportRedeclaration]

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

    return _render_generic(data, Tool.GET_CALL_GRAPH.value)


def _render_comments(data: dict[str, Any]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_comments")
    action = data.get("action", data.get("mode", ""))
    lines: list[str] = []

    if action == "set":
        lines.append(_md_heading(2, "Comment Set"))
        lines.append("")
        if data.get("batch"):
            results: list[dict[str, Any]] = data.get("results", [])  # pyright: ignore[reportRedeclaration]
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_bookmarks")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_structures")
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
            rows = [
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_constants")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_dataflow")
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_strings")
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
        # Include get-references style output for each string that has referencesTo
        for r in results:
            refs_to: list[dict[str, Any]] = r.get("referencesTo") or []
            if not refs_to:
                continue
            addr = r.get("address", "")
            lines.append("")
            lines.append(_md_heading(4, f"References to {addr}"))
            lines.append("")
            ref_headers: list[str] = ["From", "Type", "Function"]
            ref_rows: list[list[str]] = [
                [
                    ref.get("fromAddress", ""),
                    ref.get("type", ""),
                    ref.get("function") or "",
                ]
                for ref in refs_to
            ]
            lines.append(_md_table(ref_headers, ref_rows))
    else:
        lines.append("*No strings found.*")

    return "\n".join(lines)


def _render_datatypes(data: dict[str, Any]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_datatypes")
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
            results = data.get("results", [])
            for r in results:
                status = "OK" if r.get("success") else f"FAIL: {r.get('error', '')}"
                lines.append(f"- `{r.get('address', '')}`: {status}")
        else:
            lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
            lines.append(_md_bold_kv("Type", _md_code_inline(data.get("dataType", ""))))
        return "\n".join(lines)

    return _render_generic(data, "manage-data-types")


def _render_vtable(data: dict[str, Any]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_vtable")
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
            rows = [[r.get("fromAddress", ""), r.get("function", ""), r.get("refType", "")] for r in results]
            lines.append(_md_table(headers, rows))
        return "\n".join(lines)

    return _render_generic(data, "analyze-vtables")


def _render_import_export(data: dict[str, Any]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_import_export")
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
                src = p.get("sourcePath") or p.get("path", "")
                lines.append(f"- `{p.get('programName', '')}` from `{src}`")
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


def _append_program_detail_lines(lines: list[str], detail: dict[str, Any]) -> None:
    """Append markdown lines for a single program's enriched detail dict."""
    fc = detail.get("functionCount")
    if fc is not None:
        lines.append(_md_bold_kv("Functions", fc))
    lang = detail.get("languageId")
    if lang:
        lines.append(_md_bold_kv("Language", lang))
    cs = detail.get("compilerSpec")
    if cs:
        lines.append(_md_bold_kv("Compiler Spec", cs))
    ic = detail.get("instructionCount")
    if ic is not None:
        lines.append(_md_bold_kv("Instructions", ic))
    bc = detail.get("bookmarkCount")
    if bc is not None:
        lines.append(_md_bold_kv("Bookmarks", bc))
    bbt = detail.get("bookmarksByType")
    if bbt:
        parts = [f"{t}: {c}" for t, c in bbt.items()]
        lines.append(_md_bold_kv("Bookmark Types", ", ".join(parts)))
    tags = detail.get("functionTags")
    if tags:
        tag_strs = [f"{t['name']} ({t['useCount']})" for t in tags if isinstance(t, dict)]
        if tag_strs:
            lines.append(_md_bold_kv("Function Tags", ", ".join(tag_strs)))
    meta = detail.get("metadata")
    if isinstance(meta, dict):
        for mk, mv in meta.items():
            lines.append(_md_bold_kv(mk, mv))
    ver = detail.get("versioning")
    if isinstance(ver, dict):
        lines.append("")
        lines.append("**Versioning:**")
        if ver.get("isVersioned"):
            lines.append(_md_bold_kv("  Versioned", "Yes"))
            lines.append(_md_bold_kv("  Version", f"{ver.get('currentVersion', '?')}/{ver.get('latestVersion', '?')}"))
        else:
            lines.append(_md_bold_kv("  Versioned", "No (local only)"))
        if ver.get("isCheckedOut"):
            lines.append(_md_bold_kv("  Checked Out", "Yes (exclusive)" if ver.get("isCheckedOutExclusive") else "Yes"))
            co_user = ver.get("checkoutUser")
            if co_user:
                lines.append(_md_bold_kv("  Checkout User", co_user))
            if ver.get("modifiedSinceCheckout"):
                lines.append(_md_bold_kv("  Modified Since Checkout", "Yes"))
        lm = ver.get("lastModified")
        if lm:
            lines.append(_md_bold_kv("  Last Modified", lm))
        fs = ver.get("fileSize")
        if fs is not None:
            lines.append(_md_bold_kv("  File Size", f"{fs:,} bytes"))


def _render_project(data: dict[str, Any]) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_project")
    action = data.get("action", data.get("operation", ""))
    loaded = data.get("loaded")
    lines: list[str] = []

    if action == "import":
        # Import result from open-project path — render as a rich import summary
        lines.append(_md_heading(2, "Project Opened (Import)"))
        lines.append("")
        imported_from = data.get("importedFrom", "")
        if imported_from:
            lines.append(_md_bold_kv("Source", _md_code_inline(imported_from)))
        lines.append(_md_bold_kv("Files Discovered", data.get("filesDiscovered", 0)))
        lines.append(_md_bold_kv("Files Imported", data.get("filesImported", 0)))
        lines.append(_md_bold_kv("Analysis", "Requested" if data.get("analysisRequested") else "Skipped"))
        errors = data.get("errors", [])
        if errors:
            lines.append("")
            lines.append(_md_heading(3, "Import Errors"))
            for e in errors:
                if isinstance(e, dict):
                    lines.append(f"- `{e.get('path', '')}`: {e.get('error', '')}")
                else:
                    lines.append(f"- {e}")
        imported_programs: list[dict[str, Any]] = data.get("importedPrograms", [])
        if imported_programs:
            lines.append("")
            lines.append(_md_heading(3, f"Imported Programs ({len(imported_programs)})"))
            lines.append("")
            headers_imp = ["Program Name", "Source"]
            rows_imp = [[p.get("programName", ""), p.get("sourcePath") or p.get("path", "")] for p in imported_programs]
            lines.append(_md_table(headers_imp, rows_imp))
        program_details: list[dict[str, Any]] = data.get("programDetails", [])
        if program_details:
            lines.append("")
            lines.append(_md_heading(3, "Program Details"))
            for detail in program_details:
                detail_name = detail.get("name", detail.get("programPath", ""))
                lines.append("")
                lines.append(_md_heading(4, detail_name or "Program"))
                _append_program_detail_lines(lines, detail)
                funcs: list[dict[str, Any]] = detail.get("topFunctions", [])
                if funcs:
                    lines.append("")
                    lines.append(_md_bold_kv("Top Functions", ""))
                    f_headers = ["Address", "Name", "Signature"]
                    f_rows = [[f.get("address", ""), f.get("name", ""), f.get("signature", "")] for f in funcs]
                    lines.append(_md_table(f_headers, f_rows))
        project_files: list[dict[str, Any]] = data.get("projectFiles", [])
        if project_files:
            lines.append("")
            lines.append(_md_heading(3, f"Project Files ({len(project_files)})"))
            lines.append("")
            pf_headers = ["Name", "Path", "Size"]
            pf_rows = [[f.get("name", ""), f.get("path", ""), str(f.get("size", ""))] for f in project_files]
            lines.append(_md_table(pf_headers, pf_rows))
        return "\n".join(lines)

    if action == Tool.OPEN.value:
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

        # --- Enriched per-program details ---
        program_details: list[dict[str, Any]] = data.get("programDetails", [])
        if program_details:
            lines.append("")
            lines.append(_md_heading(3, "Program Details"))
            for detail in program_details:
                name = detail.get("name", detail.get("programPath", ""))
                is_active = detail.get("isActive", False)
                label = f"{name} (active)" if is_active else name
                lines.append("")
                lines.append(_md_heading(4, label))
                _append_program_detail_lines(lines, detail)

        # --- Shared-server checked-out program details ---
        co_detail = data.get("checkedOutProgramDetails")
        if isinstance(co_detail, dict) and co_detail:
            lines.append("")
            lines.append(_md_heading(3, "Checked-Out Program Details"))
            _append_program_detail_lines(lines, co_detail)

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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_suggestions")
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
    """Render get-data or apply-data-type response: address, type, value, optional hex/ascii dump."""
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_data")
    lines: list[str] = []
    if data.get("success") is not None and "address" in data and "dataType" in data:
        # apply-data-type success: address + type applied
        lines.append(_md_heading(2, "Data Type Applied"))
        lines.append("")
        lines.append(_md_bold_kv("Address", _md_code_inline(data.get("address", ""))))
        lines.append(_md_bold_kv("Type", _md_code_inline(data.get("dataType", ""))))
        return "\n".join(lines)

    # get-data response: address, optional type/value/length, optional raw bytes block
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
# Conflict renderer (two-step modification conflicts)
# ---------------------------------------------------------------------------


def _render_conflict(data: dict[str, Any]) -> str:
    """Render a modification-conflict response as markdown.

    Shows conflictSummary (udiff-style), nextStep (how to resolve), and conflictId/tool.
    """
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_conflict")
    lines: list[str] = []
    lines.append(_md_heading(2, "Modification conflict"))
    lines.append("")
    summary = data.get("conflictSummary", "")
    if summary:
        lines.append(summary)
        lines.append("")
    next_step = data.get("nextStep", "")
    if next_step:
        lines.append(_md_heading(3, "Next step"))
        lines.append("")
        lines.append(next_step)
        lines.append("")
    conflict_id = data.get("conflictId", "")
    tool = data.get("tool", "")
    if conflict_id or tool:
        lines.append(_md_bold_kv("conflictId", _md_code_inline(conflict_id)))
        if tool:
            lines.append(_md_bold_kv("Tool", _md_code_inline(tool)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Error renderer
# ---------------------------------------------------------------------------


def _render_error(data: dict[str, Any]) -> str:
    """Render an error response as readable markdown.

    Shows error message, optional state/tool, then any context keys (connection, auth,
    server reachable, etc.) and a 'How to Fix' list from nextSteps when present.
    """
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_error")
    lines: list[str] = []
    lines.append(_md_heading(2, "Error"))
    lines.append("")
    lines.append(f"> **{data.get('error', 'Unknown error')}**")
    lines.append("")

    context: dict[str, Any] = data.get("context", {})
    state: str = data.get("state", context.get("state", ""))
    if state:
        lines.append(_md_bold_kv("State", _md_code_inline(state)))

    tool: str = data.get("tool", context.get("tool", ""))
    if tool:
        lines.append(_md_bold_kv("Tool", _md_code_inline(tool)))

    detail_keys: list[tuple[str, str]] = [
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

    next_steps: list[str] = data.get("nextSteps", [])
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


def _render_function_detail_block(data: dict[str, Any], *, heading_level: int = 2) -> str:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_function_detail_block")
    lines: list[str] = []
    name: str = data.get("name", "unknown")
    addr: str = data.get("address", "")
    sig: str = data.get("signature", "")
    relationship: str = data.get("relationship", "")

    title = f"Function: `{name}`"
    if relationship:
        title = f"{title} ({relationship})"
    lines.append(_md_heading(heading_level, title))
    lines.append("")
    lines.append(_md_bold_kv("Address", _md_code_inline(addr)))
    lines.append(_md_bold_kv("Signature", _md_code_inline(sig)))
    lines.append("")

    meta: dict[str, Any] = data.get("metadata") or {}
    if meta:
        lines.append(_md_bold_kv("Size", f"{meta.get('size', 0)} bytes"))
        lines.append(_md_bold_kv("Return type", _md_code_inline(meta.get("returnType", ""))))
        lines.append(_md_bold_kv("Calling convention", meta.get("callingConvention", "") or "unknown"))
        flags: list[str] = []
        if meta.get("isExternal"):
            flags.append("External")
        if meta.get("isThunk"):
            flags.append("Thunk")
        if meta.get("hasVarArgs"):
            flags.append("VarArgs")
        if flags:
            lines.append(_md_bold_kv("Flags", ", ".join(flags)))
        params: list[dict[str, Any]] = meta.get("parameters") or []
        if params:
            lines.append("")
            lines.append(_md_heading(4, "Parameters"))
            rows: list[list[str]] = [[str(p.get("ordinal", i)), p.get("name", ""), _truncate(str(p.get("type", "")), 50)] for i, p in enumerate(params)]
            lines.append(_md_table(["#", "Name", "Type"], rows))
        lines.append("")

    ns: dict[str, Any] = data.get("namespace") or {}
    if ns and (ns.get("path") or ns.get("segments")):
        path_str = ns.get("path", "::".join(ns.get("segments") or []))
        if path_str and str(path_str).strip("()").lower() not in ("global", ""):
            lines.append(_md_heading(3, "Namespace"))
            lines.append("")
            lines.append(_md_code_inline(str(path_str)))
            lines.append("")

    decomp = data.get("decompilation", "") or data.get("code", "")
    if isinstance(decomp, str) and decomp.strip():
        lines.append(_md_heading(3, "Decompilation"))
        lines.append("")
        lines.append(_md_code_block(decomp.rstrip(), "c"))
        lines.append("")

    disasm: dict[str, Any] = data.get("disassembly") or {}
    instructions: list[dict[str, Any]] = disasm.get("instructions") or []
    if instructions and not _decompilation_text_embeds_disassembly(str(decomp)):
        lines.append(_md_heading(3, "Disassembly"))
        lines.append("")
        count = disasm.get("count", len(instructions))
        truncated = disasm.get("truncated", False)
        count_label = f"{count} shown (more exist)" if truncated else str(count)
        lines.append(_md_bold_kv("Instructions", count_label))
        lines.append("")
        asm_rows: list[list[str]] = []
        for instr in instructions:
            a = instr.get("address", "")
            b = instr.get("bytes", "")
            mnem = instr.get("mnemonic", "")
            full_op = instr.get("operands", "")
            ops_only = full_op[len(mnem):].lstrip() if full_op.startswith(mnem) else full_op
            asm_rows.append([a, b, mnem, ops_only])
        lines.append(_md_table(["Address", "Bytes", "Mnemonic", "Operands"], asm_rows))
        lines.append("")

    data_flow: dict[str, Any] = data.get("dataFlow") or {}
    if data_flow:
        direction = str(data_flow.get("direction", ""))
        lines.append(_md_heading(3, f"Data flow ({direction or 'requested'})"))
        lines.append("")
        lines.append(_md_bold_kv("Seed address", _md_code_inline(str(data_flow.get("address", "")))))
        if data_flow.get("seedCount") is not None:
            lines.append(_md_bold_kv("Seed ops", str(data_flow.get("seedCount", 0))))
        if data_flow.get("analysisDepth") is not None:
            lines.append(_md_bold_kv("Depth", str(data_flow.get("analysisDepth", 0))))
        note = data_flow.get("note") or data_flow.get("error")
        if direction == "variable_accesses":
            variables: list[dict[str, Any]] = data_flow.get("variables") or []
            if variables:
                rows = [[v.get("name", ""), v.get("dataType", ""), v.get("storage", ""), str(v.get("size", ""))] for v in variables[:25]]
                lines.append(_md_table(["Name", "Type", "Storage", "Size"], rows))
                if len(variables) > 25:
                    lines.append(f"*... and {len(variables) - 25} more*")
            elif note:
                lines.append(f"*{note}*")
            else:
                lines.append("*No variable access information available.*")
        else:
            pcode: list[dict[str, Any]] = data_flow.get("pcode") or []
            if pcode:
                rows = [
                    [
                        op.get("address", ""),
                        op.get("mnemonic", ""),
                        op.get("output", "") or "",
                        ", ".join(op.get("inputs", [])) if isinstance(op.get("inputs"), list) else str(op.get("inputs", "")),
                    ]
                    for op in pcode[:30]
                ]
                lines.append(_md_table(["Address", "Mnemonic", "Output", "Inputs"], rows))
                if len(pcode) > 30:
                    lines.append(f"*... and {len(pcode) - 30} more*")
            elif note:
                lines.append(f"*{note}*")
            else:
                lines.append("*No P-code slice available for the requested address.*")
        lines.append("")

    callers: list[dict[str, Any]] = data.get("callers") or []
    callees: list[dict[str, Any]] = data.get("callees") or []
    lines.append(_md_heading(3, "Call graph"))
    lines.append("")
    lines.append(_md_heading(4, f"Callers ({len(callers)})"))
    if callers:
        rows = [[c.get("name", ""), c.get("address", "")] for c in callers]
        lines.append(_md_table(["Name", "Address"], rows))
    else:
        lines.append("*None*")
    lines.append("")
    lines.append(_md_heading(4, f"Callees ({len(callees)})"))
    if callees:
        rows = [[c.get("name", ""), c.get("address", "")] for c in callees]
        lines.append(_md_table(["Name", "Address"], rows))
    else:
        lines.append("*None*")
    lines.append("")

    comments: dict[str, Any] = data.get("comments") or {}
    entry_comments: dict[str, str] = comments.get("entryPoint") or {}
    if entry_comments:
        lines.append(_md_heading(3, "Entry-point comments"))
        lines.append("")
        for ctype, text in entry_comments.items():
            if text:
                lines.append(f"- **{ctype}:** {_truncate(str(text), 120)}")
        lines.append("")
    inline: list[dict[str, Any]] = (comments.get("inline") or [])[:20]
    if inline:
        lines.append(_md_heading(3, "Comments (inline sample)"))
        lines.append("")
        for c in inline:
            lines.append(f"- `{c.get('address', '')}` [{c.get('type', '')}]: {_truncate(str(c.get('text', '')), 80)}")
        if (comments.get("inlineCount") or 0) > 20:
            lines.append(f"- *... and {comments.get('inlineCount', 0) - 20} more*")
        lines.append("")

    labels: list[dict[str, Any]] = data.get("labels") or []
    # Suppress if the only label is the function's own entry point (redundant with the header)
    trivial = len(labels) == 1 and labels[0].get("name") == name and labels[0].get("address") == addr
    if labels and not trivial:
        lines.append(_md_heading(3, "Labels"))
        lines.append("")
        rows = [[lb.get("name", ""), lb.get("address", ""), lb.get("type", "")] for lb in labels[:30]]
        lines.append(_md_table(["Name", "Address", "Type"], rows))
        if len(labels) > 30:
            lines.append(f"*... and {len(labels) - 30} more*")
        lines.append("")

    xrefs: list[dict[str, Any]] = data.get("crossReferences") or []
    outbound: list[dict[str, Any]] = data.get("outboundReferences") or []
    outbound_filtered = [x for x in outbound if not str(x.get("toAddress", "")).startswith("Stack[")]
    lines.append(_md_heading(3, "Cross-references (inbound)"))
    lines.append("")
    if xrefs:
        rows = [[x.get("fromAddress", ""), x.get("toAddress", ""), x.get("type", "")] for x in xrefs[:25]]
        lines.append(_md_table(["From", "To", "Type"], rows))
        if len(xrefs) > 25:
            lines.append(f"*... and {len(xrefs) - 25} more*")
    else:
        lines.append("*None*")
    lines.append("")
    if outbound_filtered:
        lines.append(_md_heading(3, "Outbound references"))
        lines.append("")
        rows = [[x.get("fromAddress", ""), x.get("toAddress", ""), x.get("type", "")] for x in outbound_filtered[:15]]
        lines.append(_md_table(["From", "To", "Type"], rows))
        if len(outbound_filtered) > 15:
            lines.append(f"*... and {len(outbound_filtered) - 15} more*")
        lines.append("")

    tags_list: list[Any] = data.get("tags") or []
    bookmarks_list: list[dict[str, Any]] = data.get("bookmarks") or []
    if tags_list or bookmarks_list:
        lines.append(_md_heading(3, "Tags & bookmarks"))
        lines.append("")
        if tags_list:
            lines.append(_md_bold_kv("Tags", ", ".join(str(t) for t in tags_list)))
        if bookmarks_list:
            lines.append(_md_bold_kv("Bookmarks", str(len(bookmarks_list))))
            rows = [[b.get("address", ""), b.get("type", ""), b.get("category", ""), _truncate(str(b.get("comment", "")), 40)] for b in bookmarks_list[:20]]
            lines.append(_md_table(["Address", "Type", "Category", "Comment"], rows))
            if len(bookmarks_list) > 20:
                lines.append(f"*... and {len(bookmarks_list) - 20} more*")
        lines.append("")

    stack: dict[str, Any] = data.get("stackFrame") or {}
    vars_list: list[dict[str, Any]] = stack.get("variables") or []
    if vars_list:
        lines.append(_md_heading(3, "Stack frame"))
        lines.append("")
        lines.append(_md_bold_kv("Frame size", f"{stack.get('frameSize', 0)} bytes"))
        has_params = any(v.get("isParameter") for v in vars_list[:25])
        if has_params:
            rows = [[v.get("name", ""), str(v.get("offset", "")), v.get("dataType", ""), "✓" if v.get("isParameter") else ""] for v in vars_list[:25]]
            lines.append(_md_table(["Name", "Offset", "Type", "Param"], rows))
        else:
            rows = [[v.get("name", ""), str(v.get("offset", "")), v.get("dataType", "")] for v in vars_list[:25]]
            lines.append(_md_table(["Name", "Offset", "Type"], rows))
        if len(vars_list) > 25:
            lines.append(f"*... and {len(vars_list) - 25} more*")
        lines.append("")

    mem: dict[str, Any] = data.get("memoryBlock") or {}
    if mem and mem.get("name"):
        lines.append(_md_heading(3, "Memory block"))
        lines.append("")
        lines.append(_md_bold_kv("Name", mem.get("name", "")))
        lines.append(_md_bold_kv("Range", f"{mem.get('start', '')} – {mem.get('end', '')}"))
        lines.append(_md_bold_kv("Size", f"{mem.get('size', 0)} bytes"))
        lines.append(_md_bold_kv("Permissions", str(mem.get("permissions", ""))))

    return "\n".join(lines)


def _render_call_tree(nodes: list[dict[str, Any]], *, indent: int = 0) -> list[str]:
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_call_tree")
    lines: list[str] = []
    for node in nodes:
        prefix = "  " * indent + "- "
        lines.append(f"{prefix}`{node.get('name', '')}` ({node.get('address', '')})")
        children = node.get("children") or []
        if children:
            lines.extend(_render_call_tree(children, indent=indent + 1))
    return lines


def _render_get_function(data: dict[str, Any]) -> str:
    """Render get-function (dissect) response as markdown. Avoids raw JSON when format=markdown."""
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_get_function")
    if data.get("found") is False:
        return _render_generic(data, "get-function")

    target: dict[str, Any] = data.get("targetFunction") or data
    lines: list[str] = [_render_function_detail_block(target)]

    call_graph_tree: dict[str, Any] = data.get("callGraphTree") or {}
    caller_tree: list[dict[str, Any]] = call_graph_tree.get("callers") or []
    callee_tree: list[dict[str, Any]] = call_graph_tree.get("callees") or []
    if caller_tree or callee_tree:
        lines.append("")
        lines.append(_md_heading(2, "Expanded Call Graph"))
        lines.append("")
        lines.append(
            _md_bold_kv(
                "Traversal",
                (
                    f"callers depth {call_graph_tree.get('callerDepth', 0)} breadth {call_graph_tree.get('callerBranching', 0)}, "
                    f"callees depth {call_graph_tree.get('calleeDepth', 0)} breadth {call_graph_tree.get('calleeBranching', 0)}"
                ),
            ),
        )
        lines.append(_md_bold_kv("Expanded caller details", call_graph_tree.get("expandedCallerCount", 0)))
        lines.append(_md_bold_kv("Expanded callee details", call_graph_tree.get("expandedCalleeCount", 0)))
        lines.append("")
        lines.append(_md_heading(3, "Caller Tree"))
        lines.append("")
        if caller_tree:
            lines.extend(_render_call_tree(caller_tree))
        else:
            lines.append("*None*")
        lines.append("")
        lines.append(_md_heading(3, "Callee Tree"))
        lines.append("")
        if callee_tree:
            lines.extend(_render_call_tree(callee_tree))
        else:
            lines.append("*None*")

    caller_details: list[dict[str, Any]] = data.get("callerDetails") or []
    if caller_details:
        lines.append("")
        lines.append(_md_heading(2, f"Expanded Caller Details ({len(caller_details)})"))
        for detail in caller_details:
            lines.append("")
            lines.append(_render_function_detail_block(detail, heading_level=3))

    callee_details: list[dict[str, Any]] = data.get("calleeDetails") or []
    if callee_details:
        lines.append("")
        lines.append(_md_heading(2, f"Expanded Callee Details ({len(callee_details)})"))
        for detail in callee_details:
            lines.append("")
            lines.append(_render_function_detail_block(detail, heading_level=3))

    return "\n".join(lines)


def _render_generic(data: dict[str, Any], tool_name: str = "") -> str:
    """Smart generic renderer for tools without a custom renderer.

    Detects: (1) pagination envelope (results + total/hasMore) → table + footer;
    (2) single key-value payload → bold key: value; (3) nested lists/dicts → subheadings
    and tables. Title comes from mode/action or normalized tool name.
    """
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:_render_generic")
    lines: list[str] = []

    # Title from mode/action or tool name so the user knows which tool produced this
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
                    rows = [[_truncate(str(item.get(h, "")), 60) for h in headers] for item in cast("list[dict[str, Any]]", value)]
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

# Per-tool markdown renderers: when format=markdown, the intercept uses this map to turn
# JSON tool output into readable markdown. Tools not listed use _render_generic (table + key blocks).
TOOL_RENDERERS: dict[str, Callable[[dict[str, Any]], str]] = {
    "executescript": _render_execute_script,
    "decompile": _render_decompile,
    "decompilefunction": _render_decompile,
    "listfunctions": _render_list_functions,
    "getfunction": _render_get_function,
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
    "open": _render_project,
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
    logger.debug("diag.enter %s", "mcp_server/response_formatter.py:render_tool_response")
    logger.debug("render_tool_response tool=%s", normalized_tool_name)
    # Modification conflicts get their own renderer (udiff + nextStep)
    if data.get("modificationConflict") is True or (data.get("success") is False and data.get("conflictId")):
        body = _render_conflict(data)
    elif data.get("success") is False:
        body = _render_error(data)
    else:
        # Look up per-tool renderer (key = normalize_identifier(tool_name)); missing or exception → generic table + key blocks
        renderer = TOOL_RENDERERS.get(normalized_tool_name)
        if renderer is not None:
            try:
                body = renderer(data)
            except Exception as exc:
                logger.warning(
                    "tool_markdown_render_fallback normalized_tool=%s exc_type=%s payload_keys=%s",
                    normalized_tool_name,
                    type(exc).__name__,
                    norm_arg_keys(data),
                )
                body = _render_generic(data, normalized_tool_name)
        else:
            body = _render_generic(data, normalized_tool_name)

    # When we have guidance for this tool, append "About This Tool" and "Suggested Next Steps"
    # (filtered so we don't recommend tools disabled via env)
    guidance: tuple[str, Callable[[dict[str, Any]], list[str]]] | None = TOOL_GUIDANCE.get(normalized_tool_name)
    lines: list[str] = [body]

    # --- Render project context block if present ---
    project_ctx: dict[str, Any] | None = data.get("projectContext") if isinstance(data, dict) else None
    if project_ctx:
        lines.append("")
        lines.append(_md_heading(3, "Project Context"))
        ctx_parts: list[str] = []
        pname = project_ctx.get("projectName")
        if pname:
            ctx_parts.append(f"**{pname}**")
        pmode = project_ctx.get("mode", "")
        if pmode:
            ctx_parts.append(pmode)
        active = project_ctx.get("activeProgram")
        if active:
            ctx_parts.append(f"active: `{active}`")
        pc = project_ctx.get("programCount")
        if pc is not None:
            ctx_parts.append(f"{pc} program{'s' if pc != 1 else ''}")
        ppath = project_ctx.get("projectPath")
        if ppath:
            ctx_parts.append(f"`{ppath}`")
        sh = project_ctx.get("serverHost")
        if sh:
            sp = project_ctx.get("serverPort", "")
            repo = project_ctx.get("repository", "")
            ctx_parts.append(f"shared: {sh}:{sp}/{repo}")
        if ctx_parts:
            lines.append(" | ".join(ctx_parts))

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
