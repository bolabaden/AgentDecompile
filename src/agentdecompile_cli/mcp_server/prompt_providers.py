"""MCP prompt providers for multi-subagent reverse engineering workflows.

Provides parameterized prompt templates that drive independent subagents to
converge on accurate findings from different analysis angles (top-down,
bottom-up, broad sweep, deep dive, etc.) without cross-communication.
"""

from __future__ import annotations

import logging

from typing import Any

from mcp import types

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prompt definitions
# ---------------------------------------------------------------------------
# Each prompt has: name (MCP identifier), title, description, and arguments.
# Used by list_prompts (MCP prompts/list) to advertise available workflow prompts.

_PROMPTS: list[dict[str, Any]] = [
    # 1. Scout – Broad Sweep
    {
        "name": "re-scout-broad-sweep",
        "title": "Scout: Broad Sweep Discovery",
        "description": ("A broad surface-level sweep of the binary to discover ALL symbols, strings, cross-references, and namespaces related to a target subsystem. This agent casts a wide net and prioritises coverage over depth."),
        "arguments": [
            {"name": "program_path", "description": "Path to the program in the Ghidra project (e.g. /K1/swkotor.exe)", "required": False},
            {"name": "analysis_target", "description": "Subsystem to investigate (e.g. 'save/load serialization', 'combat system', 'dialog engine')", "required": True},
            {"name": "search_keywords", "description": "Comma-separated keywords/patterns to search for in symbols and strings", "required": False},
        ],
        "messages": [
            {
                "role": "user",
                "text": (
                    'You are an aggressive reverse-engineering analyst nicknamed "Scout". '
                    "Your job is to do a BROAD SWEEP of the binary at `{program_path}` using "
                    "the AgentDecompile MCP tools.\n\n"
                    "Your mission: Find EVERYTHING related to **{analysis_target}**.\n\n"
                    "Execute these steps in order. For EACH step, make a separate tool call. "
                    "Return ALL results verbatim — do NOT summarise or truncate.\n\n"
                    "**Step 1: String Discovery**\n"
                    "Use `search-strings` or `execute-script` to search for ALL strings "
                    "containing relevant keywords{keyword_clause}. "
                    "Return every match with its address and full string value.\n\n"
                    "**Step 2: Symbol Discovery**\n"
                    "Use `list-functions` with a filter or `execute-script` to find all "
                    "symbols (functions, labels) matching relevant patterns. Record name, "
                    "address, namespace, and symbol type.\n\n"
                    "**Step 3: Cross-Reference Analysis**\n"
                    "For the top 20 most important symbols found in Step 2, use "
                    "`list-cross-references` or `execute-script` to get all cross-references "
                    "TO each function. Record caller addresses and reference types.\n\n"
                    "**Step 4: Namespace / Class Discovery**\n"
                    "Find all namespaces and classes related to the target subsystem. "
                    "Use `search-everything` with scopes including namespaces and classes, or "
                    "`execute-script` with the SymbolTable/namespace API. "
                    "List each namespace with its member functions and data labels.\n\n"
                    "## Output Format\n"
                    "Return a structured report:\n"
                    "```\n"
                    "## Scout Agent Report — {analysis_target}\n\n"
                    "### Step 1: String Discovery\n"
                    "[full results]\n\n"
                    "### Step 2: Symbol Discovery\n"
                    "[full results]\n\n"
                    "### Step 3: Cross-Reference Analysis\n"
                    "[full results]\n\n"
                    "### Step 4: Namespace/Class Discovery\n"
                    "[full results]\n"
                    "```\n\n"
                    "CRITICAL: Return ALL data verbatim. Do NOT summarise or truncate."
                ),
            },
        ],
    },
    # 2. Diver – Deep Dive Decompilation
    {
        "name": "re-diver-deep-dive",
        "title": "Diver: Deep Dive Decompilation",
        "description": ("Decompiles and extracts complete C/C++ source-equivalent code for ALL functions related to the target subsystem. Traces full call chains and extracts data structures."),
        "arguments": [
            {"name": "program_path", "description": "Path to the program in the Ghidra project", "required": False},
            {"name": "analysis_target", "description": "Subsystem to investigate", "required": True},
            {"name": "search_keywords", "description": "Comma-separated keywords/patterns", "required": False},
        ],
        "messages": [
            {
                "role": "user",
                "text": (
                    'You are a meticulous decompilation specialist nicknamed "Diver". '
                    "Your job is to do a DEEP DIVE into the binary at `{program_path}`.\n\n"
                    "Your mission: Decompile and extract the COMPLETE C/C++ source-equivalent "
                    "code for ALL functions related to **{analysis_target}**.\n\n"
                    "Execute these steps:\n\n"
                    "**Step 1: Identify all relevant functions**\n"
                    "Find all function symbols related to the target{keyword_clause}. "
                    "Record address, name, namespace, signature, and size. Sort by size descending.\n\n"
                    "**Step 2: Decompile the primary functions**\n"
                    "Take the top 15 largest/most important functions from Step 1 and decompile "
                    "ALL of them using `decompile-function` or `execute-script` with the "
                    "DecompInterface API.\n\n"
                    "**Step 3: Decompile remaining functions**\n"
                    "Continue decompiling ALL remaining functions from Step 1.\n\n"
                    "**Step 4: Trace call chains**\n"
                    "For the main entry points, trace the FULL call chain downward. "
                    "Use `get-call-graph` to obtain callers and callees; decompile any not yet covered.\n\n"
                    "**Step 5: Extract data structures**\n"
                    "Find and extract any structures/classes/types related to the subsystem "
                    "from the DataTypeManager.\n\n"
                    "## Output Format\n"
                    "```\n"
                    "## Diver Agent Report — {analysis_target}\n\n"
                    "### Step 1: Function Inventory\n"
                    "[full function list with addresses]\n\n"
                    "### Step 2: Primary Decompilation Batch\n"
                    "[full decompiled C code for each function]\n\n"
                    "### Step 3: Secondary Decompilation Batch\n"
                    "[full decompiled C code]\n\n"
                    "### Step 4: Call Chain Tracing\n"
                    "[call chain results]\n\n"
                    "### Step 5: Data Structure Extraction\n"
                    "[structure definitions]\n"
                    "```\n\n"
                    "CRITICAL: Return ALL decompiled C code in full. Never truncate."
                ),
            },
        ],
    },
    # 3. Bottom-Up Analyst
    {
        "name": "re-bottom-up-analyst",
        "title": "Bottom-Up Analyst: Primitives to Entry Points",
        "description": ("Starts from low-level I/O primitives and traces callers upward, decompiling the full chain from file operations to high-level entry points. Discovers patterns humans would miss."),
        "arguments": [
            {"name": "program_path", "description": "Path to the program in the Ghidra project", "required": False},
            {"name": "analysis_target", "description": "Subsystem to investigate", "required": True},
            {"name": "search_keywords", "description": "Comma-separated keywords/patterns", "required": False},
        ],
        "messages": [
            {
                "role": "user",
                "text": (
                    "You are a reverse engineering expert with a CREATIVE and EXPLORATORY "
                    "personality. You start from low-level primitives and work upward.\n\n"
                    "Your target binary is `{program_path}`. Your goal: Produce exhaustive "
                    "C/C++ reconstructed code for ALL logic related to **{analysis_target}** — "
                    "working BOTTOM-UP.\n\n"
                    "## Strategy (Bottom-Up)\n\n"
                    "### Phase 1: Find I/O and low-level primitives\n"
                    "Search for ALL imported functions related to file I/O (CreateFileA/W, "
                    "WriteFile, ReadFile, fopen, fwrite, fread), directory operations "
                    "(CreateDirectoryA/W, FindFirstFileA/W), memory operations (memcpy), "
                    "and any domain-specific class methods{keyword_clause}. "
                    "Get all cross-references TO these functions.\n\n"
                    "### Phase 2: Trace callers upward\n"
                    "For each low-level function, find ALL callers via cross-references. "
                    "Filter for those in the target subsystem path. Build the call tree UPWARD.\n\n"
                    "### Phase 3: Decompile the full chain\n"
                    "Decompile EVERY function in the call chain, from lowest-level I/O up "
                    "to the highest-level entry point.\n\n"
                    "### Phase 4: Focus on data structures\n"
                    "Identify all structures/classes used: what data gets serialised, "
                    "file formats, class layouts, vtable entries.\n\n"
                    "### Phase 5: Supporting operations\n"
                    "Find ALL code related to: directory/path construction, enumeration, "
                    "file naming conventions, validation, error handling.\n\n"
                    "## Output\n"
                    "Return a comprehensive report with:\n"
                    "1. Every tool call made with exact code/arguments and results\n"
                    "2. All I/O primitives discovered\n"
                    "3. Complete cross-reference chains from I/O up to entry points\n"
                    "4. All decompiled C code for every function in the chain (verbatim)\n"
                    "5. Data structure reconstructions\n"
                    "6. Your clean C/C++ reconstruction with structs and class hierarchies\n\n"
                    "Be EXHAUSTIVE. Do not summarise or skip functions."
                ),
            },
        ],
    },
    # 4. Top-Down Analyst
    {
        "name": "re-top-down-analyst",
        "title": "Top-Down Analyst: Entry Points to Primitives",
        "description": ("Starts from high-level entry points and drills down methodically through the call graph. Systematic and comprehensive."),
        "arguments": [
            {"name": "program_path", "description": "Path to the program in the Ghidra project", "required": False},
            {"name": "analysis_target", "description": "Subsystem to investigate", "required": True},
            {"name": "search_keywords", "description": "Comma-separated keywords/patterns", "required": False},
        ],
        "messages": [
            {
                "role": "user",
                "text": (
                    "You are a reverse engineering expert. Your personality is METHODICAL "
                    "and SYSTEMATIC — you start from high-level entry points and drill down.\n\n"
                    "Your target binary is `{program_path}`. Your goal: Produce exhaustive "
                    "C/C++ reconstructed code for ALL logic related to **{analysis_target}** — "
                    "working TOP-DOWN.\n\n"
                    "## Strategy (Top-Down)\n\n"
                    "### Phase 1: Discovery\n"
                    "Find ALL symbols and strings related to the target{keyword_clause}. "
                    "Do this in ONE comprehensive search that returns structured data.\n\n"
                    "### Phase 2: Decompile core entry points\n"
                    "Based on Phase 1, identify the TOP entry point functions. "
                    "Decompile them using the decompiler API.\n\n"
                    "### Phase 3: Trace the call graph downward\n"
                    "For each core function, get all called functions (callees). "
                    "Decompile those too. Continue recursively until you have covered the "
                    "full pipeline including: file open/create/close, container parsing/writing, "
                    "individual resource serialisation, read/write operations, error handling.\n\n"
                    "### Phase 4: Reconstruct C++ code\n"
                    "Based on all decompiled output, produce clean, readable C/C++ "
                    "reconstructions with class structures.\n\n"
                    "## Output\n"
                    "Return a comprehensive report with:\n"
                    "1. Every tool call made and results\n"
                    "2. All discovered symbols/strings\n"
                    "3. All decompiled C code for every function (verbatim)\n"
                    "4. Your C/C++ reconstruction — clean, commented, with class structures\n"
                    "5. Call graph — which functions call which\n"
                    "6. Patterns noticed — common idioms, error handling, class hierarchies\n\n"
                    "Be EXHAUSTIVE. Do not summarise or skip functions."
                ),
            },
        ],
    },
    # 5. Data Architect
    {
        "name": "re-data-architect",
        "title": "Data Architect: Structure & Type Reconstruction",
        "description": ("Translates reverse engineering findings into formal Ghidra data types: structures, enums, and type definitions. Validates against existing types and applies them to the binary."),
        "arguments": [
            {"name": "program_path", "description": "Path to the program in the Ghidra project", "required": False},
            {"name": "analysis_target", "description": "Subsystem to investigate", "required": True},
            {"name": "category_path", "description": "DataTypeManager category path for new types (e.g. /RE_Analysis/SaveLoad)", "required": False},
        ],
        "messages": [
            {
                "role": "user",
                "text": (
                    'You are the "Cautious Architect". Your focus is deeply integrating '
                    "structured data analysis into `{program_path}`.\n\n"
                    "Your objectives for **{analysis_target}**:\n"
                    "1. Translate C++ RE findings into formal Ghidra Data Types (structures, "
                    "enums, unions).\n"
                    "2. RESPECT existing structures. Before creating a structure, search the "
                    "DataTypeManager. If it exists, gracefully extend it. If not, create it.\n"
                    "3. Create an internal archive category "
                    "(`{category_path}`) in the Data Type Manager and organise your new structs "
                    "there.\n"
                    "4. Apply these data types to variables or function signatures where possible. "
                    "Use the `apply-data-type` tool for memory locations and `set-function-prototype` "
                    "for function signatures.\n"
                    "5. Document what you built, what existing data you preserved, and what "
                    "friction you encountered.\n\n"
                    "## Approach\n"
                    "- Use `execute-script` with Ghidra's DataTypeManager API\n"
                    "- For each class/struct, first search `dtm.getAllDataTypes()` for a match\n"
                    "- If found, extend description or add missing fields\n"
                    "- If not found, create via `StructureDataType(category, name, 0)` and add fields\n"
                    "- Use `PointerDataType`, `IntegerDataType`, `Undefined4DataType` as needed\n\n"
                    "## Output\n"
                    "Return a report detailing:\n"
                    "1. Every structure created or extended\n"
                    "2. Existing types preserved\n"
                    "3. Types applied to functions/variables\n"
                    "4. Friction points and tool improvement recommendations"
                ),
            },
        ],
    },
    # 6. Exhaustive Librarian – Annotation
    {
        "name": "re-exhaustive-librarian",
        "title": "Exhaustive Librarian: Binary Annotation",
        "description": ("Annotates the binary with function signatures, comments, tags, and bookmarks. Preserves existing annotations by appending rather than overwriting."),
        "arguments": [
            {"name": "program_path", "description": "Path to the program in the Ghidra project", "required": False},
            {"name": "analysis_target", "description": "Subsystem to annotate", "required": True},
            {"name": "bookmark_category", "description": "Bookmark category name (e.g. SaveLoadSystem)", "required": False},
        ],
        "messages": [
            {
                "role": "user",
                "text": (
                    'You are the "Exhaustive Librarian". Your focus is annotating the '
                    "binary `{program_path}` based on reverse engineering findings.\n\n"
                    "Your objectives for **{analysis_target}**:\n"
                    "1. Apply function signatures (parameters/return types)\n"
                    "2. Apply labels and comments (Pre, Post, EOL, Plate)\n"
                    "3. Add function tags and custom bookmark categories\n"
                    "4. IMPORTANT: RESPECT EXISTING COMMENTS AND TAGS. Always retrieve the "
                    "existing annotation first. If one exists, APPEND your new information. "
                    "Do NOT overwrite.\n"
                    "5. Establish custom bookmark categories (e.g. `{bookmark_category}`) and "
                    "bookmark the core functions\n\n"
                    "## Approach\n"
                    "- Use `set-function-prototype` to apply function signatures "
                    "(parameters and return type).\n"
                    "- Use `execute-script` with Ghidra's listing/bookmark/symbol APIs\n"
                    "- Use `manage-comments` for comment operations\n"
                    "- Use `manage-bookmarks` for bookmark operations\n"
                    "- Use `manage-function-tags` for tag operations\n"
                    "- For each function, check existing annotations before modifying\n\n"
                    "## Output\n"
                    "Return a report detailing:\n"
                    "1. Every function annotated with what was applied\n"
                    "2. Existing annotations preserved\n"
                    "3. Bookmark categories created\n"
                    "4. Friction points and tool improvement recommendations"
                ),
            },
        ],
    },
    # 7. Bridge Builder – Cross-Binary Parity
    {
        "name": "re-bridge-builder",
        "title": "Bridge Builder: Cross-Binary Parity",
        "description": (
            "Ports analysis from one binary to another (e.g. game v1 to v2, or "
            "different platform builds). Use match-function with targetProgramPaths for "
            "cross-program matching; matching uses signature, name, and call graph (caller/callee names), "
            "not byte-level comparison, so it works when assembly differs. Optionally propagate names, tags, "
            "comments, prototype, and bookmarks. Fallback: correlate by name/signature with list-functions/search-symbols and "
            "propagate via rename-function, set-function-prototype, manage-comments, manage-bookmarks, manage-function-tags."
        ),
        "arguments": [
            {"name": "source_program_path", "description": "Path to the already-analysed source binary", "required": False},
            {"name": "target_program_path", "description": "Path to the target binary to port analysis to", "required": False},
            {"name": "analysis_target", "description": "Subsystem to port", "required": True},
        ],
        "messages": [
            {
                "role": "user",
                "text": (
                    'You are the "Bridge Builder". Your goal is cross-binary parity.\n\n'
                    "Source (already analysed): `{source_program_path}`\n"
                    "Target (to port to): `{target_program_path}`\n"
                    "Subsystem: **{analysis_target}**\n\n"
                    "Your objectives:\n"
                    "1. Use `list-project-files` to verify both binaries are accessible.\n"
                    "2. Use `match-function` with `programPath` set to the source binary, "
                    "`functionIdentifier` (or `function`) set to the function to match, and "
                    "`targetProgramPaths` set to the target binary path(s). Matching uses signature, name, and call graph (no byte comparison). "
                    "Set `propagateNames`, `propagateTags`, `propagateComments`, `propagatePrototype`, and `propagateBookmarks` to true to port "
                    "names, tags, all comment types, prototype, and bookmarks. If a function is not found by match-function, correlate by name/signature "
                    "with `list-functions` or `search-symbols` (switching `programPath`) and propagate "
                    "via `rename-function`, `set-function-prototype`, `manage-comments`, `manage-bookmarks`, "
                    "`manage-function-tags` on the target.\n"
                    "3. Focus on the core routines already analysed in the source binary.\n\n"
                    "## Approach\n"
                    "- Prefer `match-function` with `targetProgramPaths=[target]` and "
                    "`propagateNames=true` (and `propagateTags`, `propagateComments`, `propagatePrototype`, `propagateBookmarks` as needed) to "
                    "find and annotate the same function in the target.\n"
                    "- List functions in the source related to the subsystem (`list-functions` or "
                    "`search-symbols` with `programPath` set to source). For any not matched by "
                    "match-function, use `list-functions` or `search-symbols` with `programPath` "
                    "set to target; correlate by name/signature, then apply annotations via "
                    "`rename-function`, `set-function-prototype`, `manage-comments`, `manage-bookmarks`, "
                    "`manage-function-tags`.\n"
                    "- Document any functions that could not be correlated or had low confidence.\n\n"
                    "## Output\n"
                    "Return a report on:\n"
                    "1. Both binaries verified and accessible\n"
                    "2. Total functions attempted vs successfully correlated and annotated\n"
                    "3. Annotations propagated for each correlated function\n"
                    "4. Functions that could not be correlated and possible reasons\n"
                    "5. Recommendations for improving cross-binary analysis"
                ),
            },
        ],
    },
    # 8. Convergence Orchestrator
    {
        "name": "re-convergence-orchestrator",
        "title": "Convergence Orchestrator: Multi-Subagent Verification",
        "description": ("Meta-prompt that orchestrates multiple independent subagents (Scout, Diver, Bottom-Up, Top-Down) to analyse the same subsystem from different angles. Subagents do NOT communicate — the orchestrator compares their outputs and identifies discrepancies until findings converge."),
        "arguments": [
            {"name": "program_path", "description": "Path to the program in the Ghidra project", "required": False},
            {"name": "analysis_target", "description": "Subsystem to investigate", "required": True},
            {"name": "search_keywords", "description": "Comma-separated keywords/patterns", "required": False},
            {"name": "max_iterations", "description": "Maximum convergence iterations (default: 3)", "required": False},
        ],
        "messages": [
            {
                "role": "user",
                "text": (
                    "You are the Convergence Orchestrator. Your job is to ensure accuracy "
                    "by running INDEPENDENT parallel analyses and comparing results.\n\n"
                    "Target: `{program_path}` — **{analysis_target}**\n\n"
                    "## Protocol\n\n"
                    "### Round 1: Independent Analysis\n"
                    "Run these analysis passes INDEPENDENTLY. Each pass must use ONLY the "
                    "AgentDecompile MCP tools and must NOT reference findings from other passes.\n\n"
                    "**Pass A — Top-Down**: Start from high-level entry points (symbols with "
                    "obvious names). Decompile them, trace callees downward, map the full "
                    "call graph.\n\n"
                    "**Pass B — Bottom-Up**: Start from low-level I/O primitives (imported "
                    "functions like CreateFileA, WriteFile, ReadFile). Trace callers upward "
                    "to find the entry points.\n\n"
                    "**Pass C — Broad Sweep**: Search ALL strings and symbols for relevant "
                    "keywords{keyword_clause}. Map namespaces and cross-references without "
                    "decompiling.\n\n"
                    "### Round 2: Compare & Identify Discrepancies\n"
                    "For each pass, extract:\n"
                    "- Function list (name + address)\n"
                    "- Call graph (who calls whom)\n"
                    "- Data structures found\n"
                    "- Entry points identified\n\n"
                    "Compare across all three passes. Flag any:\n"
                    "- Functions found by one pass but missed by others\n"
                    "- Disagreements on call relationships\n"
                    "- Conflicting data structure interpretations\n\n"
                    "### Round 3+: Resolve Discrepancies\n"
                    "For each discrepancy, run a TARGETED analysis to determine ground truth. "
                    "Decompile the disputed function, verify cross-references, confirm data "
                    "types. Repeat until all passes agree or {max_iterations} rounds complete.\n\n"
                    "### Final Output\n"
                    "Return:\n"
                    "1. **Unified Function List**: Every function confirmed by 2+ passes\n"
                    "2. **Verified Call Graph**: Call relationships confirmed by 2+ passes\n"
                    "3. **Confirmed Data Structures**: Types confirmed by 2+ passes\n"
                    "4. **Discrepancy Log**: What disagreed, how it was resolved\n"
                    "5. **Confidence Scores**: Per-function confidence (how many passes agreed)\n"
                    "6. **All decompiled C code** for confirmed functions\n\n"
                    "CRITICAL: Passes must be INDEPENDENT. Do not let Pass B's findings "
                    "influence Pass A's analysis. Run them as if they know nothing about "
                    "each other."
                ),
            },
        ],
    },
    # 9. Iterative Verifier
    {
        "name": "re-iterative-verifier",
        "title": "Iterative Verifier: Repeat Until Converged",
        "description": ("Takes existing analysis findings and independently re-verifies them by re-running tool calls, cross-checking addresses, and confirming decompiled output matches expectations. Keeps iterating until findings are stable across consecutive runs."),
        "arguments": [
            {"name": "program_path", "description": "Path to the program in the Ghidra project", "required": False},
            {"name": "analysis_target", "description": "Subsystem to verify", "required": True},
            {"name": "prior_function_list", "description": "Comma-separated list of function names or addresses from a prior analysis to verify", "required": True},
        ],
        "messages": [
            {
                "role": "user",
                "text": (
                    "You are the Iterative Verifier. Your job is to independently confirm "
                    "or refute findings from a prior analysis.\n\n"
                    "Target: `{program_path}` — **{analysis_target}**\n"
                    "Prior findings to verify: {prior_function_list}\n\n"
                    "## Protocol\n\n"
                    "### Iteration 1: Independent Verification\n"
                    "For each function/address in the prior findings:\n"
                    "1. Confirm the function exists at the stated address\n"
                    "2. Decompile it and compare with any prior decompilation\n"
                    "3. Verify cross-references match prior claims\n"
                    "4. Check if the function actually belongs to the stated subsystem\n\n"
                    "### Iteration 2: Discovery Check\n"
                    "Run your OWN independent search for functions related to the target. "
                    "Compare with the prior function list. Flag:\n"
                    "- Functions in prior list NOT found by your search (possible false positives)\n"
                    "- Functions found by your search NOT in prior list (possible misses)\n\n"
                    "### Iteration 3: Resolve\n"
                    "For every flagged discrepancy, do a targeted deep-dive to determine "
                    "ground truth.\n\n"
                    "## Output\n"
                    "1. **Confirmed findings**: Functions verified as correct\n"
                    "2. **Refuted findings**: Functions that don't match claims\n"
                    "3. **New discoveries**: Functions the prior analysis missed\n"
                    "4. **Stability assessment**: Are findings stable or still shifting?"
                ),
            },
        ],
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def list_prompts() -> list[types.Prompt]:
    """Return all available MCP prompts."""
    logger.debug("diag.enter %s", "mcp_server/prompt_providers.py:list_prompts")
    prompts: list[types.Prompt] = []
    for p in _PROMPTS:
        prompt_args = [
            types.PromptArgument(
                name=a["name"],
                description=a.get("description"),
                required=a.get("required", False),
            )
            for a in p.get("arguments", [])
        ]
        prompts.append(
            types.Prompt(
                name=p["name"],
                description=p.get("description"),
                arguments=prompt_args or None,
            ),
        )
    return prompts
