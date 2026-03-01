# AgentDecompile – Copilot/Claude Instructions

## Planning and Documentation Diagram Policy

- Every new or updated planning/design document must include at least one Mermaid diagram.
- The diagram should appear near the top (after objective/scope) and provide a high-level flow.
- Keep diagrams synchronized with the written steps when plans evolve.
- Prefer simple `flowchart TD` diagrams for execution plans and phase sequencing.
- If a document has multiple phases/modules, include one top-level diagram plus optional focused diagrams.

## What is AgentDecompile?

AgentDecompile provides a comprehensive Model Context Protocol (MCP) server that allows AI clients to interact with Ghidra/PyGhidra for reverse engineering. It surfaces **49 tools** across 6 functional domains:

1. **Symbol management** – `manage-symbols`, `search-symbols-by-name`
2. **Function analysis** – `list-functions`, `manage-function`, `get-functions`, `match-function`
3. **Memory & data** – `inspect-memory`, `manage-strings`, `manage-data-types`, `manage-structures`
4. **Control flow** – `get-call-graph`, `get-references`, `analyze-data-flow`, `analyze-vtables`
5. **Annotations** – `manage-comments`, `manage-bookmarks`, `manage-function-tags`
6. **Project management** – `open`, `list-project-files`, `manage-files`, `import-binary`, `export`

Full specification: [TOOLS_LIST.md](../TOOLS_LIST.md)

## Python Implementation

**Location:** `src/agentdecompile_cli/`

- `mcp_server/tool_providers.py` – `ToolProvider` base class + `ToolProviderManager` (centralized normalization, dispatch, error handling)
- `mcp_server/providers/*.py` – Tool implementations (19 files, one per domain)
- `mcp_server/server.py` – MCP server (FastAPI + MCP SDK wiring)
- `mcp_utils/*.py` – Shared utilities (address resolution, symbol lookup, etc.)
- `tools/wrappers.py` – `GhidraTools` wrapper class (comprehensive Ghidra API access)
- `registry.py` – Tool registry, `normalize_identifier()`, canonical tool list
- `models.py` – Response data structures

### Normalization Contract (CRITICAL)

**Absolute Rule: all tool and argument routing MUST go through the unified normalization pipeline.**

This project intentionally accepts messy client input so humans and agents can use intuitive names without memorizing exact punctuation or casing. We do this to maximize compatibility across MCP clients, CLI usage styles, legacy vendor naming, and ad-hoc agent output. If the alphabetic characters match, we treat it as the same intent. This avoids brittle UX and prevents accidental "unknown tool/arg" failures caused only by separators or case.

**Intent hierarchy (in order):**
1. Accept user intent if alphabetic core matches.
2. Preserve one canonical implementation path.
3. Reject only when no normalized canonical/alias match exists.

**Advertisement Layer (External-Facing)**:
- **CLI commands/options**: advertise canonical names in `snake_case` (example: `manage_symbols`, `program_path`).
- **MCP tool schemas**: advertise canonical names in `snake_case`.
- **Docs/examples**: may show kebab/snake/camel forms, but canonical display should remain `snake_case`.

**Execution Layer (Internal Matching, NON-NEGOTIABLE)**:
- **Tool names**: accept any case and any symbols/separators.
- **Argument names**: accept any case and any symbols/separators.
- **Matching rule**: alphabetic-only, case-insensitive equivalence.
- **Canonical normalizer**: `normalize_identifier(s) = re.sub(r"[^a-z]", "", s.lower().strip())`.
- **Interpretation**: strip EVERYTHING except letters, lowercase, then compare.

**Single Pipeline Flow (REQUIRED):**
1. Resolve tool name via `registry.resolve_tool_name()`.
2. Normalize tool/argument keys via `tool_providers.n` (alias of `registry.normalize_identifier`).
3. Apply `TOOL_PARAM_ALIASES` using normalized keys only.
4. Dispatch through `ToolProviderManager.call_tool()` and provider `ToolProvider.call_tool()`.
5. Read arguments inside handlers via `_get/_get_str/_get_int/_get_bool/_require*` only.

**Enforcement Scope (must follow contract):**
- `registry.py` (canonical normalizer + alias/resolve tables)
- `mcp_server/tool_providers.py` (authoritative dispatch + arg normalization)
- `mcp_server/providers/*.py` (handlers only; no custom dispatch/normalization)
- `mcp_server/server.py` (must keep `validate_input=False` and delegate to unified manager)
- `bridge.py` / transport adapters (must resolve forwarded tool names via registry resolver; no ad-hoc rewrites)

**Examples (all MUST resolve identically)**:
- Tool name examples: `manage-symbols`, `Manage_Symbols`, `MANAGESYMBOLS`, `@@manage symbols@@`, `manage symbols!!!` → `managesymbols`.
- Parameter examples: `programPath`, `program_path`, `PROGRAM PATH`, `__program-path__`, `program.path`, `program/path`, `program:path` → `programpath`.

**Implementation Rules (MANDATORY)**:
1. **Single normalization function**: use `registry.normalize_identifier()` everywhere (aliased as `n()` in `tool_providers.py`).
2. **Single dispatch pipeline**: all tool calls must route through unified provider dispatch (`ToolProviderManager.call_tool` / provider `call_tool`), never ad-hoc name matching.
3. **No bypass matching**: do not add alternate exact-match logic, manual case branches, or punctuation-specific routing.
4. **Normalize before any comparison**: never compare raw tool/arg names.
5. **Alias bridging after normalization**: apply `TOOL_PARAM_ALIASES` only on normalized keys.
6. **User-intent first**: if alphabetic core matches a known tool/arg, accept it.

**Forbidden Patterns (DO NOT ADD):**
- Local `operation_aliases` / per-provider alias dictionaries for tool/action normalization.
- Direct imports of `normalize_identifier` inside provider methods.
- Provider-level `call_tool()` overrides that re-implement dispatch/arg normalization.
- Tool-name rewriting via punctuation transforms (example: manual `replace("-", "_")`) instead of resolver.
- Raw string comparisons on unnormalized tool/arg names.

**Provider Authoring Standard:**
- `HANDLERS` keys must be normalized canonical names only.
- Normalize mode/action values with `n(...)` only when comparing semantic mode/action input.
- Use argument helpers (`_get*`, `_require*`) and never manually parse key style variants.
- If new synonyms are needed, add them to `TOOLS_LIST.md` and rely on generated alias maps.

**Change Checklist (must pass before merge):**
- No provider contains custom tool/argument dispatch normalization.
- No `from agentdecompile_cli.registry import normalize_identifier` inside `providers/*.py` methods.
- Bridge/server forwarding uses resolver path, not ad-hoc conversion logic.
- `tests/test_normalization_combinatorial.py` passes.
- Affected provider tests pass.

### Parameter Overload / Mix-Match Rule (CRITICAL)

**Absolute Rule: parameters are interchangeable across all tool names, including aliases.**

Many tools share a common alias target (e.g. `search-symbols-by-name` → `manage-symbols`, `list-imports` → `manage-symbols`). When a tool name resolves to another via `NON_ADVERTISED_TOOL_ALIASES`, **all parameters supplied by the caller MUST be preserved**, even if they are not in the resolved tool's advertised param set. This is a universal pattern that is always in effect implicitly.

**Why this matters:**
- `search-symbols-by-name` defines a `query` parameter.
- It resolves to `manage-symbols`, which does NOT advertise `query` in its own param set.
- If `parse_arguments()` only keeps params matching the resolved tool's schema, `query` is silently dropped → wrong results.
- The same applies to ANY parameter on ANY aliased/forwarded tool.

**Implementation (in `registry.py` `parse_arguments()`):**
After building `parsed_args` from the resolved tool's recognized params + aliases, passthrough ALL remaining caller-supplied argument keys whose normalized form is not already present:
```python
parsed_norms = {normalize_identifier(k) for k in parsed_args}
for key, value in arguments.items():
    if normalize_identifier(key) not in parsed_norms:
        parsed_args[key] = value
```

**Rules:**
1. `parse_arguments()` MUST passthrough unrecognized params — never silently drop them.
2. Tool handlers read params via `_get*` / `_require*` helpers which normalize keys, so passthrough params are automatically accessible.
3. This overload behavior does NOT affect how tools are advertised (schemas remain per-tool).
4. When adding new aliased tools, you do NOT need to duplicate params into the target tool's schema — passthrough handles it.

**Forbidden:**
- Filtering/dropping unknown params in `parse_arguments()`.
- Requiring every param to be declared in the resolved tool's param set.
- Adding duplicate param definitions to target tools just to satisfy parsing.

## Vendor Source Integration

Each tool merges compatible implementations from:
1. `vendor/pyghidra-mcp/` – Base tool implementations
2. `vendor/GhidraMCP/` – Additional symbols/xrefs API
3. `vendor/reverse-engineering-assistant/` – Project management patterns
4. `TOOLS_LIST.md` – Canonical specifications

Example: `manage-symbols` consolidates:
- pyghidra-mcp: `search_symbols_by_name()` → `mode='symbols'`
- GhidraMCP: `list_methods()`, `list_classes()` → `mode='classes'`, `mode='namespaces'`
- TOOLS_LIST: `demangle`, `imports`, `exports`, `rename_data`, `count`, `create_label`

All modes, all argument names, all response formats in one unified tool.

## How to Work on This

1. **Start with TOOLS_LIST.md** – Extract tool specification (modes, parameters, response shape)
2. **Review vendor sources** – Check pyghidra-mcp, GhidraMCP, etc. for working implementations
3. **Implement in Python** – `src/agentdecompile_cli/mcp_server/providers/DOMAIN_NAME.py`
4. **Extend `ToolProvider`** – Define `HANDLERS` dict, use `self._get()` helpers for normalized arg access
5. **Test** – Verify all modes, argument forms, error cases

For detailed architectural notes, see [src/CLAUDE.md](../src/CLAUDE.md).

ALWAYS keep [TOOLS_LIST.md](../TOOLS_LIST.md) as the source of truth for tool specifications and keep it up to date!

