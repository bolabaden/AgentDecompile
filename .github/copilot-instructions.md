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

