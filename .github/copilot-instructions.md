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

**Advertisement Layer (External-Facing)**:
- **CLI commands/options**: Advertise in `snake_case` (`manage_symbols`, `program_path`)
- **MCP tool schemas**: Use `snake_case` (`manage_symbols`, `program_path`)
- **Important**: Normalize and flexibly handle variants like `managesymbols`, `manageSymbols`, `programPath`, etc. - all should work fully.

**Execution Layer (Internal Matching)**:
- **Tool name matching**: ALWAYS accepts ANY variant as long as alphabetic characters match (case-insensitive)
- **Argument name matching**: ALWAYS accepts ANY variant as long as alphabetic characters match (case-insensitive)
- **Normalization**: `normalize_identifier(s)` = `re.sub(r"[^a-z]", "", s.lower().strip())` (alpha-only lowercase)
- **Examples**:
  - Tool names: `manage-symbols`, `Manage_Symbols`, `MANAGESYMBOLS`, `@@manage symbols@@` → all resolve to `managesymbols` internally
  - Arguments: `programPath`, `program_path`, `PROGRAM PATH`, `__program-path__` → all resolve to `programpath` internally

**Implementation Rules**:
1. **Single normalization function**: `registry.normalize_identifier()` (aliased as `n()` in tool_providers.py)
2. **Single advertisement function**: `registry.to_snake_case()` converts any format to snake_case for display
3. **No hardcoded case matching**: Never check exact strings; always normalize first
4. **User-friendly**: If it looks like the tool/arg name, accept it

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

