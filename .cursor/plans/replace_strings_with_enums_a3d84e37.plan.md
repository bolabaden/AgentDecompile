---
name: Replace strings with enums
overview: Introduce a canonical ToolName enum (and optionally ResourceUri enum) in agentdecompile_cli, then replace tool-name string literals and frozensets with enum-based types everywhere internal code uses them, while keeping the MCP/CLI boundary as strings and converting at the registry layer.
todos: []
isProject: false
---

# Replace tool-name and related strings with enums in agentdecompile_cli

## Goal

Replace string literals for tool names (and where practical other string constants) with statically type-enforceable enums across `src/agentdecompile_cli/`, so that typos and ad-hoc strings are caught by type checkers and IDEs. The main target is tool names (e.g. `_LEGACY_TOOL_NAMES` / `_DEFAULT_HIDDEN_TOOLS`, `TOOL_PARAMS` keys, advertisement logic); MCP wire and CLI still use strings at the boundary.

## Current state

- **Single source of truth**: [registry.py](src/agentdecompile_cli/registry.py) defines `TOOLS` (list of kebab-case strings), `TOOL_PARAMS` (dict keyed by those strings), `_DEFAULT_HIDDEN_TOOLS`, `DISABLED_GUI_ONLY_TOOLS`, `NON_ADVERTISED_TOOL_ALIASES`, and helpers like `resolve_tool_name()`, `is_tool_advertised()`, `get_tool_params()`.
- **Mirror**: [tools_schema.py](src/agentdecompile_cli/tools_schema.py) mirrors TOOLS/TOOL_PARAMS for compatibility; doc says "Prefer importing from agentdecompile_cli.registry".
- **Usage**: Tool name strings appear in [cli.py](src/agentdecompile_cli/cli.py) (`_TOOLS_WITH_CURATED_COMMANDS`, hardcoded `"get-functions"`, `"manage-bookmarks"`), [bridge.py](src/agentdecompile_cli/bridge.py) (e.g. `resolve_tool_name(tool.name)`), [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py) (dispatch, `recommend_tool`, `render_tool_response(norm_name, ...)`), [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) (TOOL_GUIDANCE/TOOL_RENDERERS keyed by normalized name), [executor.py](src/agentdecompile_cli/executor.py) (`_LEGACY_ALIAS_TOOLS`), and provider modules (e.g. `name="manage-bookmarks"`, `name="get-functions"`).
- **Normalization**: Matching is done via `normalize_identifier(s)` (alpha-only lowercase). Aliases resolve to a canonical kebab-case name via `resolve_tool_name()` and `TOOL_ALIASES` / `NON_ADVERTISED_TOOL_ALIASES`.

## Design decisions

1. **Enum type**: Use `class ToolName(str, Enum)` so that `ToolName.OPEN_PROJECT.value == "open"` (wire format) and enum members are serialization-friendly. Member names: `OPEN_PROJECT`, `GET_FUNCTIONS`, `MANAGE_BOOKMARKS`, etc. (PascalCase from kebab).
2. **Boundary**: MCP and CLI receive/emit strings. Conversion: at registry boundary, `resolve_tool_name(str)` continues to return canonical kebab `str`; add `resolve_tool_name_enum(s: str) -> ToolName | None` that returns the enum for the resolved canonical name. Internal APIs that today take `tool_name: str` (where the value is known to be canonical) can be updated to `tool_name: ToolName | str` during transition, then to `ToolName` where appropriate.
3. **Scope of “everywhere”**: Focus on **tool names** as the primary change. Optional follow-up: **ResourceUri** enum for `RESOURCE_URI`_* constants; **parameter names** and **mode/action** values are a much larger surface (many tools × many params) and can be a later phase.

## Implementation plan

### 1. Define ToolName enum and keep TOOLS as derived list

- In [registry.py](src/agentdecompile_cli/registry.py) (or a new `agentdecompile_cli/enums.py` if you prefer to keep registry lean), define `ToolName(str, Enum)` with one member per canonical tool, `value` = kebab-case string (e.g. `OPEN_PROJECT = "open"`, `GET_FUNCTIONS = "get-functions"`, …). Generate member names from kebab by uppercasing and replacing `-` with `_`.
- Derive the current `TOOLS` list from the enum so there is a single source of truth: e.g. `TOOLS: list[str] = [t.value for t in ToolName]` (or keep a list and add a consistency assert). Ensure every entry in the current `TOOLS` has a corresponding enum member.

### 2. Registry: key internal structures by ToolName

- **TOOL_PARAMS**: Change to `dict[ToolName, list[str]]` keyed by enum. Provide backward-compatible access: `get_tool_params(tool_name: ToolName | str) -> list[str]` that accepts `str`, resolves via `resolve_tool_name` and maps to `ToolName` when possible, then looks up in the dict (so existing callers passing string still work).
- **_DEFAULT_HIDDEN_TOOLS**: Change to `frozenset[ToolName]` (e.g. `frozenset({ToolName.DELETE_PROJECT_BINARY, ToolName.GEN_CALLGRAPH, ...})`). In `_build_advertised_tools()` and `is_tool_advertised()`, compare using enum (or normalized string from `tool.value`) so logic remains equivalent.
- **DISABLED_GUI_ONLY_TOOLS**: Change to `frozenset[ToolName]` and update any code that checks membership.
- **NON_ADVERTISED_TOOL_ALIASES**: Keep as `dict[str, str]` for alias → canonical string (or alias normalized → canonical string). Where code uses the canonical value for lookup, convert to `ToolName(canonical)` when building/advertising.
- **TOOL_ALIASES** (from TOOLS_LIST.md): Same idea—values are canonical names; where we need a set or key lookup internally, use `ToolName` for the canonical side.
- Add `resolve_tool_name_enum(tool_name: str) -> ToolName | None` that returns `ToolName(resolved)` when `resolve_tool_name(tool_name)` is not None; otherwise None.
- **ADVERTISED_TOOLS** / **ADVERTISED_TOOL_PARAMS**: Build from the same logic as today but using `ToolName` for membership and keys where applicable; when exposing to MCP/CLI, use `.value` so the wire still sees kebab-case strings.

### 3. CLI (cli.py)

- **[_TOOLS_WITH_CURATED_COMMANDS](src/agentdecompile_cli/cli.py)**: Change from `frozenset[str]` to `frozenset[ToolName]` (e.g. `ToolName.GET_FUNCTIONS`, `ToolName.MANAGE_BOOKMARKS`). Where this set is used for membership checks, compare using enum (or normalize and compare by `tool.value` if the incoming name is still a string in that code path).
- Replace hardcoded tool name strings (e.g. `"get-functions"`, `"manage-bookmarks"` in help or `_call(ctx, "manage-bookmarks", ...)`) with `ToolName.GET_FUNCTIONS.value` / `ToolName.MANAGE_BOOKMARKS.value` (or pass enum and use `.value` at call site) so there are no bare string literals for tool names.
- Any call to `TOOL_PARAMS.get(tool_name)` or similar: use the new `get_tool_params(tool_name)` that accepts `ToolName | str`, or pass enum where available.

### 4. Bridge (bridge.py)

- Where `resolve_tool_name(tool.name)` is used and the result is used as a canonical name for internal logic, optionally use `resolve_tool_name_enum(tool.name)` and pass `ToolName` through where it simplifies types; at the actual `call_tool(name, arguments)` boundary keep `name: str` (MCP contract). So: internal state or recommendations can use `ToolName`; outgoing requests use `name` (string).

### 5. Tool providers (tool_providers.py, server.py)

- **ToolProviderManager.call_tool(name: str, ...)**: Keep `name: str` for the MCP API. Inside the implementation, resolve once: `canonical = resolve_tool_name(name) or name`, then optionally `tool_enum = resolve_tool_name_enum(name)` for any internal branching or logging that benefits from enum.
- **recommend_tool(tool_name: str, ...)**: Can accept `ToolName | str` and use `.value` when passing to code that expects string.
- **render_tool_response(normalized_tool_name: str, data)**: Response formatter currently keys by normalized string; can stay as-is (normalized name is the key), or we could pass `ToolName` and use `normalize_identifier(tool.value)` for the key—minimal gain unless we also switch TOOL_GUIDANCE to enum keys.
- **HANDLERS** in provider subclasses: Keep as `dict[str, str]` (normalized tool name → method name); dispatch is still by normalized string from the request. No change required unless we want to key HANDLERS by enum (then we’d need normalized key from enum, which is redundant with current design).

### 6. Response formatter (response_formatter.py)

- **TOOL_GUIDANCE** / **TOOL_RENDERERS**: Currently keyed by normalized (alpha-only) string. Options: (a) leave as-is and keep passing normalized string from callers, or (b) key by `ToolName` and at call site use `normalize_identifier(tool.value)` or a helper to get the key. Prefer (a) for minimal change unless we refactor call sites to pass `ToolName` and add a small helper to get the normalized key from enum.
- Replace any literal tool-name strings in this file with `ToolName.*.value` or the normalized form from enum if we add a helper.

### 7. Executor (executor.py)

- **_LEGACY_ALIAS_TOOLS**: Currently a frozenset of normalized (alpha-only) strings. Either (a) keep as frozenset of normalized strings for “legacy alias” detection, or (b) if those normalized names correspond to canonical tools, use a `frozenset[ToolName]` and compare with `resolve_tool_name_enum(name)`; if they are aliases (e.g. `decompilefunction` → decompile-function), (a) is simpler and consistent with “alias” naming.

### 8. Provider modules (providers/*.py)

- Where tools are listed by name (e.g. `name="manage-bookmarks"`, `name="get-functions"` in `list_tools()` or similar), use `ToolName.MANAGE_BOOKMARKS.value` and `ToolName.GET_FUNCTIONS.value` so the advertised name remains the same string but the source is the enum.
- [bookmarks.py](src/agentdecompile_cli/mcp_server/providers/bookmarks.py), [functions.py](src/agentdecompile_cli/mcp_server/providers/functions.py), [search_everything.py](src/agentdecompile_cli/mcp_server/providers/search_everything.py), and any other provider that references tool names by string should import `ToolName` and use enum members.

### 9. tools_schema.py and public API

- [tools_schema.py](src/agentdecompile_cli/tools_schema.py): Either (1) re-export `ToolName` and derive `TOOLS` from it (e.g. `from agentdecompile_cli.registry import ToolName; TOOLS = [t.value for t in ToolName]`) and keep TOOL_PARAMS in registry only, or (2) keep tools_schema as a thin mirror that imports TOOLS/TOOL_PARAMS from registry and add a re-export of `ToolName` from registry. That keeps “single source of truth” in registry.
- **[init**.py](src/agentdecompile_cli/__init__.py): Export `ToolName` (and optionally `ResourceUri` if added) so consumers can use the enum.

### 10. Optional: ResourceUri enum

- In the same enums module (or registry), define `class ResourceUri(str, Enum)` with `PROGRAMS = "ghidra://programs"`, `STATIC_ANALYSIS = "ghidra://static-analysis-results"`, `DEBUG_INFO = "ghidra://agentdecompile-debug-info"`. Replace `RESOURCE_URI`_* constants and `RESOURCE_URIS` list with the enum and a list of its values. Update any code that compares or passes resource URIs to use the enum (and `.value` at boundaries).

### 11. Tests and typing

- Add/update unit tests that (1) ensure every `ToolName` member’s value is in the set of strings expected by the Java server / TOOLS_LIST, (2) test `resolve_tool_name_enum` for a few known tools and aliases, (3) test that advertisement and hidden-tool logic behave the same with enum-based sets.
- Run type checker (e.g. pyright) and fix any new issues from switching to `ToolName` in signatures and sets.

## Files to touch (summary)


| Area                         | Files                                                                                                                                                                                                                                                                               |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Enum definition and registry | [registry.py](src/agentdecompile_cli/registry.py) (or new enums.py), [tools_schema.py](src/agentdecompile_cli/tools_schema.py)                                                                                                                                                      |
| CLI                          | [cli.py](src/agentdecompile_cli/cli.py)                                                                                                                                                                                                                                             |
| Bridge / server              | [bridge.py](src/agentdecompile_cli/bridge.py), [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py), [server.py](src/agentdecompile_cli/mcp_server/server.py) if it references tool names                                                                       |
| Response / formatter         | [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) (optional enum usage)                                                                                                                                                                              |
| Executor                     | [executor.py](src/agentdecompile_cli/executor.py)                                                                                                                                                                                                                                   |
| Providers                    | [bookmarks.py](src/agentdecompile_cli/mcp_server/providers/bookmarks.py), [functions.py](src/agentdecompile_cli/mcp_server/providers/functions.py), [search_everything.py](src/agentdecompile_cli/mcp_server/providers/search_everything.py), and any other with tool name literals |
| Public API                   | **[init**.py](src/agentdecompile_cli/__init__.py)                                                                                                                                                                                                                                   |


## Out of scope (for a later pass)

- **Parameter names** (e.g. `programPath`, `mode`): Large and per-tool; could be a separate `ParamName` or per-tool enums later.
- **Mode/action values** (e.g. `"rename"`, `"list"`): Could be tool-specific enums in a follow-up.
- **Env var names** (e.g. `AGENTDECOMPILE_ENABLE_LEGACY_TOOLS`): Can be an enum later if desired.

## Risk and backward compatibility

- **MCP/CLI contract**: Unchanged; names remain kebab-case strings on the wire and in CLI commands.
- **Imports**: Existing code that does `from agentdecompile_cli.registry import TOOLS, get_tool_params` continues to work; we add `ToolName` and optional `resolve_tool_name_enum`, and `get_tool_params` accepts `str` as well as `ToolName`.
- **Dynamic behavior**: `ADVERTISED_TOOLS` is built at module load from env; we still build a list of strings for MCP advertisement (from enum values), so behavior stays the same.

