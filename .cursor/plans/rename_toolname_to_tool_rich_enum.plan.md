---
name: ""
overview: ""
todos: []
isProject: false
---

# Rename ToolName to Tool and add rich enum API

## Primary goal

**Improve maintainability and readability by reducing string usage and enabling static type enforcement.** Today, tool names and related data are passed as raw strings and looked up via helpers (`get_tool_params(name)`, `normalize_identifier(tool.value)`, membership in string-derived sets). This plan replaces those patterns with a single `Tool` enum: call sites use `Tool` values and enum properties (e.g. `tool.params`, `tool.normalized`) so type checkers can enforce correct usage and refactors stay safe. Wire format (kebab-case strings) stays unchanged; the improvement is internal API and types.

---

## Enhancement Summary

**Deepened on:** 2026-03-12 (initial); 2026-03-12 (fourth pass: repo-research-analyst, best-practices-researcher, line-level refs).  
**Sections enhanced:** All (Context, Rename, Rich enum, Registry refactor, Call-sites, Coverage, Compatibility, Files, Order) + line-level references and best-practices checklist.  
**Research agents used:** repo-research-analyst, best-practices-researcher.

### Key improvements

1. **Context and file list** — Added registry/call-site map and exhaustive list of files that reference `ToolName` or helpers (registry, API shims, CLI/bridge/server, MCP server, 21 providers, 9 test modules).
2. **Python 3.10 compatibility** — Project uses `requires-python = ">=3.10"`; stdlib `StrEnum` is 3.11+. Plan explicitly keeps `class Tool(str, Enum)` (no StrEnum) unless a backport is introduced.
3. **Rich-enum best practices** — Properties that depend on `TOOL_PARAMS` / `_DEFAULT_HIDDEN_TOOLS` / `ADVERTISED_TOOLS` must use `@property` (evaluated at access time) to avoid initialization-order issues; single source of truth in module-level dicts/sets.
4. **Risks and ordering** — No circular imports (registry does not import formatter/providers); keying consistency and optional `ToolName = Tool` alias documented.
5. **Fourth pass** — Line-level references for executor, response_formatter, registry (_build_advertised_tools, ADVERTISED_TOOLS); `.params` must return a **copy** (`list(TOOL_PARAMS.get(self, []))`) to avoid mutable shared data; `Tool.from_string` naming and thin `resolve_tool_name_enum` wrapper.

### New considerations

- **executor.py** uses `_registry.get_tool_params(canonical_tool_name)` at **line 768** and `normalize_identifier(canonical_tool_name)` at **951, 953, 956** in validation; migrate to `Tool.from_string(...).params` and `tool.normalized` where a `Tool` is available.
- **response_formatter** `_DISABLABLE_RECOMMENDATION_TOOLS` at **lines 91–99** uses `normalize_identifier(ToolName.XXX.value)`; replace with `Tool.XXX.normalized`. **499, 1749**: `action == ToolName.OPEN.value` → `Tool.OPEN.value`. **112**: `is_tool_advertised(token)` can stay or use `Tool.from_string(token).is_advertised` when a Tool is available.
- **registry.py** — `_build_advertised_tools()` at **857–882**; `ADVERTISED_TOOLS` at **885**. Refactor to build from `Tool.advertised()` in one place.
- **Type checkers** — Use `Tool` in all annotations (`frozenset[Tool]`, `dict[Tool, list[str]]`); prefer `Tool` over `Literal[Tool.X]` for parameters/returns unless a single-member literal is required.
- **Mutable data** — Do not store or return shared mutable lists from enum; `.params` must return `list(TOOL_PARAMS.get(self, []))` (copy). See [PEP 435](https://peps.python.org/pep-0435/) and enum docs on member values.
- **Hybrid str/enum risk:** If only some layers use `Tool` while others stay string-based (`ADVERTISED_TOOL_PARAMS`, `TOOL_RENDERERS`, `TOOL_GUIDANCE`, comparisons like `tool_name == "list_tools"`), type enforcement is partial. Mitigation: apply the “resolve at boundary” rule and convert internal dicts/sets and call sites that represent tool identity to `Tool` (or `Tool | None`); audit entry points and tests. Align with existing patterns: `ResourceUri`, enum-keyed `TOOL_PARAMS`, and domain enums in `models.py`.

---

## Goal

1. **Rename** `ToolName` → `Tool` across `src/agentdecompile_cli/` (and tests, docs).
2. **Extend the enum** with properties, class methods, and (where useful) classvars so that:
  - Any logic that today uses `get_tool_params(tool)`, `is_tool_advertised(name)`, `normalize_identifier(tool.value)`, `to_snake_case(tool.value)`, or membership in `_DEFAULT_HIDDEN_TOOLS` / `DISABLED_GUI_ONLY_TOOLS` can be expressed via the enum (e.g. `tool.params`, `tool.is_advertised`, `tool.normalized`, `tool.snake_name`, `tool.is_hidden`, `tool.is_gui_only_disabled`).
3. **Reduce repetition** by templating and abstracting: call sites use `Tool.OPEN.params`, `Tool.from_string(s)`, `tool.normalized`, etc., and module-level helpers become thin wrappers or are replaced.

### Type-safety and migration rules

- **Resolve at boundary:** When receiving a tool name from MCP/CLI (str), call `Tool.from_string(name)` once at the boundary; use `Tool | None` (or `Tool`) for the rest of the call path so internal code stays typed.
- **Prefer enum over string literals:** Use `Tool.XXX.value` (or `.wire_name` if kept) in provider `name=` and in comparisons; avoid literals like `"open"` to prevent typos and drift.
- **Data structures:** `_TOOL_PARAMS_STR` / `_merged_params_str` stay str-keyed; only `TOOL_PARAMS` is `dict[Tool, list[str]]`. `ADVERTISED_TOOL_PARAMS` remains str-keyed for ToolRegistry and tool_providers (wire/display). Internal sets use `frozenset[Tool]`; use `Tool` in annotations for params and membership.
- **Verification (post-implementation):** Grep for string literals that look like tool names (e.g. `'open'`, `'get-functions'`) and replace with `Tool.XXX.value` where the intent is a known tool.

---

## 0. Context and registry/call-site map (research)

### Registry (registry.py)

- **ToolName enum:** Lines 99–157. `class ToolName(str, Enum)` with ~60 members; `.value` is canonical kebab-case. `TOOLS = [t.value for t in ToolName]`.
- **Helpers:** `get_tool_params(ToolName | str)` (533–540), `is_tool_advertised(str)` (890–893), `resolve_tool_name(str) -> str | None` (964–1023), `resolve_tool_name_enum(str) -> ToolName | None` (522–530). `normalize_identifier(s)` (548–563), `to_snake_case(s)` (1026–1038).
- **Keying:** `TOOL_PARAMS: dict[ToolName, list[str]]` (725, from `_TOOL_PARAMS_STR`); `_DEFAULT_HIDDEN_TOOLS: frozenset[ToolName]` (792–808); `DISABLED_GUI_ONLY_TOOLS: frozenset[ToolName]` (496–503); `ADVERTISED_TOOLS: list[str]` (885) from `_build_advertised_tools()` which iterates `ToolName` and uses the frozensets.

### Files to touch (exhaustive)


| Role                            | Files                                                                                                                                                                                                                                                                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Defines / re-exports**        | registry.py, tools_schema.py, tool_registry.py, **init**.py                                                                                                                                                                                                                                                                   |
| **CLI / bridge / server**       | cli.py, bridge.py, server.py, launcher.py, executor.py, utils.py                                                                                                                                                                                                                                                              |
| **MCP server**                  | mcp_server/server.py, proxy_server.py, tool_providers.py, response_formatter.py, mcp_server/resources/debug_info.py                                                                                                                                                                                                           |
| **Providers (import ToolName)** | mcp_server/providers/*.py (bookmarks, callgraph, comments, constants, data, dataflow, datatypes, decompiler, dissect, functions, getfunction, import_export, memory, project, script, search_everything, strings, structures, symbols, vtable, xrefs)                                                                         |
| **Tests**                       | `test_cli_helpers.py`, `test_sdk_imports.py`, provider tests (`test_provider_*.py`), E2E / exhaustive contracts (`test_e2e_*.py`) — dedicated normalization/advertisement-only modules were removed; extend remaining tests if enum behavior needs coverage |


### Risks and ordering

- **No circular imports:** registry does not import response_formatter, tool_providers, or providers. Keep it that way (e.g. do not add registry/tool_providers imports into response_formatter).
- **Initialization order:** Enum is defined first; `TOOL_PARAMS`, `_DEFAULT_HIDDEN_TOOLS`, `ADVERTISED_TOOLS` are built after. Rich enum properties must use `@property` so they run at access time.
- **Backward compat:** `ToolName = Tool` at end of registry (and re-export from **init**) keeps existing type hints and imports working for one release.

### Line-level references (fourth pass)


| File                                                                             | Line(s)                  | Pattern / migration                                                                                                                                                              |
| -------------------------------------------------------------------------------- | ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [registry.py](src/agentdecompile_cli/registry.py)                                | 857–882, 885             | `_build_advertised_tools()`; `ADVERTISED_TOOLS = _build_advertised_tools()` — refactor to use `Tool.advertised()`                                                                |
| [registry.py](src/agentdecompile_cli/registry.py)                                | 522, 533–540, 890–893    | `resolve_tool_name_enum`; `get_tool_params(ToolName | str)`; `is_tool_advertised` — thin wrappers delegating to `Tool.from_string` and `.params` / `.is_advertised`              |
| [executor.py](src/agentdecompile_cli/executor.py)                                | 768                      | `_registry.get_tool_params(canonical_tool_name)` → `Tool.from_string(canonical_tool_name).params` when Tool available                                                            |
| [executor.py](src/agentdecompile_cli/executor.py)                                | 951, 953, 956            | `normalize_identifier(canonical_tool_name)` in validation → `tool.normalized` where a Tool is available                                                                          |
| [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) | 91–99                    | `normalize_identifier(ToolName.XXX.value)` in _DISABLABLE_RECOMMENDATION_TOOLS → `Tool.XXX.normalized`                                                                           |
| [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) | 499, 1749                | `action == ToolName.OPEN.value` → `Tool.OPEN.value`                                                                                                              |
| [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) | 112                      | `is_tool_advertised(token)` — keep or use `Tool.from_string(token).is_advertised`                                                                                                |
| [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py)         | 117, 119, 129, 1841–1846 | `is_tool_advertised(tool_name/fallback)`; `resolve_tool_name_enum(name)`; `tool_enum in DISABLED_GUI_ONLY_TOOLS` → `Tool.from_string`, `.is_advertised`, `.is_gui_only_disabled` |
| [cli.py](src/agentdecompile_cli/cli.py)                                          | 823, 1059                | `tool_registry.get_tool_params(resolved_name)`; `get_tool_params(tool_name)` — thin wrapper or `tool.params`                                                                     |
| [mcp_server/server.py](src/agentdecompile_cli/mcp_server/server.py)              | 86                       | `get_tool_params(canonical_name)` — thin wrapper or `Tool.from_string(canonical_name).params`                                                                                    |


**Top files by usage:** registry.py (~~100+), cli.py (~~77+), response_formatter.py (~~15), search_everything.py (~~12), tool_providers.py (~10).

---

## 1. Rename: ToolName → Tool

- **Registry** [registry.py](src/agentdecompile_cli/registry.py): Change class name to `Tool`, and replace every type hint and internal reference (`ToolName` → `Tool`, `frozenset[ToolName]` → `frozenset[Tool]`, `dict[ToolName, ...]` → `dict[Tool, ...]`).
- **Public API**: **[init**.py](src/agentdecompile_cli/__init__.py), [tools_schema.py](src/agentdecompile_cli/tools_schema.py), [tool_registry.py](src/agentdecompile_cli/tool_registry.py): Export `Tool` (and optionally keep `ToolName` as alias to `Tool` for one release, or drop it).
- **All consumers**: Replace `ToolName` with `Tool` in imports and usages in:
  - [cli.py](src/agentdecompile_cli/cli.py), [bridge.py](src/agentdecompile_cli/bridge.py), [server.py](src/agentdecompile_cli/server.py), [launcher.py](src/agentdecompile_cli/launcher.py)
  - [mcp_server/server.py](src/agentdecompile_cli/mcp_server/server.py), [proxy_server.py](src/agentdecompile_cli/mcp_server/proxy_server.py), [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py), [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py)
  - All [mcp_server/providers/*.py](src/agentdecompile_cli/mcp_server/providers/) that import or use the enum
- **Tests and docs**: Update any test or doc that references `ToolName`.

### Research insights (section 1)

- **Naming:** Best practice is PascalCase singular noun for the type (`Tool`); reserve `ToolName` for a backward-compat alias. Update all type hints to `Tool` and `frozenset[Tool]` / `dict[Tool, ...]`.
- **tools_schema.py:** Currently builds str-keyed view `TOOL_PARAMS = {t.value: list(p) for t, p in _TOOL_PARAMS_ENUM.items()}`; after rename the enum key is `Tool`, so only the import and type of `_TOOL_PARAMS_ENUM` change.
- **Executor:** Where only the canonical tool name string is available, prefer `tool = Tool.from_string(canonical_tool_name)` then `tool.params` and `tool.normalized` instead of repeated `get_tool_params(str)` and `normalize_identifier(str)`.

---

## 2. Rich Tool enum: properties and methods

Define in [registry.py](src/agentdecompile_cli/registry.py) (after `normalize_identifier` and `to_snake_case` exist; properties reference module-level names; some sets are built after the enum so use lazy/property access).

### 2.1 Instance properties (on each member, e.g. `Tool.OPEN`)


| Property                | Type      | Meaning                                         | Replaces / abstracts                                                          |
| ----------------------- | --------- | ----------------------------------------------- | ----------------------------------------------------------------------------- |
| (keep) `.value`         | str       | Canonical kebab-case wire name                  | Already used everywhere as wire form.                                         |
| `.wire_name`            | str       | Alias for `.value`                              | Optional; consider dropping (use `.value` only) to keep enum surface minimal. |
| `.normalized`           | str       | `normalize_identifier(self.value)`              | Replaces `normalize_identifier(Tool.XXX.value)` (e.g. in response_formatter). |
| `.snake_name`           | str       | `to_snake_case(self.value)`                     | Replaces `to_snake_case(resolved_name)` when the value is a known Tool.       |
| `.params`               | list[str] | Parameter names (camelCase) for this tool       | Replaces `get_tool_params(self)` / `TOOL_PARAMS.get(self, [])`.               |
| `.is_hidden`            | bool      | Member of default-hidden set (curated commands) | Replaces `self in _DEFAULT_HIDDEN_TOOLS`.                                     |
| `.is_gui_only_disabled` | bool      | Member of GUI-only disabled set                 | Replaces `self in DISABLED_GUI_ONLY_TOOLS`.                                   |
| `.is_advertised`        | bool      | Currently advertised (env-aware)                | Replaces `is_tool_advertised(self.value)` for enum call sites.                |


Implementation notes:

- `.params`: `return list(TOOL_PARAMS.get(self, []))` (TOOL_PARAMS remains `dict[Tool, list[str]]`).
- `.normalized`: `return normalize_identifier(self.value)`.
- `.snake_name`: `return to_snake_case(self.value)` (define or import `to_snake_case` before the enum, or use a local helper).
- `.is_hidden`: `return self in _DEFAULT_HIDDEN_TOOLS` (property body runs after module load, so set is defined).
- `.is_gui_only_disabled`: `return self in DISABLED_GUI_ONLY_TOOLS`.
- `.is_advertised`: delegate to same logic as `is_tool_advertised(self.value)` (e.g. call a shared helper or inline the ADVERTISED_TOOLS / env check) so behavior stays in one place.

### 2.2 Class methods (on `Tool`)


| Method              | Signature                      | Meaning                                     | Replaces / abstracts                                                         |
| ------------------- | ------------------------------ | ------------------------------------------- | ---------------------------------------------------------------------------- |
| `from_string`       | `(cls, s: str) -> Tool | None` | Resolve any alias/variant to canonical Tool | **Keep** — single entry from str→Tool. Replaces `resolve_tool_name_enum(s)`. |
| `all`               | `(cls) -> list[Tool]`          | All enum members                            | Optional; use `list(Tool)` at call sites to avoid redundant API.             |
| `canonical_visible` | `(cls) -> list[Tool]`          | All tools not in DISABLED_GUI_ONLY_TOOLS    | Add only if a second call site needs it; else fold into `Tool.advertised()`. |
| `advertised`        | `(cls) -> list[Tool]`          | Tools currently advertised (env-aware)      | **Keep.** Replaces iterating ADVERTISED_TOOLS strings; returns list[Tool].   |
| `wire_names`        | `(cls) -> list[str]`           | All canonical wire names (kebab-case)       | Optional; prefer module-level `TOOLS = [t.value for t in Tool]` and skip.    |


- `Tool.from_string(s)`: keep existing `resolve_tool_name(s)` and map result to enum; same behavior as current `resolve_tool_name_enum`. Naming: prefer `**from_string`** for the class method; keep `**resolve_tool_name_enum(s)**` as a one-line wrapper that calls `Tool.from_string(s)` for backward compatibility.
- `Tool.advertised()`: build from current ADVERTISED_TOOLS by mapping each string to Tool (or iterate Tool and use `.is_advertised`), return `list[Tool]`. Refactor `_build_advertised_tools()` (registry 857–882) to use this so `ADVERTISED_TOOLS` is derived from `Tool` in one place.

### 2.3 Classvars (optional)

- A classvar for params (e.g. `_params_cache`) is optional; the `.params` property can read directly from module-level `TOOL_PARAMS` to avoid circular definition issues and keep one source of truth.

### Research insights (section 2)

- **Python 3.10:** Project has `requires-python = ">=3.10"`. Stdlib `StrEnum` is 3.11+; keep `class Tool(str, Enum)` unless adding `backports.strenum` or bumping minimum to 3.11. Do not override `__str_`_; `str(member)` and wire format stay correct.
- **Single source of truth:** Implement properties as thin lookups: `return list(TOOL_PARAMS.get(self, []))`, `return self in _DEFAULT_HIDDEN_TOOLS`, `return is_tool_advertised(self.value)` (reuse existing helper so behavior lives in one place).
- **Initialization order:** Enum class body runs before module-level `TOOL_PARAMS` / `_DEFAULT_HIDDEN_TOOLS` / `ADVERTISED_TOOLS` are defined. Use `@property` for any attribute that reads those; avoid storing references in `__new__`/`__init__`.
- **Typing:** Annotate properties explicitly (e.g. `-> list[str]`, `-> bool`) so mypy/Pyright know return types. Use `Tool` in annotations; prefer `Tool` over `Literal[Tool.X]` for flexibility.
- `**.wire_name`:** Optional alias for `.value`; consider dropping to keep enum surface minimal.

---

## 3. Registry refactor: derive from Tool and thin wrappers

- **TOOLS**: Derive as `TOOLS: list[str] = [t.value for t in Tool]` or `Tool.wire_names()` (implement `wire_names` to return `[m.value for m in cls]`).
- **ADVERTISED_TOOLS**: Build by `[t.value for t in Tool.advertised()]` once the `Tool.advertised()` class method is implemented (it will need to use the same logic as current `_build_advertised_tools()`, which depends on _DEFAULT_HIDDEN_TOOLS, DISABLED_GUI_ONLY_TOOLS, env vars).
- **get_tool_params(tool: Tool | str)**: If `isinstance(tool, Tool)`: return `tool.params`; else `t = Tool.from_string(tool)`, return `t.params if t else []`.
- **is_tool_advertised(tool_name: str)**: `t = Tool.from_string(tool_name)`; return `t.is_advertised if t is not None else False`.
- **resolve_tool_name_enum**: Keep as `Tool.from_string` (or one-line wrapper) for backward compatibility.
- **ToolRegistry**: Continue to accept `str`; internally can use `Tool.from_string` and `.params` / `.value` where helpful.

### Research insights (section 3)

- **ADVERTISED_TOOLS:** Currently built in `_build_advertised_tools()` from `ToolName` iteration and env vars. After refactor, build as `[t.value for t in Tool.advertised()]` once `Tool.advertised()` is implemented (same logic as current `_build_advertised_tools`, e.g. filter by `_DEFAULT_HIDDEN_TOOLS`, `DISABLED_GUI_ONLY_TOOLS`, env).
- **ToolRegistry.init:** Today builds `_tool_params`, `_params_by_norm`, etc. from `TOOL_PARAMS` and `ADVERTISED_TOOLS`. After refactor these stay keyed by string (`.value` / normalized); no need to key by `Tool` inside ToolRegistry’s internal dicts if the public API remains str-based for call_tool.
- **Thin wrappers:** `get_tool_params(tool)` and `is_tool_advertised(tool_name)` remain the public API; implement by delegating to `tool.params` and `tool.is_advertised` when `Tool` is available, so external callers and tests do not need to change immediately.

---

## 4. Call-site replacements (reduce repetition)

- **response_formatter.py**: Replace `normalize_identifier(ToolName.XXX.value)` for the “disablable recommendation” set with `Tool.XXX.normalized`. Replace `action == ToolName.OPEN.value` with `action == Tool.OPEN.value`.
- **tool_providers.py**: Use `tool_enum = Tool.from_string(name)` and `tool_enum is not None and tool_enum.is_gui_only_disabled`. Use `tool_enum.snake_name` instead of `to_snake_case(resolved_name)` where we have the Tool.
- **cli.py**: Where a Tool is available, use `tool.params` and `tool.snake_name`; otherwise keep wrapper calls.
- **mcp_server/server.py**: Can use `Tool.from_string(canonical_name).params` when building schema, or keep `get_tool_params(canonical_name)` (thin wrapper).
- **Providers**: After rename, `name=Tool.XXX.value`; optionally use `Tool.XXX.params` if building schema from enum.

### Research insights (section 4)

- **response_formatter.py:** `_DISABLABLE_RECOMMENDATION_TOOLS` is a set of normalized strings (e.g. `normalize_identifier(ToolName.GET_FUNCTIONS.value)`). Replace with `Tool.XXX.normalized` for each member; optionally define as a `frozenset` of `Tool` and use `tool.normalized in {t.normalized for t in DISABLABLE_TOOLS}` for type safety.
- **tool_providers.py:** Pattern `tool_enum = resolve_tool_name_enum(name)` then `tool_enum in DISABLED_GUI_ONLY_TOOLS` and `to_snake_case(resolved_name)` maps to `tool_enum = Tool.from_string(name)`, `tool_enum.is_gui_only_disabled`, and `tool_enum.snake_name`.
- **executor.py:** Uses `_registry.get_tool_params(canonical_tool_name)` and `normalize_identifier(canonical_tool_name)` in validation and dispatch. Where a resolved tool is used repeatedly, consider `tool = Tool.from_string(canonical_tool_name)` then `tool.params` and `tool.normalized` to avoid repeated lookups.

---

## 5. Exhaustive coverage

- Migrate every pattern: `get_tool_params` → `tool.params` (or wrapper for str), `is_tool_advertised` → `tool.is_advertised`, `resolve_tool_name_enum` → `Tool.from_string`, `normalize_identifier(Tool.XXX.value)` → `Tool.XXX.normalized`, `to_snake_case(tool_value)` → `tool.snake_name`, membership checks → `.is_gui_only_disabled` / `.is_hidden`.
- Keep TOOL_PARAMS, _DEFAULT_HIDDEN_TOOLS, DISABLED_GUI_ONLY_TOOLS as module-level structures keyed by `Tool`; ADVERTISED_TOOLS built via Tool.advertised() for consistency.

### Research insights (section 5)

- **Exhaustive migration:** Grep for `get_tool_params`, `is_tool_advertised`, `resolve_tool_name_enum`, `normalize_identifier(Tool`, `to_snake_case(.*tool`, and membership in `_DEFAULT_HIDDEN_TOOLS` / `DISABLED_GUI_ONLY_TOOLS` to find every call site; replace with enum API or thin wrapper as per plan.
- **Comparison:** Prefer `tool == Tool.OPEN` and `tool in DISABLED_GUI_ONLY_TOOLS` over comparing to raw strings for clarity and type safety; StrEnum/str-Enum still allows `tool == "open"` but enum comparisons are clearer.
- **Tests / derived lists:** When tests or code build lists from tools (e.g. tools with params, curated commands), use `Tool` and properties: e.g. `[t.value for t in Tool if t.params]` or `{t for t in Tool if t in _SOME_SET}` instead of string-keyed derivations.

---

## 6. Backward compatibility

- Keep and export: `get_tool_params`, `is_tool_advertised`, `resolve_tool_name_enum` as thin wrappers. Optional: `ToolName = Tool` in **init** for one release.
- MCP/CLI wire format unchanged (kebab-case strings); `.value` / `.wire_name` remain the wire form.

### Research insights (section 6)

- **Alias:** Define `ToolName = Tool` at bottom of registry.py and re-export both from **init**.py so existing code and type hints keep working; deprecate `ToolName` in docs/changelog if removal is planned later.
- **Pickling:** Enums defined at module top level pickle correctly; no need for `module=__name_`_ since the enum is not created via functional API.
- **Wire format:** No change to MCP or CLI payloads; tool names remain kebab-case strings. All new API is internal (`.params`, `.normalized`, etc.) or additive (`Tool.from_string`).
- **Thin wrapper typing (optional):** Consider `@overload` for `get_tool_params(tool: Tool) -> list[str]` and `get_tool_params(name: str) -> list[str]` so type checkers infer return type from the argument.

---

## 7. Files to touch (summary)


| Area                  | Files                                                                                                                                                                                                                                                                                                 |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Enum and registry     | [registry.py](src/agentdecompile_cli/registry.py)                                                                                                                                                                                                                                                     |
| Public API            | **[init**.py](src/agentdecompile_cli/__init__.py), [tools_schema.py](src/agentdecompile_cli/tools_schema.py), [tool_registry.py](src/agentdecompile_cli/tool_registry.py)                                                                                                                             |
| CLI / bridge / server | [cli.py](src/agentdecompile_cli/cli.py), [bridge.py](src/agentdecompile_cli/bridge.py), [server.py](src/agentdecompile_cli/server.py), [launcher.py](src/agentdecompile_cli/launcher.py)                                                                                                              |
| MCP server            | [mcp_server/server.py](src/agentdecompile_cli/mcp_server/server.py), [proxy_server.py](src/agentdecompile_cli/mcp_server/proxy_server.py), [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py), [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) |
| Providers             | All [mcp_server/providers/*.py](src/agentdecompile_cli/mcp_server/providers/) that reference ToolName                                                                                                                                                                                                 |
| Tests / docs          | tests/, docs                                                                                                                                                                                                                                                                                          |


### Research insights (section 7)

- **Executor and utils:** executor.py and utils.py use `resolve_tool_name`, `normalize_identifier`, `canonicalize_tool_name`, `match_tool_name`; executor gets params via `_registry.get_tool_params`. Include executor.py and utils.py in the call-site pass (section 4) for any places that can use `Tool.from_string` and enum properties.
- **debug_info.py:** Imports `ToolName` and uses `ToolName.OPEN.value`, `ToolName.LIST_PROJECT_FILES.value`, etc.; update to `Tool` and `.value` (or `.wire_name`). Listed in section 0 table under MCP server.

---

## 8. Order of implementation

1. In registry: rename class to `Tool`, add properties and class methods (order: define Tool, then TOOL_PARAMS / _DEFAULT_HIDDEN_TOOLS / DISABLED_GUI_ONLY_TOOLS, then ADVERTISED_TOOLS using Tool; properties that depend on these can reference them since they run at access time).
2. Refactor TOOLS and ADVERTISED_TOOLS to use `TOOLS = [t.value for t in Tool]` and `[t.value for t in Tool.advertised()]`; implement thin wrappers get_tool_params, is_tool_advertised, resolve_tool_name_enum.
3. Add `ToolName = Tool` alias if desired; update all other files to use `Tool`.
4. Replace call sites to use `.params`, `.normalized`, `.snake_name`, `.is_advertised`, `.is_gui_only_disabled`, `Tool.from_string`.
5. Run tests and type checker; remove `ToolName` alias if added.

### Research insights (section 8)

- **Order is safe:** Enum is defined first; `normalize_identifier` and `to_snake_case` exist before the enum; `TOOL_PARAMS`, `_DEFAULT_HIDDEN_TOOLS`, `DISABLED_GUI_ONLY_TOOLS` are built after the enum. Properties that read them run at access time, so no reorder needed. Implement `Tool.advertised()` and `_build_advertised_tools()` to use it so `ADVERTISED_TOOLS` is derived from `Tool` in one place.
- **Verification:** After implementation, run: `uv run ruff check src/agentdecompile_cli tests/`, `uv run pytest tests/ -v --timeout=180` (or unit subset), and grep for remaining `ToolName` (excluding alias and deprecation comments) to ensure exhaustive rename.
- **Grep for exhaustive coverage:** `get_tool_params`, `is_tool_advertised`, `resolve_tool_name_enum`, `normalize_identifier(Tool`, `to_snake_case(.*tool`, membership in `_DEFAULT_HIDDEN_TOOLS` / `DISABLED_GUI_ONLY_TOOLS` — replace each with enum API or thin wrapper per plan. See line-level references table in section 0 for key files and line numbers.

---

## References (best practices)


| Topic                  | Reference                                                                                                            |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Enum module            | [enum — Support for enumerations (Python 3.x)](https://docs.python.org/3/library/enum.html)                          |
| Enum design            | [PEP 435 – Adding an Enum type](https://peps.python.org/pep-0435/)                                                   |
| Mutable enum values    | Enum docs “Member values”; return copies from properties                                                             |
| Properties on enums    | Use `@property` for attributes that read module-level dicts/sets (access time)                                       |
| Type alias deprecation | [PEP 613 – Explicit Type Aliases](https://peps.python.org/pep-0613/); `ToolName = Tool` for one release, then remove |


