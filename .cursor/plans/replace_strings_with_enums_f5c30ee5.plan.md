---
name: Replace strings with enums
overview: "Two-phase plan: (Phase A) Replace tool-name string literals with ToolName.*.value across agentdecompile_cli and document MCP security audit; (Phase B) Rename ToolName → Tool and add rich enum API (properties: .params, .normalized, .snake_name, .is_advertised, .is_gui_only_disabled; class method Tool.from_string). MCP/CLI wire format stays string at the boundary."
todos: []
isProject: false
---

# Replace tool-name strings with enums, then Tool rename + rich enum (merged plan)

**Plan structure:** **Phase A** (sections below through “Suggested implementation order”) — replace kebab-case literals with `ToolName.*.value`, verify DISABLED_GUI_ONLY_TOOLS, tests. **Phase B** (new section) — rename `ToolName` → `Tool`, add enum properties and `Tool.from_string`, thin wrappers, call-site migration to `tool.params` / `tool.normalized` / etc.

**Phase ordering (repo-research):** Phase A then Phase B is safe; no file has conflicting edits. executor.py and utils.py are Phase B only — Phase A must not modify them. Before starting Phase B, verify executor.py and utils.py are unchanged by Phase A.

## Enhancement summary

- **Deepened on:** 2026-03-11 (second pass); 2026-03-12 (third pass: repo-research-analyst, best-practices-researcher); 2026-03-12 (merged with [rename_toolname_to_tool_rich_enum.plan.md](.cursor/plans/rename_toolname_to_tool_rich_enum.plan.md) as Phase B).  
- **Scope:** Tool names (and existing ResourceUri) in `src/agentdecompile_cli/`; MCP/CLI boundary remains string. Phase A: string→enum replacement. Phase B: `Tool` rename + rich enum API.  
- **Current state:** [registry.py](src/agentdecompile_cli/registry.py) already defines `ToolName(str, Enum)`, `TOOL_PARAMS: dict[ToolName, list[str]]`, `DISABLED_GUI_ONLY_TOOLS: frozenset[ToolName]`, `resolve_tool_name_enum()`, `get_tool_params(ToolName | str)`. DISABLED_GUI_ONLY_TOOLS check in [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py) is **already fixed** (lines 1841–1842).  
- **Remaining work (Phase A):** Replace remaining kebab-case literals with `ToolName.*.value` where a member exists. **(Phase B):** Rename to `Tool`, add `.params`, `.normalized`, `.snake_name`, `.is_advertised`, `.is_gui_only_disabled`, `Tool.from_string()`, thin wrappers; migrate call sites.

### Key improvements from deepening

1. **Type-checker behavior:** Use enum membership (`tool_enum in DISABLED_GUI_ONLY_TOOLS`) so that resolved `ToolName` is compared to `frozenset[ToolName]`; mypy/pyright have varying support for narrowing on `in` with enums—explicit `tool_enum = resolve_tool_name_enum(name)` keeps intent clear.
2. **Single source of truth:** Optional follow-up to derive `_TOOL_PARAMS_STR` from `ToolName` (e.g. build dict from enum members or assert all keys in `ToolName` at load) to catch key typos at startup.
3. **Verification:** Add concrete test and type-check steps; after rollout, validate tool discovery/schema with MCP Inspector or mcptools (see [.cursor/skills/mcp-debugging/](.cursor/skills/mcp-debugging/)).

### New considerations (third pass)

- **response_formatter.py:** `action` comes from `data.get("action", data.get("operation", ""))` (wire string). Use `action == ToolName.OPEN.value` for comparison.  
- **Aliases / TOOLS_LIST.md:** New tools or aliases added only in TOOLS_LIST.md may not have a `ToolName` member until registry is updated; keep `resolve_tool_name_enum` returning `None` for unknown names and handle gracefully at call sites.  
- **Tools not in ToolName:** `connect-shared-project`, `list-open-programs` are used in [project.py](src/agentdecompile_cli/mcp_server/providers/project.py) and [bridge.py](src/agentdecompile_cli/bridge.py) but have no `ToolName` member today; either add enum members and use `.value` or keep as string literals until registry is updated. `search-symbols-by-name` is an advertised alias (resolves to manage-symbols); can remain string for the advertised alias name.  
- **TOOL_RENDERERS:** [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) uses normalized str keys (e.g. `"inspectmemory"`). Optional: build from `ToolName` via `normalize_identifier(ToolName.XXX.value)` to avoid drift.

---

## MCP security audit (workspace)

Per the mcp-security-audit skill, MCP configs were discovered under [.cursor/mcp.json](.cursor/mcp.json). **No secrets are reproduced below.**


| Server      | Type              | Classification      | Risks                                                                                                       |
| ----------- | ----------------- | ------------------- | ----------------------------------------------------------------------------------------------------------- |
| agdec-http  | Remote (HTTP URL) | Shadow MCP (remote) | High: remote SSE/HTTP endpoint not Runlayer-managed; credentials in headers (ensure not logged or exposed). |
| agdec-proxy | stdio             | Shadow MCP (stdio)  | Medium: local `uvx`/`agentdecompile-server`; not Runlayer CLI; env may contain credentials.                 |


**Remediation:**

1. **agdec-http:** Treat as unmanaged remote MCP. Prefer Runlayer for governance (e.g. `uvx runlayer login`) and PBAC if this server exposes destructive tools; ensure credentials are not stored in plain text in config and are injected via env or a secrets manager where possible.
2. **agdec-proxy:** Same credential hygiene for env vars; consider Runlayer for policy and audit if desired.

Audit does not change the enum-replacement implementation; it is recorded here for governance and future hardening.

---

## Design (unchanged)

- **Enum type:** `ToolName(str, Enum)` with `.value` as kebab-case wire format; member names PascalCase-from-kebab (e.g. `OPEN`, `GET_FUNCTIONS`).
- **Boundary:** MCP and CLI continue to use strings; conversion at registry boundary via `resolve_tool_name()` (str) and `resolve_tool_name_enum()` (ToolName | None).
- **Scope:** Tool names are the main target; ResourceUri already enum-based; parameter/mode enums deferred.

### Research insights (design)

- **StrEnum as single source of truth:** Use enum members in internal code; convert to string only at boundaries (`.value` for `call_tool`, MCP payloads, CLI help). Python 3.11+ `StrEnum` is an alternative to `(str, Enum)`; both compare equal to their string value and serialize the same.  
- **Exhaustive mappings:** When building dicts keyed by tool (e.g. TOOL_GUIDANCE), ensure every `ToolName` member is handled or explicitly skipped so adding a new enum member forces a decision (avoids silent omissions).  
- **References:** [Python enum docs](https://docs.python.org/3/library/enum.html); mypy/pyright enum narrowing with `in` (mypy PR #17044, pyright #8641).

---

## Research insights

**Best practices (Python str Enum + type checkers):**

- Use enum members in internal APIs and `.value` only at the MCP/CLI boundary (e.g. `call_tool(ToolName.OPEN.value, payload)`).
- For functions that accept both wire input and internal callers, `ToolName | str` with `resolve_tool_name_enum()` keeps backward compatibility and enables gradual tightening to `ToolName` where appropriate.
- StrEnum compares equal to strings; type checkers and IDEs get better autocomplete and typo detection when signatures use `ToolName` or `ToolName | None` rather than raw `str` for canonical tool names.
- Keep a single source of truth: registry owns `ToolName` and enum-keyed structures; tools_schema and **init** re-export and expose str-keyed views only where needed for backward compat.

**Edge case:** In [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py), `resolved_name in DISABLED_GUI_ONLY_TOOLS` would be incorrect (str vs frozenset[ToolName]); the codebase already uses `tool_enum = resolve_tool_name_enum(name)` and `tool_enum in DISABLED_GUI_ONLY_TOOLS`.

### Best practices (research)

- **Boundary pattern:** Accept `str` (wire) or `ToolName` (internal). Normalize with `tool_enum = resolve_tool_name_enum(name)`; do not use `ToolName(str_value)` on arbitrary input (resolver handles aliases and returns `None` for unknown names). Outbound: use `.value` for MCP/CLI.
- **(str, Enum) vs StrEnum:** For Python 3.10, keep `(str, Enum)`; use `.value` at boundaries. If moving to 3.11+ only, `StrEnum` gives clearer `str()` behavior; still use `.value` on the wire to avoid serializer/`type(x)==str` edge cases (Pydantic, pytest-xdist).
- **Type checkers:** After `if tool_enum is not None:` both mypy and pyright narrow to `ToolName`. Membership `tool_enum in DISABLED_GUI_ONLY_TOOLS` may not narrow in mypy (PR #17044 open); runtime is correct.
- **Single source of truth:** Build str-keyed views from enum (e.g. `{t.value: params for t, params in TOOL_PARAMS.items()}`); assert or derive so every key is a `ToolName` member at load to catch drift.
- **Tests:** Assert `set(TOOLS) == {t.value for t in ToolName}`; assert advertised set equals `{t.value for t in ToolName if t not in DISABLED_GUI_ONLY_TOOLS}`; optionally assert every TOOLS_LIST name resolves via `resolve_tool_name_enum`.

**References:** [Python enum](https://docs.python.org/3/library/enum.html), [mypy #17044](https://github.com/python/mypy/pull/17044), [pyright #8641](https://github.com/microsoft/pyright/issues/8641), [MCP spec – Tools](https://spec.modelcontextprotocol.io/specification/2025-03-26/server/tools/).

---

## Implementation plan (remaining work)

### 1. DISABLED_GUI_ONLY_TOOLS check in tool_providers.py (already fixed — verify only)

- **Status:** The fix is already applied in [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py) at lines 1841–1842: `tool_enum = resolve_tool_name_enum(name)` then `if tool_enum is not None and tool_enum in DISABLED_GUI_ONLY_TOOLS`. No code change required.
- **Verification:** Run unit tests that invoke a GUI-only tool in headless mode and assert the disabled error is returned; confirm no `str in frozenset[ToolName]` comparison remains.

**Reference (current correct pattern):**

```python
resolved_name: str = resolve_tool_name(name) or name
tool_enum: ToolName | None = resolve_tool_name_enum(name)
if tool_enum is not None and tool_enum in DISABLED_GUI_ONLY_TOOLS:
    return create_error_response(...)
```

### 2. Replace tool name string literals with ToolName.*.value

**CLI / bridge / server / launcher (wire boundary: keep .value for call_tool / MCP):**

- [cli.py](src/agentdecompile_cli/cli.py): Replace `"open"` in `call_tool(...)` and any help/example strings with `ToolName.OPEN.value`. Same for any other hardcoded tool names in this file.
- [bridge.py](src/agentdecompile_cli/bridge.py): Replace `"get-functions"` (and any other tool name literals) with `ToolName.GET_FUNCTIONS.value` (or appropriate enum).
- [mcp_server/server.py](src/agentdecompile_cli/mcp_server/server.py): Replace `"open"` in test/example payloads with `ToolName.OPEN.value`.
- [launcher.py](src/agentdecompile_cli/launcher.py) and [server.py](src/agentdecompile_cli/server.py): Replace `"open"` in `call_tool(...)` with `ToolName.OPEN.value`.
- [mcp_server/proxy_server.py](src/agentdecompile_cli/mcp_server/proxy_server.py): Replace `"open"` in example/tool list with `ToolName.OPEN.value`.

**Response formatter:**

- [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py): Replace `action == "open"` with comparison using `ToolName.OPEN.value` (or a normalized form if that is what `action` holds).

**Providers (list_tools / tool metadata):**

- In each provider under [mcp_server/providers/](src/agentdecompile_cli/mcp_server/providers/), replace `name="..."` in tool list entries with `name=ToolName.XXX.value`. Files to touch (representative): [project.py](src/agentdecompile_cli/mcp_server/providers/project.py), [decompiler.py](src/agentdecompile_cli/mcp_server/providers/decompiler.py), [symbols.py](src/agentdecompile_cli/mcp_server/providers/symbols.py), [getfunction.py](src/agentdecompile_cli/mcp_server/providers/getfunction.py), [script.py](src/agentdecompile_cli/mcp_server/providers/script.py), [memory.py](src/agentdecompile_cli/mcp_server/providers/memory.py), [callgraph.py](src/agentdecompile_cli/mcp_server/providers/callgraph.py), [comments.py](src/agentdecompile_cli/mcp_server/providers/comments.py), [structures.py](src/agentdecompile_cli/mcp_server/providers/structures.py), [dissect.py](src/agentdecompile_cli/mcp_server/providers/dissect.py), [datatypes.py](src/agentdecompile_cli/mcp_server/providers/datatypes.py), [vtable.py](src/agentdecompile_cli/mcp_server/providers/vtable.py), [constants.py](src/agentdecompile_cli/mcp_server/providers/constants.py), [data.py](src/agentdecompile_cli/mcp_server/providers/data.py), [dataflow.py](src/agentdecompile_cli/mcp_server/providers/dataflow.py), [strings.py](src/agentdecompile_cli/mcp_server/providers/strings.py), [xrefs.py](src/agentdecompile_cli/mcp_server/providers/xrefs.py), [import_export.py](src/agentdecompile_cli/mcp_server/providers/import_export.py). Also [search_everything.py](src/agentdecompile_cli/mcp_server/providers/search_everything.py) for suggested tool names in dicts (e.g. `"decompile-function"` → `ToolName.DECOMPILE_FUNCTION.value`).

**Executor:**

- [executor.py](src/agentdecompile_cli/executor.py): _LEGACY_ALIAS_TOOLS is a frozenset of normalized (alpha-only) strings used for “legacy alias” detection. Per original plan, keeping it as `frozenset[str]` is acceptable; no enum change required unless you later switch to a `frozenset[ToolName]` and resolve via `resolve_tool_name_enum`.

### 3. Public API and tests

- **[init**.py](src/agentdecompile_cli/__init__.py): Ensure `ToolName` and `ResourceUri` are exported (already present per tools_schema re-exports).
- Add or extend unit tests: (1) every `ToolName` member’s `.value` appears in the set of names expected by the Java server / TOOLS_LIST; (2) `resolve_tool_name_enum` for a few tools and aliases; (3) advertisement and DISABLED_GUI_ONLY_TOOLS behavior (including the fixed membership check).
- Run type checker (e.g. pyright) and fix any new issues from using `ToolName` in signatures and sets.

### Testing and verification (concrete steps)

- **Type check:** `uv run pyright src/agentdecompile_cli` (or project’s configured command).  
- **Unit tests:** `uv run pytest tests/ -v -k "registry or normalization or tool"` (or run full `uv run pytest tests/ -v`).  
- **MCP tool discovery (post-rollout):** Use [.cursor/skills/mcp-debugging/](.cursor/skills/mcp-debugging/) references (e.g. MCP Inspector or mcptools) to confirm advertised tool list and names are unchanged on the wire; ensures no accidental renames or missing tools.

### 4. Optional: _TOOL_PARAMS_STR in registry

- [registry.py](src/agentdecompile_cli/registry.py) still has `_TOOL_PARAMS_STR` keyed by kebab-case strings for merge/TOOLS_LIST sync. Converting this to be keyed by `ToolName` (e.g. building from enum) would remove the last large string-keyed tool map and catch key typos at load time; optional follow-up if you want to eliminate all str keys in registry.

### 5. Optional: TOOL_RENDERERS from ToolName

- [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) uses a str-keyed `TOOL_RENDERERS` with normalized keys (e.g. `"inspectmemory"`). Optional: build keys from `ToolName` via `normalize_identifier(ToolName.XXX.value)` so new tools are not silently omitted from the renderer map.

### Suggested implementation order (from repo research)

- **Phase A boundary:** Do **not** modify [executor.py](src/agentdecompile_cli/executor.py) or [utils.py](src/agentdecompile_cli/utils.py) in Phase A (no edits to `get_tool_params`, `normalize_identifier`, or `resolve_tool_name`). Before starting Phase B, verify they are unchanged (e.g. no diff in those files for Phase A).

1. **Registry / tools_schema** — No change required; already enum-based. Optional: validate or derive `_TOOL_PARAMS_STR` from `ToolName`.
2. **tool_providers.py** — Replace remaining string literals (`recommend_tool`, `call_tool`, context `"tool"`).
3. **response_formatter.py** — Replace `_render_generic(..., "inspect-memory")` etc. with `ToolName.*.value`; optionally derive `TOOL_RENDERERS` from enum.
4. **cli.py** — Help/example strings to `ToolName.*.value`.
5. **server.py / proxy_server.py** — Example JSON in docstrings.
6. **Providers (project.py, symbols.py, etc.)** — `recommend_tool` and `name=` where a `ToolName` member exists; leave `connect-shared-project` / `list-open-programs` / `search-symbols-by-name` as-is unless enum members are added.
7. **bridge.py / debug_info.py** — Replace literals that have enum members; `connect-shared-project` in bridge has no member.
8. **Tests** — Advertised-tools vs `ToolName`, `resolve_tool_name_enum`, DISABLED_GUI_ONLY_TOOLS behavior; type-check (pyright).

---

## Phase B: Rename ToolName → Tool and rich enum API

**Prerequisite:** Phase A complete (string literals replaced with `ToolName.*.value`).

**Goal:** (1) Rename `ToolName` → `Tool` across `src/agentdecompile_cli/` and tests. (2) Extend the enum with properties and class methods so call sites use `tool.params`, `tool.normalized`, `tool.snake_name`, `tool.is_advertised`, `tool.is_gui_only_disabled`, and `Tool.from_string(s)` instead of `get_tool_params(tool)`, `normalize_identifier(tool.value)`, `to_snake_case(resolved_name)`, `is_tool_advertised(name)`, and membership checks. (3) Keep `get_tool_params`, `is_tool_advertised`, `resolve_tool_name_enum` as thin wrappers; optional `ToolName = Tool` alias for one release.

### B.1 Rename and type updates

- [registry.py](src/agentdecompile_cli/registry.py): Change class name to `Tool`; replace every type hint and internal reference (`frozenset[ToolName]` → `frozenset[Tool]`, `dict[ToolName, ...]` → `dict[Tool, ...]`).
- **[init**.py](src/agentdecompile_cli/__init__.py), [tools_schema.py](src/agentdecompile_cli/tools_schema.py), [tool_registry.py](src/agentdecompile_cli/tool_registry.py): Export `Tool`; optionally `ToolName = Tool`.
- All consumers (cli, bridge, server, launcher, mcp_server/*, providers, tests): Replace `ToolName` with `Tool` in imports and usages.

### B.2 Rich Tool enum: properties and class methods

Define in [registry.py](src/agentdecompile_cli/registry.py). Use `@property` for any attribute that reads `TOOL_PARAMS`, `_DEFAULT_HIDDEN_TOOLS`, or `DISABLED_GUI_ONLY_TOOLS` (evaluated at access time to avoid init order issues).


| Property / method                      | Type / signature | Replaces                                                                     |
| -------------------------------------- | ---------------- | ---------------------------------------------------------------------------- |
| `.value`                               | str (keep)       | Wire kebab-case                                                              |
| `.normalized`                          | str              | `normalize_identifier(self.value)`                                           |
| `.snake_name`                          | str              | `to_snake_case(self.value)`                                                  |
| `.params`                              | list[str]        | `get_tool_params(self)` — **return copy:** `list(TOOL_PARAMS.get(self, []))` |
| `.is_hidden`                           | bool             | `self in _DEFAULT_HIDDEN_TOOLS`                                              |
| `.is_gui_only_disabled`                | bool             | `self in DISABLED_GUI_ONLY_TOOLS`                                            |
| `.is_advertised`                       | bool             | `is_tool_advertised(self.value)`                                             |
| `Tool.from_string(cls, s: str) -> Tool | None`            | class method                                                                 |
| `Tool.advertised(cls) -> list[Tool]`   | class method     | Build ADVERTISED_TOOLS from Tool                                             |


- **Registry refactor:** `TOOLS = [t.value for t in Tool]`; `ADVERTISED_TOOLS = [t.value for t in Tool.advertised()]` (refactor `_build_advertised_tools()` at 857–882 to use `Tool.advertised()`). Thin wrappers: `get_tool_params(tool)` → `tool.params` if `Tool` else `Tool.from_string(tool).params if Tool.from_string(tool) else []`; `is_tool_advertised(name)` → `Tool.from_string(name).is_advertised if Tool.from_string(name) else False`; `resolve_tool_name_enum(s)` → `Tool.from_string(s)`.

### B.3 Call-site replacements (Phase B)

- [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py): `normalize_identifier(ToolName.XXX.value)` → `Tool.XXX.normalized` (lines 91–99); `action == ToolName.OPEN.value` → `Tool.OPEN.value` (499, 1749); `is_tool_advertised(token)` optionally → `Tool.from_string(token).is_advertised` (112).
- [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py): `tool_enum = Tool.from_string(name)`; `tool_enum.is_gui_only_disabled`; `tool_enum.snake_name` instead of `to_snake_case(resolved_name)` (117, 119, 129, 1841–1846).
- [executor.py](src/agentdecompile_cli/executor.py): Line 768 `_registry.get_tool_params(canonical_tool_name)` → `Tool.from_string(canonical_tool_name).params` where a Tool is available; 951, 953, 956 `normalize_identifier(canonical_tool_name)` → `tool.normalized`.
- [cli.py](src/agentdecompile_cli/cli.py), [mcp_server/server.py](src/agentdecompile_cli/mcp_server/server.py): Where a Tool is available, use `tool.params`; else keep thin wrapper.

### B.4 Phase B order and verification

1. In registry: rename class to `Tool`, add properties and class methods; then refactor TOOLS and ADVERTISED_TOOLS; implement thin wrappers. Add `ToolName = Tool` if desired.
2. Update all files to use `Tool`; replace call sites with `.params`, `.normalized`, `.snake_name`, `.is_advertised`, `.is_gui_only_disabled`, `Tool.from_string`.
3. Run tests and type checker; grep for remaining `ToolName` (excluding alias).

**Line-level refs (Phase B):** See [rename_toolname_to_tool_rich_enum.plan.md](.cursor/plans/rename_toolname_to_tool_rich_enum.plan.md) “Line-level references (fourth pass)” table for registry (857–882, 885), executor (768, 951–956), response_formatter (91–99, 499, 1749, 112), tool_providers, cli, server.

**Tests (Phase A vs Phase B):** Phase A: test_tool_name_and_argument_normalization, test_unified_provider_advertisement, test_legacy_tools_advertisement, test_normalization_combinatorial, test_cli_helpers assert on ToolName, TOOLS, ADVERTISED_TOOLS, DISABLED_GUI_ONLY_TOOLS, get_tool_params. Phase B: same tests updated to Tool and .params / Tool.from_string; add/update tests for Tool.from_string (canonical, aliases, unknown→None), tool.params, tool.normalized, tool.is_advertised, tool.is_gui_only_disabled.

**References (Phase B):** [Python enum](https://docs.python.org/3/library/enum.html), [PEP 435](https://peps.python.org/pep-0435/) (mutable member values: return copies from `.params`), [PEP 613](https://peps.python.org/pep-0613/) (type alias deprecation).

---

## Files to touch (summary)


| Area                  | Files                                                                                                                                                                                                                                                                                                                               |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bug fix               | [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py) (DISABLED_GUI_ONLY_TOOLS already fixed; replace remaining string literals)                                                                                                                                                                                 |
| CLI / bridge / server | [cli.py](src/agentdecompile_cli/cli.py), [bridge.py](src/agentdecompile_cli/bridge.py), [mcp_server/server.py](src/agentdecompile_cli/mcp_server/server.py), [launcher.py](src/agentdecompile_cli/launcher.py), [server.py](src/agentdecompile_cli/server.py), [proxy_server.py](src/agentdecompile_cli/mcp_server/proxy_server.py) |
| Formatter             | [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py)                                                                                                                                                                                                                                                    |
| Providers             | All under [mcp_server/providers/](src/agentdecompile_cli/mcp_server/providers/) that use `name="..."` (see list above)                                                                                                                                                                                                              |
| Tests / typing        | Tests under `tests/` (registry/advertisement/disabled tools), pyright                                                                                                                                                                                                                                                               |
| **Phase B only**      | [executor.py](src/agentdecompile_cli/executor.py), [utils.py](src/agentdecompile_cli/utils.py); registry refactor (_build_advertised_tools, ADVERTISED_TOOLS); all Phase A files for rename ToolName→Tool and rich enum call sites                                                                                                  |


### Line-level references (from repo research)


| File                                                                             | Line(s)                                  | Literal / replacement                                                                                                                                                             |
| -------------------------------------------------------------------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py)         | 455, 469, 486                            | `recommend_tool("manage-files", "list-project-files")` → `ToolName.MANAGE_FILES.value`, `ToolName.LIST_PROJECT_FILES.value`                                                       |
| [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py)         | 790, 799                                 | `entries.append(("list-project-files", {}))` / `("manage-files", ...)` → use `ToolName.*.value`                                                                                   |
| [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py)         | 1921, 1938, 2034                         | `call_tool("list-project-files", ...)`, `"tool": "list-project-files"`, `call_tool("match-function", ...)` → `ToolName.LIST_PROJECT_FILES.value`, `ToolName.MATCH_FUNCTION.value` |
| [project.py](src/agentdecompile_cli/mcp_server/providers/project.py)             | 208, 335                                 | `name="connect-shared-project"`, `name="list-open-programs"` — no `ToolName` member; keep string or add enum                                                                      |
| [project.py](src/agentdecompile_cli/mcp_server/providers/project.py)             | 1215, 1310, 1731, 1755, 1974, 1976, 2039 | `recommend_tool("manage-files", "list-project-files")` → `ToolName.MANAGE_FILES.value`, `ToolName.LIST_PROJECT_FILES.value`                                                       |
| [symbols.py](src/agentdecompile_cli/mcp_server/providers/symbols.py)             | 89                                       | `name="search-symbols-by-name"` — advertised alias; can stay string                                                                                                               |
| [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) | 1155, 1236                               | `_render_generic(data, "inspect-memory")`, `_render_generic(data, "get-call-graph")` → `ToolName.INSPECT_MEMORY.value`, `ToolName.GET_CALL_GRAPH.value`                           |
| [server.py](src/agentdecompile_cli/mcp_server/server.py)                         | 638                                      | Example JSON in docstring: `"name":"open"`, `"name":"list-functions"` → `ToolName.OPEN.value`, `ToolName.LIST_FUNCTIONS.value`                                    |
| [cli.py](src/agentdecompile_cli/cli.py)                                          | 1953, 2194, 3658                         | Help/command/example strings: `"list-functions"`, `"match-function"`, `"inspect-memory"` → `ToolName.LIST_FUNCTIONS.value` etc.                                                   |
| [bridge.py](src/agentdecompile_cli/bridge.py)                                    | 862                                      | `call_tool("connect-shared-project", ...)` — no `ToolName` member; keep string or add enum                                                                                        |
| [debug_info.py](src/agentdecompile_cli/mcp_server/resources/debug_info.py)       | 78                                       | `"name": "manage-files"` → `ToolName.MANAGE_FILES.value`                                                                                                                          |


---

## Edge cases

- **Wire string in response_formatter:** `action` is from `data.get("action", data.get("operation", ""))`. Compare with `ToolName.OPEN.value`; if the wire ever sends a different casing or alias, normalize first (e.g. `resolve_tool_name(action) == ToolName.OPEN.value`) or keep string comparison for flexibility.  
- **Unknown tools / TOOLS_LIST-only aliases:** `resolve_tool_name_enum()` returns `None` for names not in the enum. Call sites that branch on tool type must handle `None` (e.g. fallback to generic handling or error). When adding a new tool in TOOLS_LIST.md, add a corresponding `ToolName` member in registry to avoid drift.  
- **Provider `name=` in list_tools:** Use `ToolName.XXX.value` so the advertised name remains the same string; no change to MCP schema or client behavior.  
- **Tools not in ToolName:** `connect-shared-project`, `list-open-programs` (project.py, bridge.py) and advertised alias `search-symbols-by-name` (symbols.py) have no enum member today; either add `ToolName` members and use `.value` or keep as string literals until registry is updated.

---

## Out of scope (later)

- Parameter names / mode/action values as enums.
- Env var names as enums.
- Runlayer migration for MCP servers (audit only; remediation is config/ops).
- Phase B is optional follow-on: Phase A alone achieves string→enum replacement; Phase B adds type-safety and a richer enum API.

---

## Risk and backward compatibility

- MCP and CLI contracts remain string; only internal code and test payloads use enums and `.value`.
- Existing imports of `TOOLS`, `get_tool_params`, and str-keyed `TOOL_PARAMS` (via tools_schema) remain valid.
- Fixing the DISABLED_GUI_ONLY_TOOLS check restores intended behavior (GUI-only tools actually disabled in headless).

