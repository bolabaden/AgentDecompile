# MCP Resources for Zero-Arg / program_path-Only Tools — Research Summary

This document supports adding MCP resources that expose tool outputs at `agentdecompile://<tool-name>` for tools that can be called with **no arguments** or with **only program_path** (no other required parameters).

---

## 1. All MCP Tools: Name, Description, and Parameter Schema

Tools are defined by **provider** `list_tools()` and then filtered and normalized by **ToolProviderManager.list_tools()**. The canonical source is:

- **Tool names and param names (code):** `src/agentdecompile_cli/registry.py` — `Tool` enum, `_TOOL_PARAMS_STR` / `TOOL_PARAMS`, `ADVERTISED_TOOLS`, `ADVERTISED_TOOL_PARAMS`.
- **Required vs optional:** Each provider’s `list_tools()` returns `types.Tool` with `inputSchema.required`. The manager merges this with `ADVERTISED_TOOL_PARAMS` and builds the final advertised `required` list in `tool_providers.py` (see “Required list” comment around line 1944).
- **Cross-check / docs:** `TOOLS_LIST.md` at repo root is the canonical tool reference; the registry can merge param names from it via `_extract_tools_list_sync_data()` and `_merge_tools_list_params()`.

**Full parameter schema (required vs optional)** for each tool is therefore:

1. **Advertised list:** `ToolProviderManager.list_tools()` → one `types.Tool` per `ADVERTISED_TOOLS` entry with `inputSchema.properties` and `inputSchema.required` (snake_case in advertised schema).
2. **Required logic:** `required` comes from the provider’s `inputSchema.required`; normalized and then converted to snake_case for the advertised schema. Mode/selector aliases can make `mode` effectively required (see `_SELECTOR_PARAM_ALIASES` in `tool_providers.py`).

To get the exact list and schema programmatically, run the server and call MCP `tools/list` (or use `self.tool_providers.list_tools()` in tests).

---

## 2. Classification: No Args vs Only program_path vs Other Required

**Definitions:**

- **No arguments:** `inputSchema.required` is empty — tool can be called with `{}`.
- **Only program_path:** Either no required params, or the only required param is `program_path` (or `programPath`); no other user input required.
- **Requires other arguments:** Any other param is required (e.g. `conflictId`, `resolution`, `code`, `address`, `query`, `mode` for tools that require mode, etc.).

**Qualifying tools (no args or only program_path)** — from provider schemas and registry:

| Tool name | Params (summary) | Required (from providers) | Classification |
|-----------|------------------|---------------------------|----------------|
| `list-project-files` | folder, maxResults, programPath, path, binary | [] | No args |
| `list-prompts` | (none) | [] | No args |
| `get-current-program` | programPath | [] | No args |
| `open` | path, shared, serverHost, serverPort, … | [] | No args (path from context) |
| `sync-project` | mode, path, sourcePath, … | [] | No args |
| `manage-files` | mode, path, programPath, … | [] | No args (mode optional for list) |
| `checkout-program` | program_path, exclusive | [] | No args / only program_path |
| `checkin-program` | program_path, comment, keep_checked_out | [] | No args / only program_path |
| `checkout-status` | program_path | [] | No args / only program_path |
| `list-processors` | filter | [] | No args |
| `analyze-program` | programPath, analyzers, force | [] | No args / only program_path |
| `import-binary` | path, filePath, … | [] | No args (path often from context) |
| `export` | programPath, outputPath, format, … | [] | No args / only program_path |
| `change-processor` | programPath, language, compiler | [] | No args / only program_path |
| `list-functions` | programPath, mode, query, limit, … | [] | No args / only program_path |
| `get-functions` | programPath, identifier, view, … | [] | No args / only program_path |
| `list-exports` | programPath, filter, maxResults, … | [] | No args / only program_path |
| `list-imports` | programPath, libraryFilter, … | [] | No args / only program_path |
| `list-strings` / `manage-strings` (list) | programPath, filter, … | [] | No args / only program_path |
| `get-call-graph` | programPath, functionIdentifier, … | [] | No args / only program_path (function optional for “all”) |
| `decompile-function` | functionIdentifier, programPath, … | [] | Only program_path if function from context |
| `inspect-memory` | programPath, mode, address, … | [] (but read-bytes needs address) | Only program_path for “list blocks” |
| `list-cross-references` | programPath, address, … | [] | Only program_path (address optional for some modes) |
| `manage-bookmarks` | programPath, mode, … | [] | No args / only program_path (list mode) |
| `manage-comments` | programPath, mode, … | [] | No args / only program_path (list mode) |
| `manage-data-types` | programPath, mode, … | [] | No args / only program_path (list mode) |
| `manage-function-tags` | programPath, function, mode, tags | [] | No args / only program_path (list mode) |
| `manage-symbols` | programPath, mode, … | [] | No args / only program_path (list mode) |
| `manage-structures` | programPath, mode, … | [] | No args / only program_path (list mode) |
| `get-data` | programPath, addressOrSymbol | [] | Only program_path if address from context (rare) |
| `get-references` | programPath, target, … | [] | Only program_path if target from context |
| `search-constants` | programPath, mode, value, … | [] | No args / only program_path (list mode) |
| `search-symbols` | programPath, query, … | [] | No args / only program_path |
| `suggest` | programPath, suggestionType, … | [] | No args / only program_path |

**Not qualifying (other required):**

- `resolve-modification-conflict`: required `conflictId`, `resolution`.
- `remove-program-binary`: required `programPath`, `confirm`.
- `execute-script`: required `code`.
- `read-bytes` / `inspect-memory` (read mode): required `address`.
- `search-code`: required `query` (in strings provider).
- `search-everything`: runtime requires `query` or `queries`.
- `analyze-data-flow`: requires `functionAddress`, `direction`.
- Tools that effectively require `mode` when the provider marks a selector alias as required.

**Note:** GUI-only tools (`get-current-address`, `get-current-function`, `open-program-in-code-browser`, `open-all-programs-in-code-browser`) are disabled in headless and can be excluded from resource design.

---

## 3. Where MCP Resources Are Defined and Registered

### 3.1 Registration and dispatch

| Location | Symbol | Role |
|----------|--------|------|
| `src/agentdecompile_cli/mcp_server/resource_providers.py` | `ResourceProvider` | Base class: `list_resources()`, `read_resource(uri)`, `set_program_info`, `set_tool_provider_manager`, `program_opened`/`program_closed`. |
| `src/agentdecompile_cli/mcp_server/resource_providers.py` | `ResourceProviderManager` | Holds all providers; `_init_providers()` registers built-ins; `list_resources()` aggregates; `read_resource(uri, program_info)` tries each provider until one returns. |
| `src/agentdecompile_cli/mcp_server/server.py` | `AgentDecompileServer` | Creates `ResourceProviderManager()`, calls `set_tool_provider_manager(self.tool_providers)`, wires `list_resources()` and `read_resource(uri)` to the MCP server. |

### 3.2 Existing resources (URI pattern and response)

| Resource | URI(s) | File | Class | How response is produced |
|----------|--------|------|--------|---------------------------|
| Debug info | `agentdecompile://debug-info`, legacy `ghidra://agentdecompile-debug-info` | `resources/debug_info.py` | `DebugInfoResource` | `read_resource` builds a big JSON (metadata, session, project, version control, programs, analysis, profiling); uses `_safe_tool_call()` to call `list-project-files`, `get-current-program`, and optionally `checkout-status`. |
| Programs list | `ghidra://programs` (legacy, via DebugInfoResource) | `resources/programs.py` | `ProgramListResource` | `read_resource`: session binaries from `SESSION_CONTEXTS.get_project_binaries()` or domain folder listing; returns `{"programs": [...]}`. |
| Static analysis | `ghidra://static-analysis-results` (legacy, via DebugInfoResource) | `resources/static_analysis.py` | `StaticAnalysisResultsResource` | `read_resource`: SARIF 2.1.0 report for current program (or empty SARIF if no program). |
| Analysis dump | `ghidra://analysis-dump` | `resources/analysis_dump.py` | `AnalysisDumpResource` | `read_resource`: single JSON with bookmarks, symbols, comments, functions, data types, strings for current program (or programs list + empty categories). |

### 3.3 URI patterns

- **Current:** `agentdecompile://debug-info`, `ghidra://programs`, `ghidra://static-analysis-results`, `ghidra://analysis-dump`.
- **Proposed for tool-backed resources:** `agentdecompile://<tool-name>` (e.g. `agentdecompile://list-functions`), with tool name in kebab-case matching the canonical tool name.

### 3.4 How resources are fetched/served

1. Client calls MCP `resources/read` with a URI.
2. `server.read_resource(uri)` (in `server.py`) calls `self.resource_providers.read_resource(uri, self.program_info)`.
3. `ResourceProviderManager.read_resource()` iterates over `self.providers` and calls `provider.read_resource(uri)` until one returns without raising `NotImplementedError`. On failure it raises `ValueError`; the server catches and returns JSON `{"error": "...", "uri": ..., "status": "failed"}`.

---

## 4. Exact Code Paths for Adding New Resources

### 4.1 Where to add

- **New provider class:** Either a new file under `src/agentdecompile_cli/mcp_server/resources/` (e.g. `tool_resources.py`) or extend an existing one. Recommended: one new provider that handles all `agentdecompile://<tool-name>` URIs and dispatches to the tool manager.
- **Registration:** `ResourceProviderManager._init_providers()` in `resource_providers.py` — append the new provider(s) to `self.providers`.
- **Tool calls:** The new provider must have access to `ToolProviderManager` via `set_tool_provider_manager()` (already called by the server so that resources can call tools, as in `DebugInfoResource._safe_tool_call()`).

### 4.2 (a) Declaring a resource URI

- In the new provider’s `list_resources()`: for each qualifying tool, add a `types.Resource` with:
  - `uri=AnyUrl(url=f"agentdecompile://{tool_name}")` (tool_name in kebab-case, e.g. `list-functions`).
  - `name`, `description`, `mimeType="application/json"` (or as appropriate).

### 4.3 (b) Generating the response

**Rule (from your spec):** If the tool logically requires a program (program-scoped), the resource should return JSON keyed by each **opened** program path: `{"programPath1": output1, "programPath2": output2}`. If the tool is session/project-scoped (no program), return a single payload (e.g. one tool result).

**Implementation outline:**

1. **Resolve URI to tool name:** e.g. strip `agentdecompile://` and normalize to canonical tool name (e.g. `resolve_tool_name()` or `Tool.from_string()`).
2. **Decide scope:**
   - **Session/project scope** (e.g. `list-project-files`, `list-prompts`, `get-current-program`, `open`, `sync-project`, `list-processors`): call the tool once with `{}` or minimal args; return `json.dumps(result)` (or wrap in `{"result": ...}`).
   - **Program scope** (e.g. `list-functions`, `analyze-program`, `list-exports`): get open program paths from the session, then for each path call the tool and key by path.
3. **Getting open program paths:** Use `get_current_mcp_session_id()` and then `SESSION_CONTEXTS.get_session_snapshot(session_id)["openProgramKeys"]` (or iterate `session.open_programs.keys()`). Alternatively use the same source as `ProgramListResource` / `analysis_dump`: `SESSION_CONTEXTS.get_project_binaries(session_id)` for project binaries; for *open* only, prefer `openProgramKeys` from the snapshot.
4. **Calling the tool per program:** For each `program_path` in open program keys:
   - Ensure the tool manager’s provider has the correct program context (the manager’s `call_tool` resolves program from args; pass `programPath` in the args).
   - Call `await self.tool_provider_manager.call_tool(tool_name, {"programPath": program_path, "format": "json"})`.
   - Parse the response (e.g. extract text from `list[types.TextContent]`, then JSON-decode if needed).
   - Store in a dict: `out[program_path] = parsed_or_text`.
5. **Return:** `return json.dumps(out)` for program-scoped (e.g. `{"path/a": {...}, "path/b": {...}}`). For session-scoped, return the single tool output (or wrapped in a small structure).

**Error handling:** If a tool call fails for one program, you can put an error object in that key (e.g. `{"path/a": {"success": false, "error": "..."}}`) so the client still gets results for other programs.

### 4.4 Files and symbols summary

| File | Symbol | Purpose |
|------|--------|--------|
| `resource_providers.py` | `ResourceProviderManager._init_providers()` | Register new provider(s). |
| `resource_providers.py` | `ResourceProvider` | Base: `list_resources`, `read_resource(uri)`. |
| `resources/debug_info.py` | `DebugInfoResource._safe_tool_call()` | Pattern for calling a tool from a resource and parsing response. |
| `resources/analysis_dump.py` | `_collect_programs_from_session()` | Pattern for session_id + program list (open + project binaries). |
| `session_context.py` | `SESSION_CONTEXTS.get_session_snapshot(session_id)` | Get `openProgramKeys`, `activeProgramKey`, etc. |
| `session_context.py` | `SESSION_CONTEXTS.get_program_info(session_id, key)` | Get `ProgramInfo` for a program path (for setting context if needed). |
| `tool_providers.py` | `ToolProviderManager.call_tool(name, arguments)` | Invoke a tool by name with args (program resolved inside). |
| `registry.py` | `resolve_tool_name()`, `Tool`, `ADVERTISED_TOOLS` | Map URI path to canonical tool name and check if advertised. |

---

## 5. Step-by-Step Implementation Outline

1. **Add a new resource provider** (e.g. `ToolOutputResource` in `resources/tool_resources.py`):
   - In `list_resources()`, for each qualifying tool (from a fixed list or derived from `ADVERTISED_TOOLS` + a “qualifying” filter), add `types.Resource(uri=AnyUrl(f"agentdecompile://{tool_name}"), ...)`.
   - In `read_resource(uri)`:
     - If `uri` is not `agentdecompile://<tool-name>`, raise `NotImplementedError`.
     - Parse tool name from URI (e.g. `uri.replace("agentdecompile://", "")`), normalize (e.g. `resolve_tool_name()`), and check it’s in the qualifying set.
     - If tool is session-scoped: call `await self._safe_tool_call(tool_name, {})` (or minimal args), then return `json.dumps(result)`.
     - If tool is program-scoped: get `open_program_keys` from `SESSION_CONTEXTS.get_session_snapshot(get_current_mcp_session_id())["openProgramKeys"]`. If empty, return `json.dumps({})` or `{"error": "no open programs"}`. Else for each key call `await self._safe_tool_call(tool_name, {"programPath": key, "format": "json"})` and build `{key: parsed_output}`; return `json.dumps(out)`.
   - Reuse the same `_safe_tool_call` / response-parsing pattern as `DebugInfoResource` (extract text, optionally parse JSON, handle errors).

2. **Register the provider** in `ResourceProviderManager._init_providers()` in `resource_providers.py`: append the new provider instance to `self.providers`. Ensure the server already calls `resource_providers.set_tool_provider_manager(self.tool_providers)` so the new provider can call tools.

3. **Optional: centralize “qualifying” tools** in `registry.py` or a small constant (e.g. `TOOLS_ELIGIBLE_FOR_RESOURCE`) so both the resource (for `list_resources` and `read_resource`) and any tests/docs stay in sync.

4. **Tests:** Add unit tests that (a) list resources and assert `agentdecompile://list-functions` (etc.) appear, and (b) call `read_resource` for one no-arg and one program-scoped tool and assert shape (e.g. session-scoped single object; program-scoped dict keyed by program path).

---

## 6. References to TOOLS_LIST.md and Tool Enumeration

- **TOOLS_LIST.md** (repo root): Exhaustive tool reference; each tool has a `### \`<name>\`` section with Parameters, Overloads, Synonyms, Examples. The registry parses it in `_extract_tools_list_sync_data()` to merge param names and aliases into `TOOL_PARAMS` and `TOOL_ALIASES`.
- **Registry:** `registry.py` — `Tool` enum (all canonical names), `_TOOL_PARAMS_STR`, `TOOL_PARAMS`, `ADVERTISED_TOOLS`, `ADVERTISED_TOOL_PARAMS`, `get_tool_params()`. Use these to cross-check tool names and param lists.
- **Manager:** `tool_providers.py` — `ToolProviderManager.list_tools()` returns the final advertised tools (only from `ADVERTISED_TOOLS`) with normalized params and `responseFormat`; required list comes from each provider’s schema.

To keep the “qualifying tools” list accurate, either:
- Derive it once from `list_tools()` output (required array empty or only program_path), or
- Maintain a small explicit list (e.g. `RESOURCE_ELIGIBLE_TOOLS`) next to `ADVERTISED_TOOLS` and document that it must be updated when adding tools that are no-arg or program_path-only.

---

## 7. Concise Checklist for One Resource Per Qualifying Tool

- [ ] Add provider class that implements `list_resources()` (one resource per `agentdecompile://<tool-name>`) and `read_resource(uri)`.
- [ ] For session-scoped tools: one `call_tool` with `{}` (or minimal args); return JSON of that result.
- [ ] For program-scoped tools: get `openProgramKeys` from session snapshot; for each key `call_tool(tool_name, {"programPath": key, "format": "json"}); build `{key: output}`; return JSON.
- [ ] Register provider in `ResourceProviderManager._init_providers()`.
- [ ] Optionally add `TOOLS_ELIGIBLE_FOR_RESOURCE` (or similar) and reference it from the new provider and from this doc.
- [ ] Cross-check tool list against `TOOLS_LIST.md` and `ADVERTISED_TOOLS` / provider schemas.
