---
name: K1 match-function migration script
overview: Provide a way to bulk-propagate function metadata from a documented source binary (e.g. k1_win_gog_swkotor.exe) to other project binaries. Implementation is a thin helper_scripts launcher that invokes the CLI migrate-metadata command; all iteration and target discovery live inside the match-function tool (bulk mode when no functionIdentifier is given).
todos:
  - id: "1"
    content: Create helper_scripts script (migrate_k1_metadata.py) as backward-compatible launcher mapping script args to CLI migrate-metadata
    status: completed
  - id: "2"
    content: "CLI migrate-metadata: call match-function with no functionIdentifier so tool iterates all functions; pass programPath, optional targetProgramPaths, limit, propagate* flags"
    status: completed
  - id: "3"
    content: "match-function bulk mode: when no functionIdentifier, discover targets via SESSION_CONTEXTS.get_project_binaries; _list_source_function_identifiers; loop _handle_match_cross_program"
    status: completed
  - id: "4"
    content: Script forwards --server-url to AGENT_DECOMPILE_MCP_SERVER_URL, --source-path→--binary, --target-paths, --limit, --dry-run (→--limit 0), --include-externals, --verbose
    status: completed
  - id: "5"
    content: Document preferred path (agentdecompile-cli migrate-metadata) and script launcher in docstring and USAGE.md
    status: completed
  - id: "6"
    content: "Verify: dry-run (--limit 0), small run (--limit 2) with one target, manual K1 project run"
    status: completed
isProject: false
---

## Enhancement Summary

**Deepened on:** 2026-03-12  
**Sections enhanced:** Implementation plan, MCP protocol details, list-project-files response shape, Error handling, Testing.

**Updated on:** 2026-03-12 (post-implementation)  
**Corrections:** Plan aligned with current implementation—migration logic lives in match-function bulk mode and CLI migrate-metadata; script is a thin launcher. Target discovery uses session context (get_project_binaries), not list-project-files from the script. Todos and flow rewritten to match codebase.

**Deepened again:** 2026-03-12 with **repo-research-analyst** and **best-practices-researcher**.  
**Research agents used:** repo-research-analyst (codebase alignment, conventions, current architecture); best-practices-researcher (MCP clients, bulk migration, CLI/env, progress/resumability, error handling).  
**New content:** Best-practices subsection below (MCP session/timeouts/retries, edge cases, performance); reference value of list-functions/list-project-files for other clients; repo conventions consolidated.

### Key improvements (original)

1. **Exact response shapes** from codebase: `list-functions` returns `results` (not `functions`), each item has `name`, `address`; `list-project-files` returns `files` with `name`, `path`, `type` (filter `type != "Folder"` for binaries).
2. **Session and endpoint**: Use `Mcp-Session-Id` from response headers; support both `/mcp` and `/mcp/message` base URLs with normalisation as in [mcp_cli_testing.py](helper_scripts/mcp_cli_testing.py).
3. **Robustness**: Optional retry with backoff for transient tool failures; configurable timeout per tool call; progress output (e.g. every N functions) for long runs.
4. **Edge cases**: Handle empty target list, session expiry, and malformed JSON in tool responses; prefer function name over address for match-function with fallback when name is default/missing.

### Current architecture (implementation reality)

- **Preferred entry**: `uv run agentdecompile-cli migrate-metadata --binary <source> [--target-paths T1 T2] [--limit N]`. Server URL via `--mcp-server-url` or `AGENT_DECOMPILE_MCP_SERVER_URL`.
- **Script**: [helper_scripts/migrate_k1_metadata.py](helper_scripts/migrate_k1_metadata.py) is a **thin launcher**: maps legacy args (e.g. `--server-url`, `--source-path`) to CLI migrate-metadata and sets `AGENT_DECOMPILE_MCP_SERVER_URL`, then runs `python -m agentdecompile_cli.cli migrate-metadata ...`. No MCP HTTP client, no list-functions pagination, no per-function match-function loop in the script.
- **Bulk logic inside match-function**: [getfunction.py](src/agentdecompile_cli/mcp_server/providers/getfunction.py) `_handle_match`: when `targetProgramPaths` is set (or discovered) and **no** `functionIdentifier` is given, it uses `_discover_target_paths(source_path)` (session binaries from `SESSION_CONTEXTS.get_project_binaries`, exclude source, filter by `.exe`/`.dll`/`.so`/`.dylib`), then `_list_source_function_identifiers(program, include_externals, limit)` (Ghidra FunctionManager iteration, name or address per function), then loops each identifier and calls `_handle_match_cross_program`. Response includes `mode: "cross-program-bulk"`, `processedCount`, `resultsByFunction`, `summary.matchesPerTarget` / `summary.errors`.
- **Target discovery**: Done **inside** match-function via `_discover_target_paths()` (session context), not by the script or CLI calling list-project-files. Session must already have project binaries (user opened project via MCP or prior tool-seq).

---

# K1 match-function bulk migration

## What we're building (current state)

A **bulk metadata migration** path that:

1. **Preferred**: Run `agentdecompile-cli migrate-metadata --binary <source>` against an already-running MCP server whose session has the project open (e.g. `/K1/k1_win_gog_swkotor.exe` and other binaries).
2. **Alternative**: Run `helper_scripts/migrate_k1_metadata.py --server-url <url> --source-path <path>` for backward compatibility; the script invokes the CLI migrate-metadata command with mapped arguments.
3. **Under the hood**: One **match-function** call with no `functionIdentifier`; the tool discovers targets from session (or uses `targetProgramPaths` if provided), lists all source function identifiers via `_list_source_function_identifiers`, then for each function calls `_handle_match_cross_program` (propagate name, comments, tags, prototype, bookmarks; checkout/apply/checkin once per target per function in [getfunction.py](src/agentdecompile_cli/mcp_server/providers/getfunction.py)).
4. **No script-side** list-functions pagination or per-function match-function HTTP loop; progress and summary come from the single match-function bulk response (and CLI output).

**Scope**: Script = launcher only. Bulk iteration, target discovery, and checkin behavior are in [getfunction.py](src/agentdecompile_cli/mcp_server/providers/getfunction.py) and [cli.py](src/agentdecompile_cli/cli.py) migrate_metadata.

---

## Why this approach

- **match-function bulk mode**: When `targetProgramPaths` is set (or discovered) and `functionIdentifier` is omitted, getfunction.py iterates all source functions and matches each to targets, with one checkin per target per function. So a single tool call does the full migration; no need for the script to paginate list-functions or call match-function per function.
- **CLI migrate-metadata**: Exposes match-function with `programPath`, optional `targetProgramPaths`, `limit`, `includeExternals`, all `propagate`* flags, and **no** functionIdentifier. Single async tool call; CLI passes through to MCP server.
- **Thin script**: Keeps backward compatibility for users who ran a script with `--server-url` and `--source-path`; it sets env and forwards to the CLI so one code path (match-function bulk) is used everywhere.

---

## Key decisions


| Decision                             | Rationale                                                                                                                                                                                                                  |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bulk iteration inside match-function | Single MCP round-trip for “migrate all”; avoids payload size and session limits from scripting thousands of match-function calls.                                                                                          |
| Target discovery from session        | match-function uses `SESSION_CONTEXTS.get_project_binaries(session_id)` (populated by open-project/import), filters by binary extension and excludes source path. Script/CLI do not call list-project-files for discovery. |
| Script as launcher                   | Aligns with repo pattern: helper_scripts run CLI or external tools (e.g. mcp_cli_testing.py, run_live_agdec_http_test.py). No duplicate MCP HTTP client in migrate_k1_metadata.py.                                         |
| Prefer CLI migrate-metadata          | Canonical entry point; script docstring and USAGE.md direct users to `agentdecompile-cli migrate-metadata --binary <path>`.                                                                                                |
| includeExternals default             | CLI defaults to true; match-function bulk uses it when listing source identifiers.                                                                                                                                         |


---

## Implementation plan (aligned with codebase)

### 1. Script: helper_scripts/migrate_k1_metadata.py

- **Role**: Backward-compatible launcher. Map script argv to `agentdecompile-cli migrate-metadata` and set `AGENT_DECOMPILE_MCP_SERVER_URL` from `--server-url`.
- **Arg mapping** (from script → CLI): `--server-url` → set env only; `--source-path` → `--binary`; `--target-paths` → multiple `--target-paths`; `--limit`, `--min-similarity` → pass through; `--include-externals` / `--no-include-externals` → pass through; `--dry-run` → `--limit 0`; `--verbose` → `--verbose`.
- **Flow**: No session setup, no list-functions, no match-function loop in script. Build `out` args and run `sys.executable -m agentdecompile_cli.cli migrate-metadata *out` with `os.environ` (so env server URL is picked up by CLI’s `resolve_backend_url`).
- **Dependencies**: stdlib only (os, subprocess, sys). No httpx in this script.

### 2. CLI: migrate-metadata command

- **Location**: [cli.py](src/agentdecompile_cli/cli.py) around lines 2248–2300.
- **Behavior**: Build payload with `programPath` (from `--binary`/`--source-path`), optional `targetProgramPaths`, `limit`, `includeExternals`, all `propagate`* flags, `minSimilarity`. **Omit** `functionIdentifier` so match-function runs in bulk mode. Call `_call(ctx, ToolName.MATCH_FUNCTION.value, **payload)` via `_run_async`.

### 3. match-function bulk mode (getfunction.py)

- **Entry**: `_handle_match` in [getfunction.py](src/agentdecompile_cli/mcp_server/providers/getfunction.py). When `resolved_targets` is non-empty and `func_id` is falsy (no functionIdentifier), bulk path runs.
- **Target discovery**: `_discover_target_paths(source_path)` (lines 511–528): `SESSION_CONTEXTS.get_project_binaries(session_id, fallback_to_latest=True)`; exclude source; filter `type != "Folder"` and path ending in `.exe`/`.dll`/`.so`/`.dylib`.
- **Function list**: `_list_source_function_identifiers(program, include_externals, limit)` (lines 531–550): iterate `fm.getFunctions(include_externals)`, use name if non-default else address.
- **Loop**: For each identifier, `_resolve_function` then `_handle_match_cross_program`; aggregate `resultsByFunction`, `errors_count`, `matches_per_target`. Return `mode: "cross-program-bulk"` with `processedCount`, `resultsByFunction`, `summary`.

### 4. list-functions / list-project-files (reference only)

- **list-functions**: Used by other workflows; returns `results`, `hasMore`, `count`, `total`, etc. (tool_providers._create_paginated_response). **Not used by the migration script or by match-function bulk**; bulk mode uses Ghidra FunctionManager directly via `_list_source_function_identifiers`.
- **list-project-files**: Returns `files` with `name`, `path`, `type`. **Not called by migrate-metadata or the script**; match-function uses session context (get_project_binaries) which is populated when the user opens the project.

### 5. Error handling and idempotency

- **Per-function errors**: Handled inside match-function bulk loop (try/except, append to resultsByFunction, increment errors_count); no abort. Script/CLI do not implement `--continue-on-error`; the tool always continues.
- **Idempotency**: Re-running migrate-metadata is safe; match-function overwrites/sets metadata to match source.

### 6. Documentation

- **Script docstring**: States that the script is a launcher; preferred command is `uv run agentdecompile-cli migrate-metadata --binary <path>`; for shared projects, open project first then run migrate-metadata.
- **USAGE.md**: Mention bulk migration via script and preferred CLI command; correct description (script calls CLI; migration runs in match-function bulk), and remove any claim that the script “calls match-function for every function” or “discovers targets from list-project-files” (target discovery is in-session inside match-function).

### 7. Testing

- **Dry-run**: Script `--dry-run` → CLI `--limit 0`; match-function bulk runs but processes 0 functions (good for “discover targets only” behavior).
- **Small run**: `--limit 2` with one target; match-function bulk processes 2 functions; checkin once per target per function in shared project.
- **Manual**: K1 project with 2–3 binaries, small `--limit` to confirm propagation.

---

## Research insights (best practices)

*Applicable to any MCP HTTP client (e.g. mcp_cli_testing.py, future scripts) and to long-running tool chains; match-function bulk runs server-side so the script/CLI do not implement these directly.*

### MCP session, timeouts, retries

- **Session**: Use `Mcp-Session-Id` (or `mcp-session-id`) from response headers; send on all subsequent requests. On HTTP 404, treat as session invalid; re-initialize or exit with “Session expired; re-open project and re-run.” (MCP spec; bridge.py, mcp_cli_testing.py.)
- **URL**: Normalize base URL—if path does not end with `/mcp` or `/mcp/message`, append `/mcp/message`; optionally try without `/message` on 404.
- **Timeouts**: Prefer separate connect (e.g. 10–30s) and read (e.g. 60–120s for heavy tools). Use per-request override for match-function. (HTTPX Timeout; bridge.py.)
- **Retries**: Retry only transient conditions (5xx, 408, 429, connection/timeout). Do not retry 4xx or tool-level “function not found” / “no match.” Use exponential backoff with jitter; cap delay (e.g. 30–60s) and max attempts (e.g. 3–5).

### Bulk migration and idempotency

- **Chunking**: Server-side pagination (offset/limit until `hasMore` false) when listing; match-function bulk does this internally via FunctionManager. No need for script to hold full function list when using bulk tool.
- **Idempotency**: Re-running migrate-metadata is safe; match-function overwrites/sets metadata; document “safe to run multiple times” in script/CLI docs.
- **Target discovery**: Prefer session/project listing + filter (e.g. `type != "Folder"`, binary extensions). Allow CLI override (`--target-paths`) for tests and partial runs.

### CLI and env

- **Config precedence**: CLI args override env; env overrides defaults. Use `default=os.environ.get("AGENT_DECOMPILE_MCP_SERVER_URL")` so `--server-url` is optional when set. After parse, if URL still empty, exit with usage message.
- **Documentation**: Document every env var (name, purpose, example) in script docstring or USAGE.md.

### Progress and resumability (reference)

- **Progress**: For long loops, log every N items (e.g. 50–100) with current/total (e.g. “Processed 500/2500 functions”); optional `--verbose` per item. match-function bulk returns one response with `processedCount` and `summary`; CLI formats it.
- **Resume**: For very large runs, optional `--resume-from <index-or-name>` and/or checkpoint file so re-run skips already-done work; not implemented in current script/CLI (single bulk call).

### Error handling

- **Transient vs permanent**: Retry 5xx, 408, 429, connection/timeout; do not retry 4xx or “function not found” / “no match.” Exponential backoff with jitter.
- **Malformed JSON**: When parsing tool result, wrap in try/except; on decode failure log raw snippet and count as error; continue if tool supports continue-on-error (match-function bulk always continues per function).
- **Session expiry**: On repeated 404/session invalid, re-initialize once or exit with clear message.

### Performance and robustness

- **Connection reuse**: One HTTP client and one session ID for the whole run (CLI/client); reuse for all tool calls.
- **Memory**: Pagination (or server-side iteration in bulk) avoids loading full function list in client when using list-functions elsewhere.
- **Logging**: Use stderr for progress so stdout can be used for machine-readable output (e.g. `--json-summary` if added).

### Edge cases (handling)


| Edge case                              | Handling                                                                                                                      |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Empty target list                      | match-function bulk: after discovery, if no targets, raise “No target programs…”. Script/CLI: session must have project open. |
| Session expired (404)                  | Client: re-initialize once; if still 404, exit with “Session expired; re-open project and re-run.”                            |
| list-functions returns empty           | N/A for bulk (tool uses FunctionManager). For other clients: loop runs 0 times; summary “0 processed” is correct.             |
| match-function “no match” for a target | Count as no-match for that (function, target); do not retry; continue (bulk does this).                                       |
| Malformed JSON in tool result          | try/except around parse; log raw snippet; count as one error; continue if continue-on-error.                                  |
| Function identifier (single-function)  | Prefer name from list-functions; if name empty or default (e.g. FUN_00401234), use address. Bulk does not pass identifier.    |
| Very long run (hours)                  | Progress every N; optional checkpoint and resume (not in current design; single bulk call).                                   |


---

## Repo conventions to reflect

- **helper_scripts**: Client-side or test utilities; may invoke CLI (`python -m agentdecompile_cli.cli`) or curl/httpx (mcp_cli_testing.py). Scripts do not duplicate MCP tool logic.
- **CLI**: Uses `resolve_backend_url` (env `AGENT_DECOMPILE_MCP_SERVER_URL` or `--mcp-server-url`/`--server-url`), `get_client`, `_call` for tool invocation. Tool names from `ToolName` (e.g. `ToolName.MATCH_FUNCTION.value`).
- **Session**: Session context in [session_context.py](src/agentdecompile_cli/mcp_server/session_context.py); `get_project_binaries(session_id)` used by match-function and list-project-files path in project provider. Project must be opened before migrate-metadata so session has binaries.
- **Naming**: Prefer canonical tool names (e.g. `match-function`, `list-functions`) in docs; CLI commands may differ (e.g. `migrate-metadata`).

---

## Open questions (resolved or optional)

1. **Project bootstrap**: Resolved—user opens project first (MCP or tool-seq); script does not call open-project. Document in USAGE.md.
2. **Target discovery**: Resolved—match-function uses session binaries (get_project_binaries), not list-project-files from the client. Binary filter in getfunction: `.exe`, `.dll`, `.so`, `.dylib`.
3. **Function identifier in bulk**: N/A—bulk mode does not pass functionIdentifier; tool iterates internally. Single-function mode uses name or address (getfunction uses same _resolve_function / name-vs-address logic).

---

## Files (current)


| Path                                                                                                                     | Role                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| [helper_scripts/migrate_k1_metadata.py](helper_scripts/migrate_k1_metadata.py)                                           | Thin launcher: env + argv → `agentdecompile_cli.cli migrate-metadata`.                                            |
| [src/agentdecompile_cli/cli.py](src/agentdecompile_cli/cli.py)                                                           | `migrate_metadata` command: build match-function payload without functionIdentifier, call tool.                   |
| [src/agentdecompile_cli/mcp_server/providers/getfunction.py](src/agentdecompile_cli/mcp_server/providers/getfunction.py) | match-function bulk: _discover_target_paths, _list_source_function_identifiers, loop _handle_match_cross_program. |
| [USAGE.md](USAGE.md)                                                                                                     | One-line bulk migration; prefer CLI and correct “who does what” (script vs tool).                                 |


---

## Success criteria (updated)

- Preferred: `uv run agentdecompile-cli migrate-metadata --binary /K1/k1_win_gog_swkotor.exe` runs against a live server with that project open and propagates to other session binaries.
- Script: `uv run python helper_scripts/migrate_k1_metadata.py --server-url http://127.0.0.1:8080 --source-path /K1/k1_win_gog_swkotor.exe` behaves the same (forwards to CLI).
- Dry-run: `--dry-run` (script) or `--limit 0` (CLI) results in match-function bulk with 0 functions processed; no errors if session has targets.
- With `--limit 2` and one target, match-function bulk processes 2 functions; summary shows processed count and matches per target; checkin once per target per function in versioned project.
- Summary output from match-function (and CLI) shows processedCount, summary.processed, summary.errors, summary.matchesPerTarget.

