---
name: Two-step modification conflict system
overview: "Introduce an authoritative two-step flow for all tools that modify project data: when a modification would overwrite existing custom data, the tool returns a conflict response with a unique conflictId and a udiff-style summary (markdown); a new tool resolve-modification-conflict is the only way to apply or discard that change using the conflictId."
todos: []
isProject: false
---

# Two-step modification conflict system

## Objective

- **No overwrite by default**: Any tool that would overwrite *custom* (user-defined) data must **not** apply the change immediately. It must return a structured conflict response with a unique **conflictId** (GUID) and a clear **udiff-style** summary in markdown.
- **Apply only via resolution tool**: The **only** way to complete a conflicting modification is to call a new tool `**resolve-modification-conflict`** with that `conflictId` and a resolution choice (e.g. `overwrite` or `skip`).
- **No conflict → immediate success**: If there is no existing custom data at the target (e.g. symbol is `FUN_004173b0`, no comment yet, no structure with that name), the modifying tool succeeds in one step as today.

## Definitions

- **Custom data**: Names/symbols that are not Ghidra default patterns (use existing [SymbolUtil.is_default_symbol_name](src/agentdecompile_cli/mcp_utils/symbol_util.py) and `SourceType.USER_DEFINED` where applicable); existing comments at an address/type; existing bookmarks; existing structures/data types with the same name; existing data at an address.
- **Conflict**: The tool would replace or overwrite such custom data with the requested new value.

## Scope: modifying tools (from [TOOLS_LIST.md](TOOLS_LIST.md) / [registry.py](src/agentdecompile_cli/registry.py))


| Category    | Tool                                                                               | Conflicting cases                                                                |
| ----------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Symbol/name | `manage-symbols`, `create-label`                                                   | Label already at address; renaming a symbol that already has a custom name       |
| Function    | `manage-function` (rename, set_prototype, set_return_type, set_calling_convention) | Current name/signature is already user-defined or non-default                    |
| Comments    | `manage-comments` (set)                                                            | Comment already exists at (address, type) with different text                    |
| Structures  | `manage-structures` (create, apply, modify)                                        | Structure with same name exists; data already at address                         |
| Data types  | `manage-data-types`, `apply-data-type`                                             | Data already at address (different type)                                         |
| Bookmarks   | `manage-bookmarks` (set)                                                           | Bookmark already at (address, type/category)                                     |
| Tags        | `manage-function-tags` (add/set)                                                   | Optional: report no-op if tag already present                                    |
| Versioning  | `checkout-program`, `checkin-program`                                              | Already checked out / merge conflicts (optional two-step)                        |
| Project     | `manage-files` (rename, etc.)                                                      | Target name exists; optional two-step                                            |
| Propagation | `match-function`                                                                   | Target already has custom name/comment/bookmark/signature (per-target, per-kind) |


Exclude from two-step (or treat as already having their own “preview”): `sync-project` (already has `dryRun`/`force`).

## Architecture

```mermaid
flowchart LR
  Client[Client] --> ModTool[Modifying tool]
  ModTool --> Check{Conflict?}
  Check -->|No| Apply[Apply in transaction]
  Check -->|Yes| Store[Store pending by conflictId]
  Store --> Resp[Return conflict response]
  Resp --> Client
  Client --> Resolve[resolve-modification-conflict]
  Resolve --> Lookup[Lookup by conflictId]
  Lookup --> Overwrite[Apply stored op] or Skip[Discard]
  Apply --> Success[Success response]
  Overwrite --> Success
  Skip --> Success
```



## 1. Conflict response shape (when modification would overwrite custom data)

Return a **success=false** or a dedicated **conflict** payload so that format=markdown still renders usefully. Recommended shape (in the JSON body):

- `success`: `false` (or a dedicated `modificationConflict`: `true` so clients can distinguish from hard errors).
- `conflictId`: string (UUID) — **required** for the next step.
- `tool`: canonical tool name that produced the conflict.
- `conflictSummary`: string (markdown) — **udiff-style** text showing what would change (e.g. “current name: `myFunc` → requested: `otherName`” or a short unified-diff block).
- `nextStep`: string (markdown): “To apply this change, call `resolve-modification-conflict` with `conflictId` = `<conflictId>` and `resolution` = `overwrite`. To discard, use `resolution` = `skip`.”

When `format=markdown`, [render_tool_response](src/agentdecompile_cli/mcp_server/response_formatter.py) (or a dedicated conflict renderer) should render `conflictSummary` and `nextStep` prominently so the user/agent sees exactly what to do.

## 2. Pending-modification store (session-scoped)

- **Location**: Session-scoped storage keyed by `(session_id, conflictId)`. Use [session_context](src/agentdecompile_cli/mcp_server/session_context.py) or a new module (e.g. `conflict_store`) that is keyed by `get_current_mcp_session_id()` (already used in [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py)).
- **Stored value**: Enough to re-run the modification when the user chooses “overwrite”:
  - `tool`: str (canonical name)
  - `arguments`: dict (normalized args from the original call)
  - `programPath` (or program key): optional, for program-scoped tools
  - Optional: `summary` (for display) and TTL/expiry to avoid unbounded growth (e.g. 1 hour or 100 entries per session).

When `resolve-modification-conflict` is called with `resolution=overwrite`, the manager looks up the pending modification by `conflictId` (within current session), then **re-invokes the same tool** with the stored arguments plus an **internal flag** (e.g. `__force_apply_conflict_id` = `conflictId` or `forceOverwriteCustom` = true) so the handler **skips** conflict detection and runs the transaction. After a successful apply, remove the pending entry.

## 3. New tool: `resolve-modification-conflict`

- **Name**: `resolve-modification-conflict` (canonical); register in [registry.py](src/agentdecompile_cli/registry.py) (Tool enum + TOOL_PARAMS, aliases if needed).
- **Parameters**:
  - `conflictId` (string, required): The GUID returned in the conflict response. Must be present in the current session’s pending store.
  - `resolution` (string, required): `overwrite` | `skip`. `overwrite` = apply the stored modification; `skip` = discard and remove from store.
  - `programPath` (string, optional): Optional override for program context when resolving (default: use stored program key if any).
- **Behavior**:
  - Look up pending modification by `conflictId` in the current session. If not found, return a clear error (e.g. “Unknown or expired conflictId”).
  - If `resolution` = `skip`: remove pending entry; return success with message “Change discarded.”
  - If `resolution` = `overwrite`: call the stored tool with stored arguments + internal force flag; on success, remove pending and return the inner tool’s success response (or a short “Applied: …” summary); on failure, return error and leave pending for retry or skip.
- **Provider**: Implement in a small new provider (e.g. `conflict_resolution.py`) or inside [tool_providers.py](src/agentdecompile_cli/mcp_server/tool_providers.py) as a special tool that reads from the conflict store and dispatches to `call_tool`. It must **only** be callable when a conflict exists — the conflictId is obtained solely from the output of another tool.

## 4. Per-tool changes (inject conflict detection; two-step only when conflict)

Each modifying tool handler (see repo-research summary for file:handler list) must:

1. **Before** calling `_run_program_transaction` (or equivalent), perform a **read-only** conflict check:
  - **Symbols** ([symbols.py](src/agentdecompile_cli/mcp_server/providers/symbols.py)): For create_label — symbol already at address? For rename — `sym.getSource()` or `SymbolUtil.is_default_symbol_name(sym.getName())`; if custom name exists, conflict.
  - **manage-function** ([getfunction.py](src/agentdecompile_cli/mcp_server/providers/getfunction.py)): For rename — same as symbols; for set_prototype/set_return_type/set_calling_convention — define “custom” (e.g. already USER_DEFINED or non-default signature) and conflict if overwriting.
  - **Comments** ([comments.py](src/agentdecompile_cli/mcp_server/providers/comments.py)): Before set — `listing.getComment(addr, type)`; if non-empty and different from requested text, conflict.
  - **Structures** ([structures.py](src/agentdecompile_cli/mcp_server/providers/structures.py)): create — `_find_structure(dtm, name)`; if found, conflict. apply — `listing.getDataAt(addr)`; if exists and different, conflict.
  - **Data types** ([datatypes.py](src/agentdecompile_cli/mcp_server/providers/datatypes.py), [data.py](src/agentdecompile_cli/mcp_server/providers/data.py)): Before apply — get current data at address; if present and different type, conflict.
  - **Bookmarks** ([bookmarks.py](src/agentdecompile_cli/mcp_server/providers/bookmarks.py)): Before set — get bookmarks at address; if same type/category exists, conflict.
  - **match-function** ([getfunction.py](src/agentdecompile_cli/mcp_server/providers/getfunction.py)): Before each propagation block (name, prototype, tags, comments, bookmarks), check target’s current state; if custom, add to a list of conflicts; optionally return a single conflict payload with multiple items or one conflictId per target/kind.
2. **If conflict detected**:
  - Generate UUID as `conflictId`.
  - Store in session-scoped pending store: `{ conflictId, tool, arguments, programPath }`.
  - Return conflict response (JSON with `conflictId`, `conflictSummary` (udiff-style markdown), `nextStep`). Do **not** call `_run_program_transaction`.
3. **If internal flag** `__force_apply_conflict_id` / `forceOverwriteCustom` is set (only when invoked from `resolve-modification-conflict`): skip conflict check and run the transaction as today.
4. **If no conflict**: current behavior unchanged — run transaction and return success.

## 5. Udiff / conflict summary format (markdown, default)

- **Requirement**: “clear and concise udiff formatted thing in markdown” per tool.
- **Content**: For each conflicting item, a short block showing:
  - **Current (existing custom)** vs **Requested (new)**.
  - Prefer a few lines of unified-diff style (e.g. `- currentName` / `+ requestedName`) or a simple two-line “Current: … / Requested: …” so the agent/user sees exactly what overwriting would do.
- **Placement**: In the `conflictSummary` field of the conflict response; when `format=markdown`, render this in [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) (e.g. new branch in `_render_error` or a dedicated `_render_conflict` that emits the udiff block and the “call resolve-modification-conflict” instruction).

## 6. Documentation and schema

- Add `resolve-modification-conflict` to [TOOLS_LIST.md](TOOLS_LIST.md) with description: “Resolve a modification conflict reported by another tool. Call only when a tool returned a conflictId; use resolution=overwrite to apply the change or resolution=skip to discard.”
- Document the two-step flow in AGENTS.md or TOOLS_LIST.md: “Tools that modify project data may return a conflict when the change would overwrite custom data. In that case, use the returned conflictId with resolve-modification-conflict to overwrite or skip.”
- Add `conflictId` and `resolution` to TOOL_PARAMS for the new tool in [registry.py](src/agentdecompile_cli/registry.py).

## 7. Implementation order (suggested)

1. **Conflict store** (session-scoped dict or attached to session context) and **resolve-modification-conflict** tool (registry + handler that looks up, then either skips or re-calls tool with force flag).
2. **One modifying tool end-to-end** (e.g. `manage-symbols` rename): conflict detection, conflict response with conflictId + udiff-style summary, force flag path, and resolve-modification-conflict applying it.
3. **Response formatter**: render conflict response in markdown (conflictSummary + nextStep).
4. **Remaining modifying tools**: add conflict detection and same response shape (symbols create_label, manage-function, manage-comments, manage-structures, manage-data-types, apply-data-type, manage-bookmarks, manage-function-tags, match-function, and optionally manage-files / checkout/checkin).
5. **Tests**: unit tests for conflict detection (custom vs default name, existing comment, etc.), and for resolve-modification-conflict (overwrite/skip, unknown conflictId, expired).

## Files to touch (summary)

- **New**: `src/agentdecompile_cli/mcp_server/conflict_store.py` (or store in session_context) — pending modifications keyed by (session_id, conflictId).
- **New**: `src/agentdecompile_cli/mcp_server/providers/conflict_resolution.py` — handler for `resolve-modification-conflict` (or fold into tool_providers / project provider).
- **Registry**: [registry.py](src/agentdecompile_cli/registry.py) — add Tool.RESOLVE_MODIFICATION_CONFLICT, TOOL_PARAMS, alias if desired.
- **Modifying providers**: [symbols.py](src/agentdecompile_cli/mcp_server/providers/symbols.py), [getfunction.py](src/agentdecompile_cli/mcp_server/providers/getfunction.py), [comments.py](src/agentdecompile_cli/mcp_server/providers/comments.py), [structures.py](src/agentdecompile_cli/mcp_server/providers/structures.py), [datatypes.py](src/agentdecompile_cli/mcp_server/providers/datatypes.py), [data.py](src/agentdecompile_cli/mcp_server/providers/data.py), [bookmarks.py](src/agentdecompile_cli/mcp_server/providers/bookmarks.py); optionally [import_export.py](src/agentdecompile_cli/mcp_server/providers/import_export.py), [project.py](src/agentdecompile_cli/mcp_server/providers/project.py).
- **Formatting**: [response_formatter.py](src/agentdecompile_cli/mcp_server/response_formatter.py) — conflict response rendering (udiff + nextStep).
- **Docs**: [TOOLS_LIST.md](TOOLS_LIST.md), [AGENTS.md](AGENTS.md).

No changes to the core tool dispatch contract (normalization, HANDLERS, call_tool) beyond adding one new tool and optional internal args for the force-apply path.