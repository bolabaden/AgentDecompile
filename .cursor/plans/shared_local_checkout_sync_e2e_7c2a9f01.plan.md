---
name: Shared/local checkout-checkin + sync E2E
overview: Verify shared Ghidra server projects and local .gpr projects both support checkout/checkin with real edits (rename/label), persistence after MCP server restart, and sync-project pull/push. Optional code hardening from code review (exclusive checkout, honest check-in-all, push transaction policy).
todos:
  - id: verify-shared-three-cycles
    content: "E2E: shared open → 3× (checkout → rename or label → checkin) → list-project-files; use tool-seq + same --server-url"
    status: completed
  - id: verify-shared-restart
    content: Restart agentdecompile-server only; reopen shared; checkout; assert renames/labels via get-function or search-symbols
    status: completed
  - id: verify-local-three-cycles
    content: "E2E: open local .gpr → 3× (edit → checkin-program or save path) → list-project-files"
    status: completed
  - id: verify-local-restart
    content: Restart MCP server; reopen same local project; assert edits persist
    status: completed
  - id: verify-sync-pull
    content: sync-project mode=pull (dryRun true then false); confirm shared-to-local transferred/skipped in response
    status: completed
  - id: verify-sync-push
    content: sync-project mode=push (dryRun true then false); confirm local-to-shared / save semantics in response
    status: completed
  - id: optional-exclusive-checkout
    content: (Optional) Thread exclusive flag into _checkout_shared_program / RepositoryAdapter.checkout
    status: completed
  - id: optional-checkin-all-versioned
    content: "(Optional) checkin all: do not report save_local success when versioned and not canCheckin"
    status: completed
  - id: optional-push-tx-policy
    content: (Optional) Document or narrow endTransaction(commit) during sync-project push
    status: completed
isProject: false
---

# Plan: Shared + local checkout/checkin, persistence, sync-project

## Goals

1. **Shared** and **local** projects both work with `checkout-program` / `checkin-program` / `checkout-status` where applicable.
2. **Three successive cycles** per mode: checkout → **rename function** or **set label** → checkin (shared) or checkin/save (local).
3. **Restart** the **MCP server** (agentdecompile-server), reopen project, **assert** edits still visible (persistence on Ghidra side, not in-memory session).
4. `**sync-project`**: **pull** (shared → local) and **push** (local changes into shared-backed workflow / save), including `**dryRun: true`** first.

## Preconditions

- **Ghidra Server** running (e.g. `ghidraSvr.bat` on Windows per project docs); repository exists (e.g. `agentrepo`).
- `**GHIDRA_INSTALL_DIR`** set; `**uv run agentdecompile-server**` (or equivalent) for MCP.
- **Same `--server-url`** for all steps in a run so CLI persists `**mcp-session-id**` ([AGENTS.md](AGENTS.md)); if using **proxy**, it must **forward** session id to backend ([fix_shared_project_cli_persistence_b811ed58.plan.md](fix_shared_project_cli_persistence_b811ed58.plan.md)).
- Use `**programPath`** values from `**list-project-files**` after import/open (canonical casing; code also **canonicalizes** via [session_context.py](src/agentdecompile_cli/mcp_server/session_context.py) `canonicalize_program_path`).

## Implementation map (reference)


| Concern                           | Primary code                                                                                                                                                                                  |
| --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Checkout / checkin / status       | [import_export.py](src/agentdecompile_cli/mcp_server/providers/import_export.py) `_handle_checkout`, `_handle_checkin`, `_handle_checkout_status`, `_resolve_domain_file_for_checkout_status` |
| Path canonicalization             | [session_context.py](src/agentdecompile_cli/mcp_server/session_context.py) `canonicalize_program_path`                                                                                        |
| Shared repo checkout              | [project.py](src/agentdecompile_cli/mcp_server/providers/project.py) `_checkout_shared_program`                                                                                               |
| Checkout reclaim (foreign holder) | [import_export.py](src/agentdecompile_cli/mcp_server/providers/import_export.py) `_ensure_versioned_file_ready_for_checkin`                                                                   |
| Sync pull/push                    | [project.py](src/agentdecompile_cli/mcp_server/providers/project.py) `_sync_shared_repository`, `_pull_shared_repository_to_local`, `_push_local_project_to_shared`                           |


## Phase A — Shared project: three cycles + edits

Run as **one `tool-seq`** (or one HTTP session with stable session id).

1. `**open**` — `shared: true`, `path` / repository, `serverHost`, `serverPort`, `serverUsername`, `serverPassword`.
2. `**list-project-files**` — pick `programPath` `P` (e.g. import `sort.exe` first if repo empty).
3. **Cycle 1:** `checkout-program` `programPath: P` → `**manage-function`** `mode=rename` (valid address) → `**checkin-program**` `programPath: P`, `comment: cycle-1`.
4. **Cycle 2:** `checkout-program` `programPath: P` → `**create-label`** or `**manage-symbols**` → `**checkin-program**` `comment: cycle-2`.
5. **Cycle 3:** `checkout-program` → another edit → `**checkin-program`** `comment: cycle-3`.
6. `**list-project-files**` — confirm program still listed.

**Assertions:** Each step returns `success` where expected; `checkout-status` after checkout shows checked out; after checkin, state matches expectations (not checked in vs kept checked out per flags).

## Phase B — Persistence after MCP restart (shared)

1. Stop **agentdecompile-server** (not necessarily Ghidra Server).
2. Start server again; **same** `--server-url` so CLI reuses session if configured.
3. `**open`** (same shared args).
4. `**checkout-program**` `P` (or path from `list-project-files`).
5. `**get-function**` / `**search-symbols**` / `**decompile-function**` — **assert** renamed symbols / labels from phases A1–A3.

## Phase C — Local project: three cycles + edits

1. `**open`** with **local** project path (`.gpr` or directory per launcher).
2. `**list-project-files`** → pick `L`.
3. Three cycles: edits + `**checkin-program**` with `programPath: L` (non-versioned projects may **save** locally; versioned local mirrors shared flow).
4. Restart MCP server; `**open`** same path; assert edits.

## Phase D — sync-project

**Requires** active **shared** session **and** resolvable **local** `project_data` (open local project or same session setup as `_sync_shared_repository` expects — see [project.py](src/agentdecompile_cli/mcp_server/providers/project.py) prerequisite checks).

1. `**sync-project`** `mode: pull` (or `download`), `**dryRun: true**` — inspect planned items / errors.
2. `**sync-project**` `mode: pull`, `**dryRun: false**` — expect `direction: shared-to-local` (or equivalent in payload).
3. `**sync-project**` `mode: push` (or `upload`), `**dryRun: true**` then `**false**` — expect `direction: local-to-shared` or documented save-only behavior.

## Phase E — Optional code hardening (code-reviewer)


| Item                                       | Action                                                                                                                    |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `exclusive` ignored on shared checkout     | Pass `exclusive` into `_checkout_shared_program`; use Ghidra exclusive checkout type if API allows.                       |
| Check-in all + versioned + `!canCheckin()` | Avoid reporting `save_local` + success as server check-in; return failure or explicit warning with checkout holder hints. |
| Sync push `endTransaction(..., true)`      | Document that push may commit open transactions, or match policy to import_export transaction helpers.                    |


## CLI template (PowerShell)

Replace `P`, server args, and tool payloads (addresses) with real values from your binary.

```powershell
$seq = @'
[
  {"name":"open","arguments":{"shared":true,"path":"REPO","serverHost":"127.0.0.1","serverPort":13100,"serverUsername":"ghidra","serverPassword":"admin"}},
  {"name":"list-project-files","arguments":{}},
  {"name":"checkout-program","arguments":{"programPath":"/P"}},
  {"name":"manage-function","arguments":{"mode":"rename","programPath":"/P","functionIdentifier":"FUN_...","newName":"e2e_cycle1"}},
  {"name":"checkin-program","arguments":{"programPath":"/P","comment":"cycle-1"}},
  {"name":"checkout-program","arguments":{"programPath":"/P"}},
  {"name":"create-label","arguments":{"programPath":"/P","address":"...","labelName":"e2e_l2"}},
  {"name":"checkin-program","arguments":{"programPath":"/P","comment":"cycle-2"}},
  {"name":"checkout-program","arguments":{"programPath":"/P"}},
  {"name":"manage-function","arguments":{"mode":"rename","programPath":"/P","functionIdentifier":"FUN_...","newName":"e2e_cycle3"}},
  {"name":"checkin-program","arguments":{"programPath":"/P","comment":"cycle-3"}},
  {"name":"list-project-files","arguments":{}}
]
'@
uv run python -m agentdecompile_cli.cli --server-url http://127.0.0.1:8080 tool-seq $seq
```

After restart, run a shorter seq: `open` → `checkout-program` → `get-function` / `search-symbols` with identifiers from the renames.

## `/lfg` note

Steps 1–9 in `/lfg` are **Cursor slash workflows** (ralph-loop, workflows:plan, compound-engineering, feature-video, etc.). They must be run **inside Cursor**; this file is the **technical plan** for the shared/local/sync/persistence work those workflows may orchestrate.

## Done criteria

- Shared: 3 edit cycles + checkin succeed in one session.
- Shared: After MCP restart, edits visible.
- Local: 3 cycles + persistence after restart.
- `sync-project` pull and push validated (at least dryRun + one real run each direction).
- Optional: code-reviewer items triaged (implement or document).

