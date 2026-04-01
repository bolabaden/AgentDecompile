# E2E: Shared + local checkout/checkin, persistence, sync-project

This runbook matches the intended behavior: **three checkout → edit → checkin cycles** per mode (shared and local), **MCP server restart** then **assert** renames/labels still exist, and **`sync-project`** pull/push (shared ↔ local) in a valid session.

## Prerequisites

1. **Ghidra repository server** running (e.g. `ghidraSvr.bat console` from `GHIDRA_INSTALL_DIR\server`, or `ghidraSvr.bat start` elevated) and a repository (e.g. `agentrepo`).
2. **Windows port clash:** if the server fails to bind **13101** (`BindException: Address already in use`), set an alternate RMI/registry base in `server\server.conf` (e.g. `-p23100` in the server command args) and pass **`-GhidraPort 23100`** to the PowerShell runner (and matching `serverPort` in `open` / CLI) so the client matches the running server.
3. **Port open ≠ repository ready:** a TCP probe (e.g. `Test-NetConnection` to **13100**) can succeed while the Ghidra **repository** client still gets **`ConnectException` / `NotConnectedException`** (wrong process on the port, firewall, or server still starting). Confirm with **`ghidraSvr`** logs and a real **`open`** from the CLI; match **`serverPort`** to the running server’s **`-p`** / registry base.
4. **`GHIDRA_INSTALL_DIR`** set; **`agentdecompile-server`** (or your MCP backend) reachable.
5. **Same `--server-url`** for every CLI step so **`mcp-session-id`** is reused ([AGENTS.md](../AGENTS.md) § Session and proxy behavior). If you use **agentdecompile-proxy**, it must **forward `mcp-session-id`** to the backend.
6. **`tool-seq`** can load steps from a file: `tool-seq @path\to\steps.json` (required for the PowerShell runner on Windows). A step is treated as **failed** if the MCP payload has **`isError: true`**, embedded JSON with **`success: false`** and an **`error`** field, or markdown text content that begins with **`## Error`** (blockquote-style tool errors) or contains **`## Modification conflict`**. The command exits **non-zero** if any step fails (or the first failure unless **`--continue-on-error`**). With **`--continue-on-error`**, later steps still run but the process **exits 1** if any step failed.

7. The **PowerShell E2E script** checks **`$LASTEXITCODE`** after each **`tool-seq`** and **throws** on failure so automation does not report success when the CLI failed.

**Local project directory:** `open` with a **directory** path creates or opens **`{dirname}\{dirname}.gpr`** so imports and edits target that project (not the server’s default `--project-path`). The script normalizes **`-LocalProjectDir`** to forward slashes inside JSON on Windows.

## What the automation does

| Goal | How |
|------|-----|
| Shared: 3 cycles | `checkout-program` → `manage-function` rename **or** `create-label` → `checkin-program` (×3) |
| Local: 3 cycles | Same pattern; `checkin-program` triggers **local save** for non-versioned `.gpr` |
| Persistence | After **restarting only `agentdecompile-server`**, run **`restart_assert`** (shared) or **`restart_local_assert`** (local) — uses `get-function` / `search-symbols` |
| Sync | **`sync-project`** `pull` / `push` with **`dryRun: true`** then **`false`**; needs **shared session + local `project_data`** — run **in the same MCP session** as `open` + `import-binary` |

**Important:** In-memory MCP session is lost when the backend process restarts. **Restarting the MCP server requires `open` again** before asserts; Ghidra Server / repository data should still hold checked-in versions.

**Shared E2E first:** **`shared_plus_sync`** needs the **Ghidra repository server listening** on the host/port you pass (e.g. `127.0.0.1:23100`). If `open` fails with “server not reachable”, fix Ghidra first — do not rely on a merged run: an existing MCP session may still have a **local** project open, so later steps can look like shared (errors, wrong symbols). Prefer **restarting `agentdecompile-server`** (or a **fresh `mcp-session-id`**) before a shared run after doing local E2E on the same backend.

## PowerShell runner (recommended)

From repo root:

```powershell
# 1) Shared: open + import + 3 cycles + sync (single tool-seq / one MCP session)
.\scripts\e2e_checkout_sync_plan_runner.ps1 -Phase shared_plus_sync `
  -ServerUrl http://127.0.0.1:8080 `
  -Repo agentrepo -GhidraHost 127.0.0.1 -GhidraPort 13100 `
  -GhidraUser ghidra -GhidraPassword admin `
  -ProgramPath /sort.exe `
  -FunCycle1 FUN_140001010 -LabelAddress 140001020 -FunCycle3 FUN_140001140

# Optional: -AnalyzeAfterImport if your binary needs analysis for stable FUN_* names
# Optional: -ContinueOnError to run every tool-seq step even after a failure (CLI still exits non-zero)

# 2) Stop and start agentdecompile-server (not necessarily Ghidra Server)

# 3) Assert persistence (shared)
.\scripts\e2e_checkout_sync_plan_runner.ps1 -Phase restart_assert -ServerUrl http://127.0.0.1:8080 `
  -Repo agentrepo -GhidraHost 127.0.0.1 -GhidraPort 13100 `
  -GhidraUser ghidra -GhidraPassword admin -ProgramPath /sort.exe
```

**Local `.gpr`:**

```powershell
.\scripts\e2e_checkout_sync_plan_runner.ps1 -Phase local_full -LocalProjectDir C:\temp\e2e_local_gpr
# restart MCP
.\scripts\e2e_checkout_sync_plan_runner.ps1 -Phase restart_local_assert -LocalProjectDir C:\temp\e2e_local_gpr
```

Adjust **`-ProgramPath`**, **`-FunCycle1`**, **`-FunCycle3`**, **`-LabelAddress`** using **`list-project-files`** and **`list-functions`** if `sort.exe` or addresses differ on your OS/binary.

## Code areas (reference)

| Behavior | Primary implementation |
|----------|-------------------------|
| Checkout / checkin / status | `import_export.py` (`_handle_checkout`, `_handle_checkin`, …) |
| Shared repo checkout | `project.py` `_checkout_shared_program` (supports **exclusive** checkout when the Ghidra API allows) |
| Sync pull/push | `project.py` `_sync_shared_repository`, `_pull_shared_repository_to_local`, `_push_local_project_to_shared` |
| Session + paths | `session_context.py` `canonicalize_program_path` |

## Sync-project semantics (short)

- **Pull:** `direction: shared-to-local` when shared session + `project_data` exist.
- **Push:** `direction: local-to-shared` when shared session + `project_data` exist.
- **No shared session:** push may fall back to **`local-save`** (save local project only) — not a server upload.

If you see **`local-project-context-missing`**, run **`open` + `import-binary`** in that session before **`sync-project`**, or use **`-Phase shared_plus_sync`** so everything runs in one connection.

See also [CONTRIBUTING.md](../CONTRIBUTING.md) (Manual E2E) and [AGENTS.md](../AGENTS.md) (session / proxy).
