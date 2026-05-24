# Check-in / Check-out / Status Implementation Investigation

**Date**: 2026-03-12  
**Scope**: Determine if version-control operations (check-in, check-out, status, undo checkout, add to version control, update/merge) are fully implemented and aligned with Ghidra/PyGhidra documentation.

---

## 1. Ghidra documentation (version control)

From [Ghidra Project Repository](https://www.ghidradocs.com/12.0.4_PUBLIC/help/Base/help/topics/VersionControl/project_repository.htm):

| Feature | Description |
|--------|-------------|
| **Check Out** | Select file → Check Out; optional **exclusive lock** for memory-map changes. Non-shared projects get exclusive implicitly. |
| **Check In** | After changes, Check In with **comment**; creates new version. Option **Keep File Checked Out**; option **Create ".keep" file**. |
| **Undo Checkout** | Revert local changes, file goes back to latest server version. Option to create `.keep` copy. File must be closed first. |
| **Update** | (Shared only) Bring working copy in sync with latest version on server; may require **merge** if others checked in. |
| **Add to Version Control** | Add private file to version control (comment, Keep File Checked Out). |
| **View Checkouts** | See who has a file checked out (checkout date, version). Admin can **Terminate Checkout**. |
| **Show Version History** | History of versions (date, user, comments). **View Version** opens a specific version read-only. |
| **Undo Hijack** | When local private file conflicts with same-named versioned file (e.g. after terminated checkout). |

API-wise (DomainFile / PyGhidra):

- `checkout(boolean exclusive, TaskMonitor monitor)`
- `checkin(CheckinHandler checkinHandler, TaskMonitor monitor)`
- `canCheckout()` / `canCheckin()` / `isCheckedOut()` / `isCheckedOutExclusive()`
- `getCheckoutStatus()` → checkout id, user, version, time
- `undoCheckout(keep, force)` (Undo Checkout)
- `addToVersionControl(comment, keepCheckedOut, monitor)` (Add to version control)
- `unhijack(force)` (Undo Hijack)

---

## 2. Codebase implementation map

### 2.1 Canonical MCP tools (user-facing)

| Tool | Provider | Handler | Notes |
|------|----------|---------|--------|
| **checkin-program** | `ImportExportToolProvider` | `_handle_checkin` | Full: comment, keepCheckedOut, CheckinHandler, checkin-all when no programPath |
| **checkout-program** | `ImportExportToolProvider` | `_handle_checkout` | Full: exclusive, DomainFile.checkout(), already-checked-out handling |
| **checkout-status** | `ImportExportToolProvider` | `_handle_checkout_status` | Full: is_versioned, is_checked_out, is_exclusive, modified_since_checkout, can_checkout/can_checkin, latest/current version, **getCheckoutStatus()** (checkout_id, user, checkout_version, checkout_time) |

All three live in **`src/agentdecompile_cli/mcp_server/providers/import_export.py`**. They operate on the **active program** (or session’s open programs for checkin-program with no args). They use:

- `program.getDomainFile()`
- `domain_file.checkout(exclusive, TaskMonitor.DUMMY)`
- `domain_file.checkin(CheckinHandler, TaskMonitor.DUMMY)` with a small `_SimpleCheckinHandler` (getComment, keepCheckedOut, createKeepFile=False)
- `domain_file.getCheckoutStatus()` for checkout-status

So **check-in**, **check-out**, and **status** are fully implemented for the active/session program context and match Ghidra’s DomainFile API.

### 2.2 manage-files (project-level operations)

In **`src/agentdecompile_cli/mcp_server/providers/project.py`**:

| Operation | Handler | Implementation |
|-----------|---------|-----------------|
| **checkout** | `_handle_checkout` | Resolves domain file by programPath → `domain_file.checkout(exclusive, TaskMonitor.DUMMY)` |
| **uncheckout** | `_handle_uncheckout` | Resolves domain file → `domain_file.undoCheckout(keep, force)` |
| **unhijack** | `_handle_unhijack` | Resolves domain file → `domain_file.unhijack(force)` |

These are invoked via **manage-files** with `mode=checkout`, `mode=uncheckout`, `mode=unhijack`. So **Undo Checkout** and **Undo Hijack** are implemented; they are just exposed under manage-files, not as separate top-level tools.

### 2.3 Shared repository checkout (open from server)

**`ProjectToolProvider._checkout_shared_program`** (project.py) checks out a program **from a shared Ghidra server** into the local project:

- Uses `RepositoryAdapter.getItem()`, `project_data.getFile()` / `createFile()`, `GhidraProject.openProgram()` or ProgramDB fallback.
- Used when connecting to a shared server and opening a repository path (e.g. connect-shared-project with path, or program activation by path).

This is the “check out from server into local project” flow, not the per-file DomainFile checkout/checkin. It is implemented and used for shared-server workflows.

### 2.4 sync-project

**`ProjectToolProvider._handle_sync_project`** / **`_sync_shared_repository`** implement **sync-project** (pull/push/bidirectional) between local project and shared repository. This is the transfer/sync of repository content, not the single-file “Update” (merge latest version into current working copy). So:

- **sync-project** = transfer/sync of files (pull/push/bidirectional) — **implemented**.
- **Update** (Ghidra’s “update working copy to latest version”, with merge) = **not** exposed as a dedicated tool (no “update-program” or “merge-latest” that calls DomainFile update/merge APIs).

### 2.5 Add to version control

Ghidra’s **Add to Version Control** is `DomainFile.addToVersionControl(comment, keepCheckedOut, monitor)`. In the codebase:

- **Not** implemented as a dedicated MCP tool (no `add-to-version-control` or similar).
- **import-binary** has `enableVersionControl`; when true and in a shared context, the code returns an error that automatic promotion of local import into shared version control is not implemented. So “add existing private file to version control” is **not** offered as a first-class tool.

### 2.6 Version history / View version / View checkouts

- **Show Version History** (list versions, open a specific version read-only): not implemented as MCP tools.
- **View Checkouts** (who has file checked out; admin terminate): not implemented.  
Checkout-status exposes **current file’s** checkout state (and getCheckoutStatus), not “list all checkouts” or “terminate checkout”.

### 2.7 Auto-match worker (internal use)

**`auto_match_worker.py`** uses checkout/checkin for propagation:

- Checks out target if versioned and not already checked out (`domain_file_tgt.checkout(False, TaskMonitor.DUMMY)`).
- After propagation, checkin with `CheckinHandler` (comment, keepCheckedOut based on whether we did the checkout). So internal automation correctly uses the same DomainFile checkout/checkin APIs.

---

## 3. Summary table (vs Ghidra docs)

| Ghidra feature | Implemented in codebase? | Where |
|----------------|--------------------------|--------|
| Check Out | Yes | checkout-program (import_export), manage-files mode=checkout (project) |
| Check In | Yes | checkin-program (import_export), incl. checkin-all and CheckinHandler |
| Checkout status (single file) | Yes | checkout-status (import_export), incl. getCheckoutStatus() |
| Undo Checkout | Yes | manage-files mode=uncheckout (project), DomainFile.undoCheckout |
| Undo Hijack | Yes | manage-files mode=unhijack (project), DomainFile.unhijack |
| Exclusive checkout | Yes | checkout-program exclusive flag, DomainFile.checkout(exclusive, …) |
| Comment / Keep checked out | Yes | checkin-program comment, keepCheckedOut, CheckinHandler |
| Shared-server checkout (open from repo) | Yes | _checkout_shared_program (project), connect-shared-project flow |
| Sync project (pull/push/bidirectional) | Yes | sync-project (project) |
| Add to version control | No | No tool; import-binary enableVersionControl explicitly unsupported |
| Update (merge latest into working copy) | No | No “update-program” / merge tool |
| Show version history / View version | No | No tool |
| View checkouts (list who has what) | No | No tool; only single-file status |
| Terminate checkout (admin) | No | No tool |

---

## 4. Conclusion

- **Check-in, check-out, and status** are fully implemented for the active/session program and are consistent with Ghidra’s Project Repository and DomainFile APIs. They are exposed as **checkin-program**, **checkout-program**, and **checkout-status** (ImportExportToolProvider) and use the same APIs as in Ghidra docs (checkout, checkin with CheckinHandler, getCheckoutStatus, etc.).
- **Undo checkout** and **undo hijack** are fully implemented via **manage-files** with `mode=uncheckout` and `mode=unhijack` (ProjectToolProvider).
- **Shared repository checkout** (open program from server) and **sync-project** are implemented.
- **Not implemented** as MCP tools: **Add to version control**, **Update** (merge latest), **Show version history / View version**, **View checkouts** (list/terminate). These are the main gaps relative to the full Ghidra version-control UI feature set.

No PyGhidra-specific deviations were found; the code uses the same DomainFile/CheckinHandler/TaskMonitor APIs that Ghidra documents and that PyGhidra exposes in headless scripts.
