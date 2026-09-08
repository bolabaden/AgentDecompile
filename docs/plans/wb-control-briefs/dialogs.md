# Task: Dialogs (open, save-as, confirm)

Write **only** `src/agentdecompile_recovery/corpus/dashboard/static/workbench-dialogs.css`.

Read first: `docs/superpowers/specs/2026-08-31-workbench-control-system-design.md` and tokens/controls.

Classes:
- `.wb-modal-backdrop`, `.wb-modal`, `.wb-modal-head`, `.wb-modal-body`, `.wb-modal-foot`, `.wb-modal-close`
- `.wb-confirm-dialog`, `.wb-confirm-backdrop`
- `.wb-dialog-tabs`, `.wb-open-paste`, `#wb-open-paste`
- `.wb-drop`, `.wb-browse`, `.wb-browse-path`, `.wb-browse-list`, `.wb-browse-item`
- `#wb-save-as-form`, `#wb-shared-form`, `.wb-bin-form`

Feel: Ghidra file dialog. Dim 50% backdrop. Modal 560–720px, no 12px radius. Header is a title bar. Footer right-aligned actions using `.wb-btn`. Path field is the hero control. Browse is a **list or tight grid** of folders with kind-colored left rail (gpr / shared-fs / binary), not rounded cards. Drop zone is dashed inset, not a banner. Confirm danger uses `.wb-btn.danger`.

Do not edit JS. Do not commit.
Report: `docs/plans/wb-control-briefs/dialogs-report.md`.
