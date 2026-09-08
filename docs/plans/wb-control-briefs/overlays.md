# Task: Overlays (palette, action strip, jobs dock, toast)

Write **only** `src/agentdecompile_recovery/corpus/dashboard/static/workbench-overlays.css`.

Read first: `docs/superpowers/specs/2026-08-31-workbench-control-system-design.md` and tokens/controls.

Classes:
- `.wb-palette-backdrop`, `.wb-palette`, `.wb-palette-input`, `.wb-palette-section`, `.wb-palette-item`, `.wb-palette-item.active`, `.wb-palette-kbd`
- `.wb-action-strip`, `.wb-action-strip-head`, `.wb-action-strip-btns`, `.wb-tool-form`, `.wb-tool-field`
- `.wb-jobs-dock`, `.wb-jobs-dock-head`, `.wb-jobs-dock-body`, `.wb-job-row`, `.wb-job-log`, `.wb-job-cancel`
- `.wb-toast`

Feel: VS Code / JetBrains command palette (centered, 640px, typeahead rows with section kickers). Action strip is a **context bar** under chrome, not a card. Jobs dock is a status-line expander: compact when idle, log pane when open. Toast is bottom-right, 3s-looking, no success-green for finished jobs. Keep “A finished job is not a match.” readable.

Do not edit JS. Do not commit.
Report: `docs/plans/wb-control-briefs/overlays-report.md`.
