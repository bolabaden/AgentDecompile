# Task: Editor window (tabs, meta, listing, islands)

Write **only** `src/agentdecompile_recovery/corpus/dashboard/static/workbench-editor.css`.

Read first: `docs/superpowers/specs/2026-08-31-workbench-control-system-design.md` and tokens/controls.

Classes:
- `.wb-editor`, `.wb-editor-tabs`, `#wb-corpus-nav`, `.wb-corpus-nav-item`, `.wb-editor-more`, `.wb-editor-more-list`
- `.wb-editor-meta`, `.wb-project-path`, `.wb-kind`
- `.wb-editor-body`, `.wb-surface` (must stay `display:block` in the body — **never** `display:none` on `.wb-surface`)
- `.wb-listing-empty`, `.wb-preview`, `.wb-island`, `.wb-match-island`, `.wb-graph-island`
- `.wb-reaction`

Feel: One document window. Tabs flush like IDA. Active tab `--bg` + inset blue bar. More menu is a real dropdown (raised, z-index). Meta bar is a 22px inspector strip, path wraps. Listing empty state is a drop target, not a card. Islands inherit `--fg-body`, min-height 16rem. Legacy HTML inside `.wb-legacy` must remain readable (no white-on-white).

Do not edit JS. Do not commit. Do not hide `.wb-surface`.
Report: `docs/plans/wb-control-briefs/editor-report.md`.
