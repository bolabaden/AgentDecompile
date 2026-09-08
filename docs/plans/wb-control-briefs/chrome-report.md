# Chrome stylesheet report

**Status:** DONE_WITH_CONCERNS

**File:** `src/agentdecompile_recovery/corpus/dashboard/static/workbench-chrome.css`

## What changed

Wrote the chrome widget stylesheet only. Existing class names and IDs kept; no JS, no other CSS.

## What was styled

| Surface | Selectors | Treatment |
|---------|-----------|-----------|
| Shell | `.wb-chrome` | `--bg-panel`, `--z-chrome`, 1px `--border` bottom; focus ring 2px `--focus` offset −2px |
| Toolbar | `.wb-toolbar` | 32px row; brand \| full-width search \| pulse; space tokens |
| Brand | `.wb-brand`, `.wb-mark` | 18px square mark `--accent`, radius 0; title `--wb-type-body` |
| Search | `.wb-search`, `#wb-q` | Sunken `--bg-sunken` + `--wb-inset`, 28px, full width |
| Palette | `.wb-server-btn` | 24px compact icon (not pill, not a second field); hover/active/disabled/danger |
| Pulse | `#job-pulse` | Dim `--text-dim`, tabular nums — not celebratory |
| Menubar | `.wb-menubar`, `.wb-menu`, `.wb-menu-btn` | `--bg-raised`; hover/open = `--accent` fill |
| Menus | `.wb-menu-list`, `.wb-menu-item`, `.wb-menu-sep` | `--z-menu`, `--wb-raise`; item hover/focus `--accent`; press `--wb-press` |
| Sessions | `.wb-sessions`, `.wb-tab`, `.wb-tab.on` | Inactive on panel; **active = `--bg` + 2px `--accent` underline**; kind color on `.wb-tab-chip` only |
| Tab chrome | `.wb-tab-name`, `.wb-tab-close`, `.wb-tab-new`, `.wb-tab-rename` | Hover/disabled; close 16px muted; `+` compact; rename sunken + focus |
| Status | `footer.wb-status`, `#wb-status-source`, `#wb-status-kind` | **22px**, dim copy; hint muted; overview link not accent-loud |

Tokens only (`--bg`, `--accent`, `--wb-*`, kind vars). Radius 0. Ghidra/IntelliJ cool gray.

## How verified

- Cross-checked selectors against `workbench-app.js` chrome markup and `workbench.css` class list.
- Confirmed `workbench.py` already links `workbench-chrome.css` after tokens/controls.
- No browser render, no CSS test suite. A stylesheet-only commission cannot fail a unit test without the change.

## Deviations

None from the brief. `.wb-tab-chip` and `#job-pulse` styled as descendants of listed chrome (present in JS; needed for kind + pulse).

## Findings outside scope

- `workbench.css` still contains visual chrome (pill `.wb-server-btn`, kind underlines on `.wb-tab`, 0.85rem footer). This file overrides by cascade. Layout-only strip of those rules is another owner.
- Action strip / live region sit inside `.wb-chrome` in JS; they are overlays, not styled here.

## Risks / follow-ups

- Equal-specificity clashes with leftover `workbench.css` rules depend on stylesheet order (currently chrome wins).
- Narrow-toolbar media queries here may fight `workbench.css` `@media (max-width: 1100px)` stacking — chrome keeps brand+search+⌘K on one row until 640px.

## Uncertainties

- Visual proof not run (no dashboard session in this commission).
