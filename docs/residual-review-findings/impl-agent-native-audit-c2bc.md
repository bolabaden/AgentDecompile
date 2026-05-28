---
branch: impl/agent-native-audit-c2bc
plan: docs/plans/2026-05-24-lfg-agent-native-audit-c2bc.md
audit: docs/audits/2026-05-24-agent-native-audit.md
---

# Residual findings — agent-native audit (P1+)

From [2026-05-24 agent-native audit](../audits/2026-05-24-agent-native-audit.md). Implementation is **out of scope** for the audit PR; track here for follow-up slices.

**Residual actionable work: none.** (PR #49 merged squash `13200d6`, 2026-05-28.)

## P1 — high impact, low–medium effort

| ID | Area | Action | Principle |
|----|------|--------|-----------|
| P1-1 | `program_metadata.collect_project_context()` | ~~Add `analysisComplete`, compact `checkoutSummary`; inject slim context on errors~~ **Done** (PR #49) | Context injection |
| P1-2 | MCP server | ~~Implement **`prompts/get`** (9 prompts listed; content exists)~~ **Done** (PR #49) | Discovery + prompt-native |
| P1-3 | Mutating tool responses | ~~Add **`uiVisibility` / `guiHint`** footer~~ **Done** (PR #49) | UI integration |
| P1-4 | Proxy | ~~Forward **`x-agentdecompile-project-path`** header~~ **Done** (PR #49) | Shared workspace |

## P2 — CRUD and surface

| ID | Area | Action |
|----|------|--------|
| P2-1 | `manage-data-types` / new tool | ~~Enum CRUD (`manage-enums` or enum modes)~~ **Done** (PR #49) |
| P2-2 | `manage-symbols` | ~~`delete_label` / remove label mode~~ **Done** (PR #49) |
| P2-3 | Curated tool surface | ~~Advertise list/search primitives; demote `search-everything` / `get-function` to `full`~~ **Done** (PR #49) |
| P2-4 | Discovery | ~~`.cursor/commands/help.md`~~ **Done**; ~~`/capabilities` slash command~~ **Done** (PR #49) |

## P3 — docs / hygiene

| ID | Action |
|----|--------|
| P3-1 | ~~Document dual-JVM + checkin-before-GUI-reload in README~~ **Done** (PR #49) |
| P3-2 | ~~Fix or remove **`suggest`** stub~~ **Done** (PR #49) |
| P3-3 | ~~Fail hard on `import-binary` temp ProjectManager fallback~~ **Done** (PR #49) |

## Ship gate (audit plan R4)

- [x] Stage `docs/audits/2026-05-24-agent-native-audit.md`, plan, residual doc, AGENTS.md cross-link
- [x] Push `impl/agent-native-audit-c2bc` and open PR (do not include unrelated `_version.py` / lockfile churn)
- [x] P1-1 `projectContext` enrichment (`analysisComplete`, `checkoutSummary`, error injection)

## Residual Review Findings (code review c97fb23)

Optional polish from P1-1 review — status:

- ~~**Low** | `response_formatter.py:3072` | Render `analysisComplete` / `checkoutSummary` in markdown Project Context footer~~ **Done** (PR #49)
- ~~**Low** | `tests/test_project_context.py` | Add unit test: error response omits `projectContext` when session has no programs~~ **Done**
- ~~**Low** | `.cursor/commands/help.md` | Document `analysisByProgram` field~~ **Done**
- ~~**Info** | `docs/audits/2026-05-24-agent-native-audit.md:120` | Update Context Injection audit rows post-P1-1~~ **Done**

## PR #49 ship gate

- [x] CI green (unit, headless, CodeQL)
- [x] P1–P3 + P2-1 polish on branch
- [x] Advertised-tool count test/docs aligned (56 tools after `manage-enums`)
- [x] P2-4 `/capabilities` discovery command
- [x] **Merge-ready** — all agent-implementable gates satisfied (2026-05-24)
- [x] Merge to `master` (squash `13200d6`, PR #49, 2026-05-28)

## PR #49 summary (merge reviewer)

**Branch:** `impl/agent-native-audit-c2bc` · **PR:** https://github.com/bolabaden/AgentDecompile/pull/49

| Area | Delivered |
|------|-----------|
| Audit | `docs/audits/2026-05-24-agent-native-audit.md` (~74% agent-native score) |
| P1 | `projectContext` enrichment, `prompts/get`, UI hints, proxy project-path header |
| P2 | Enum CRUD, symbol delete, curated surface, `/help`, `/capabilities`, COBRA_CASE + action-scoped hints |
| P3 | Dual-JVM docs, `suggest` stub, import-binary project gate |
| CI | Dynamic advertised-tool count (56); unit + headless green |

**Verification:** `uv run pytest -m unit -q --timeout=120` · `gh pr checks 49`

**Merged:** squash `13200d6` on `master` (2026-05-28).

## Final LFG verification (2026-05-24)

- [x] `.cursorrules` tool count aligned (60 canonical / 56 advertised)
- [x] Unit suite green locally
- [x] PR #49 CI green on required checks (unit + headless)

**Branch HEAD (merge traceability):** `13200d6` (squash merge) · **Solutions:** [agent-native-mcp-patterns.md](../solutions/architecture-patterns/agent-native-mcp-patterns.md)

## Residual Review Findings (P2-1 manage-enums review c1641e4)

Follow-up polish after P2-1 ship (alias handlers + conflict overwrite addressed in review pass):

- ~~**Low** | `src/agentdecompile_cli/mcp_server/providers/enums.py` | Enforce COBRA_CASE at runtime via `is_cobra_case()` on create/add/edit_member~~ **Done** (PR #49)
- ~~**Low** | `src/agentdecompile_cli/mcp_server/program_metadata.py` | Scope UI hints / auto-checkin to mutating enum modes via payload `action`~~ **Done** (PR #49)
- ~~**Low** | `tests/test_manage_enums.py` | Add formatter/conflict-response coverage with mocked handlers~~ **Done** (PR #49)
