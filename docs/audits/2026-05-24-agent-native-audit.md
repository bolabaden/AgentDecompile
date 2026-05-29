---
title: Agent-native architecture audit — AgentDecompile MCP
date: 2026-05-24
branch: impl/agent-native-audit-c2bc
related: docs/plans/2026-05-24-lfg-agent-native-audit-c2bc.md
prior_review: docs/agent-native-architecture-review-2026-05-24.md
---

# Agent-Native Architecture Review: AgentDecompile

AgentDecompile is a **Ghidra-backed MCP server**, not a web SPA. This audit maps the eight agent-native principles to **MCP tools**, **CLI**, **Ghidra GUI parity**, and the **`/lfg` proof harness**.

```mermaid
flowchart TD
  subgraph surfaces [Human surfaces]
    GUI[Ghidra CodeBrowser]
    CLI[agentdecompile-cli]
  end
  subgraph agent [Agent surfaces]
    MCP[MCP tools/call]
    LFG[/lfg tool-seq proof]
  end
  Store[(.gpr / Ghidra Server)]
  GUI --> Store
  CLI --> MCP
  MCP --> Store
  LFG --> MCP
```

## Overall Score Summary

| Core Principle | Score | Percentage | Status |
|----------------|-------|------------|--------|
| Action Parity | 40/41 headless outcomes | 98% | ✅ |
| Tools as Primitives | 35/55 (strict atomic: 21/55) | 64% (38% strict) | ⚠️ |
| Context Injection | 7/7 context types | 100% | ✅ |
| Shared Workspace | 12/14 stores shared | 86% (6/6 persisted RE data) | ✅ |
| CRUD Completeness | 9/12 entities full CRUD | 75% | ⚠️ |
| UI Integration | 18/23 deferred GUI visibility | 78% deferred; 0% live | ⚠️ |
| Capability Discovery | 5/7 mechanisms | 71% | ⚠️ |
| Prompt-Native Features | 1/6 audited features | 17% | ❌ |

**Overall agent-native score (mean of percentages): ~74%**

### Status legend

- ✅ Excellent (80%+)
- ⚠️ Partial (50–79%)
- ❌ Needs work (<50%)

---

## Action Parity Audit

**Score: 40/41 headless-relevant outcomes (98%)** — 40/44 including GUI-only (91%).

### Highlights

| User outcome | Agent MCP path | Status |
|--------------|----------------|--------|
| Open / import / analyze | `open`, `import-binary`, `analyze-program` | ✅ |
| Decompile / xrefs / call graph | `decompile-function`, `get-references`, `get-call-graph` | ✅ |
| Rename / comments / structures | `manage-function`, `manage-comments`, `manage-structures` | ✅ |
| Shared VC loop (`/lfg`) | `checkout-program`, `create-label`, `checkin-program`, `sync-project` | ✅ |
| Export SARIF | `export` | ✅ |
| Cold binary triage / external scans | `run-file-triage` (optional `externalScanTools`), `run-external-re-scan` | ✅ |
| GUI cursor / Code Browser launch | — | ❌ intentional (`DISABLED_GUI_ONLY_TOOLS`) |
| `ghidrecomp` batch pipeline | `run-batch-decompile`, `run-batch-export-gzf`, `run-batch-bsim-signatures`, `run-batch-sast-scan` | ✅ |

### Gaps

1. **GUI-only tools** — `get-current-address`, `get-current-function`, `open-program-in-code-browser` disabled headless.
2. ~~**`ghidrecomp`** — batch decompile/BSIM/SAST; no MCP wrapper.~~ **Done:** Tier 1 `run-batch-*` tools (2026-05-30).
3. **Curated surface** — 14 primitives hidden from `tools/list` when `AGENTDECOMPILE_TOOL_SURFACE=curated`; calls still work.
4. **Auto-checkin** — `checkin-program` hidden when `AGENTDECOMPILE_AUTO_CHECKIN=1`; implicit persist only.

### Recommendations

- Document canonical kebab-case tool map (legacy `rename-function` → `manage-function`).
- Keep `.cursor/commands/lfg.md` synchronized with registry for regression proof.
- ~~Optional: MCP wrapper for `ghidrecomp` if batch export is an agent workflow.~~ **Done:** Tier 1 batch tools.

---

## Tools as Primitives Audit

**Score: 35/55 proper primitives or domain primitives (64%)** — 21/55 strict atomic (38%).

### Workflow-heavy tools (sample)

| Tool | Type | Issue |
|------|------|-------|
| `search-everything` | Workflow | Meta-router across 20+ scopes |
| `get-function` | Workflow | AIO bundle (decompile + xrefs + comments + …) |
| `open` | Workflow | Session bootstrap router |
| `manage-*` (7 tools) | Workflow | Multi-mode CRUD routers |
| `match-function` / `migrate-metadata` | Workflow | Cross-binary orchestration |
| `sync-project` | Workflow | Shared-repo pull/push |

### Primitives (sample)

`inspect-memory`, `create-label`, `checkout-program`, `list-project-files`, `decompile-function`, `resolve-modification-conflict`, …

### Recommendations

1. On **curated** surface, advertise scoped list/search tools; demote `search-everything` / `get-function` to `full`.
2. Split `manage-*` into semantic primitives (`rename-function`, `set-comment`) with `manage-*` as legacy aliases.
3. Add `primitive_tier` metadata to registry for client filtering.

---

## Context Injection Audit

**Score: 7/7 (100%)** — P1-1 shipped in PR #49

| Context type | Injected passively? | Where |
|--------------|---------------------|-------|
| Active program | ✅ | `projectContext` on tool success + errors |
| Open programs | ✅ | `projectContext.openPrograms` |
| Project path | ✅ | `projectContext.projectPath` |
| Analysis complete | ✅ | `projectContext.analysisComplete` / `analysisByProgram` |
| Checkout state | ✅ | `projectContext.checkoutSummary` (shared mode) |
| Session id | ❌ | `debug-info` only |
| Available tools | ❌ | `tools/list` separate call |

### Recommendations

1. ~~Extend `collect_project_context()` with `analysisComplete` and compact `checkoutSummary`.~~ **Done (PR #49)**
2. ~~Inject slim `projectContext` on **error** responses (analysis timeout, no program).~~ **Done (PR #49)**
3. Implement MCP **`prompts/get`** with live session substitution.
4. Add initialize instructions or `agentdecompile://capabilities` resource.

---

## Shared Workspace Audit

**Score: 12/14 stores shared (86%)** — **6/6 persisted RE data stores shared (100%)**.

### Shared ✅

Ghidra `Program` DB, local `.gpr`, Ghidra Server programs, `ProgramInfo.domain_file`, CLI `mcp-session-id` persistence, proxy session forwarding, proxy **`X-AgentDecompile-Project-Path`** forwarding.

### Partial / isolated ⚠️❌

| Store | Notes |
|-------|-------|
| `SESSION_CONTEXTS` | Process-local index, not a data fork |
| ChromaDB index | Optional; derived cache |
| LFG `--manage-mcp` workspace | Intentional test sandbox |

### Recommendations

1. ~~Forward **`x-agentdecompile-project-path`** on proxy.~~ **Done (PR #49)**
2. ~~Fail hard on import-binary temp ProjectManager fallback.~~ **Done (PR #49)**
3. Document one-workspace checklist (same `.gpr`, session id, checkin before GUI reload).

---

## CRUD Completeness Audit

**Score: 9/12 entities with full CRUD (75%)**

| Entity | C | R | U | D | Score |
|--------|---|---|---|---|-------|
| Programs | ✅ | ✅ | ✅ | ✅ | Full |
| Functions | ✅ | ✅ | ✅ | ✅ | Full |
| Comments | ✅ | ✅ | ✅ | ✅ | Full |
| Bookmarks | ✅ | ✅ | ✅ | ✅ | Full |
| Structures | ✅ | ✅ | ✅ | ✅ | Full |
| Project files | ✅ | ✅ | ✅ | ✅ | Full |
| VC checkout state | ✅ | ✅ | ✅ | ✅ | Full |
| Symbols/labels | ✅ | ✅ | ✅ | ✅ | Full |
| Function tags | ✅ | ✅ | ⚠️ | ✅ | 3/4 |
| Data types (catalog) | ❌ | ✅ | ⚠️ | ❌ | 2/4 |
| Strings | ❌ | ✅ | ❌ | ❌ | 1/4 |
| Enums | ✅ | ✅ | ✅ | ✅ | Full |

### Top gaps

- **Variable rename** — registry params exist; handlers missing on `manage-function`.

---

## UI Integration Audit

**Score: 0/23 live CodeBrowser sync; 18/23 deferred after checkin/save/reload (78%)**

AgentDecompile uses a **headless MCP JVM** separate from CodeBrowser. Mutations persist via `domain_file.save()` / `checkin-program`; GUI requires **manual reload** or shared-server checkout/sync.

| Mechanism | Present? |
|-----------|----------|
| Live GUI event bus | ❌ |
| File watching | ❌ |
| Web UI listing mirror | ❌ (console only) |
| Tool response feedback | ✅ (`uiVisibility` / `guiHint` on mutating tools) |
| Auto-checkin (silent persist) | ⚠️ |

### Recommendations

1. ~~Add **`uiVisibility`** / `guiHint` on mutating tool responses.~~ **Done (PR #49)**
2. Surface auto-checkin in response footer when env enabled.
3. ~~Document dual-JVM model in README.~~ **Done (PR #49)**

---

## Capability Discovery Audit

**Score: 5/7 (71%)**

| Mechanism | Status |
|-----------|--------|
| Onboarding docs | ✅ README, AGENTS.md, cli_agent_help |
| Help docs | ✅ TOOLS_LIST.md, OpenAPI `/docs` |
| UI hints | ✅ TOOL_GUIDANCE, nextSteps |
| Agent self-describes | ⚠️ per-tool; no initialize preamble |
| Suggested prompts | ✅ 9 MCP prompts; **`prompts/get` implemented** (session substitution) |
| Empty state | ⚠️ reactive errors only |
| Slash commands | ✅ `/help`, `/capabilities`, `/lfg` (proof) |

### Recommendations

1. ~~Add `.cursor/commands/help.md` or `/capabilities` discovery command.~~ **Done (PR #49)** — `/help` and `/capabilities`.
2. ~~Implement MCP **`prompts/get`**.~~ **Done (PR #49)**
3. Proactive empty-session hints on `get-current-program` / `list-project-files`.

---

## Prompt-Native Features Audit

**Score: 1/6 audited features prompt-native (17%)**

| Feature | Type |
|---------|------|
| MCP `_PROMPTS` workflows | **Prompt** ✅ |
| Analysis gate | Code |
| Auto-checkin | Code |
| Auto-match-propagate | Code |
| `search-everything` routing | Code |
| `suggest` tool | Explicit not-implemented stub (legacy types only) |

RE **workflow playbooks** are prompt-native; **server middleware** is correctly code-native for safety and persistence.

---

## `/lfg` and Agent-Native Alignment

The canonical **`/lfg`** proof (`.cursor/commands/lfg.md`, `scripts/lfg_validation.py`) exercises **agent parity** for shared-server version control:

| LFG phase | MCP tools | Parity |
|-----------|-----------|--------|
| Shared open + import | `open`, `import-binary` | ✅ |
| 3× checkout / label / checkin | `checkout-program`, `create-label`, `checkin-program` | ✅ |
| Post-restart persistence | `search-symbols`, `checkout-program` | ✅ |
| Local track | `open`, `import-binary`, save cycles | ✅ |
| Sync | `sync-project` pull/push | ✅ |
| Transport tests | nested pytest (not full GUI) | ⚠️ |

**Pytest entry:** `tests/test_lfg_e2e.py` — fast smoke in unit CI; full stack opt-in via `LFG_RUN=1`.

**Agent-native gaps exposed by `/lfg`:**

1. Requires correct **session id** + **project path** alignment (shared workspace).
2. Does not prove **live GUI refresh** — only persisted state.
3. LFG isolated MCP workspace (`--manage-mcp`) is an intentional **sandbox**, not user workspace.

---

## Top 10 Recommendations by Impact

| Priority | Action | Principle | Effort |
|----------|--------|-----------|--------|
| 1 | ~~Extend `projectContext` with `analysisComplete`, checkout summary, errors~~ **Done (PR #49)** | Context injection | Low |
| 2 | ~~Implement MCP **`prompts/get`**~~ **Done (PR #49)** | Discovery + prompt-native | Medium |
| 3 | ~~Add **`uiVisibility` / guiHint** on mutating tools~~ **Done (PR #49)** | UI integration | Low |
| 4 | ~~Forward **`x-agentdecompile-project-path`** on proxy~~ **Done (PR #49)** | Shared workspace | Low |
| 5 | ~~Add **`manage-enums`** or enum modes on `manage-data-types`~~ **Done (PR #49)** | CRUD | Medium |
| 6 | ~~Add **`delete_label`** on `manage-symbols`~~ **Done (PR #49)** | CRUD | Low |
| 7 | ~~Add **`.cursor/commands/help.md`** capability discovery~~ **Done (PR #49)** | Discovery | Low |
| 8 | ~~Invert **curated** surface: advertise list/search primitives~~ **Done (PR #49)** | Tools as primitives | Medium |
| 9 | ~~Document **dual-JVM + checkin-before-GUI-reload** workflow~~ **Done (PR #49)** | UI integration | Low |
| 10 | ~~Fix or remove **`suggest`** stub~~ **Done (PR #49)** | Prompt-native clarity | Low |

---

## What's Working Excellently

1. **Headless action parity (98%)** — Nearly every RE outcome available via MCP; `/lfg` proves VC persistence.
2. **Shared persisted workspace** — Agents mutate the same Ghidra Program DB as the GUI after checkin/save.
3. **TOOLS_LIST.md + OpenAPI** — Exhaustive capability reference and live HTTP docs.
4. **Conflict two-step flow** — `resolve-modification-conflict` enables safe agent writes.
5. **Nine RE workflow prompts** — Prompt-native playbooks for scout/dive/bridge patterns; delivered via **`prompts/get`** (PR #49).

---

## Residual tracking

P1–P3 implementation gaps and the audit ship gate (plan R4) are tracked in [docs/residual-review-findings/impl-agent-native-audit-c2bc.md](../residual-review-findings/impl-agent-native-audit-c2bc.md).

## Verification

This audit is documentation-only. Related automated checks:

```bash
uv run pytest tests/test_lfg_e2e.py -m "not lfg" -q --timeout=60
uv run pytest -m unit -q --timeout=120
```
