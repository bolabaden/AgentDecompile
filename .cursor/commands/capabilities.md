# `/capabilities` — AgentDecompile full capability map

Structured inventory of what agents can do with AgentDecompile. For workflow guidance, see [`/help`](./help.md).

## Tiered RE routing

| Tier | Ghidra MCP? | When |
|------|-------------|------|
| 0 | No | File metadata, strings, headers, yara/capa — **before** `open-project` |
| 1 | Batch CLI | `ghidrecomp`, export/SARIF — offline bulk |
| 2 | Read-only MCP | `list-*`, `search-*`, xrefs — **`analysis_tier: 2`** in tool reference metadata |
| 3 | Deep/mutate | `decompile-function`, `manage-*`, `match-function` — **`analysis_tier: 3`** |

Details: [tiered-re-analysis-knowledgebase.md](../../docs/solutions/architecture-patterns/tiered-re-analysis-knowledgebase.md) · skill `/tiered-re-analysis` (`.cursor/skills/tiered-re-analysis/`).

## Surfaces

| Surface | Entry | Notes |
|---------|-------|-------|
| MCP tools | `tools/list` → `tools/call` | **56 advertised** tools (default surface); 4 GUI-only tools hidden |
| MCP prompts | `prompts/list` → **`prompts/get`** | 9 RE workflow prompts with session substitution |
| CLI | `agentdecompile-cli tool`, `tool-seq` | Persists `mcp-session-id` per backend URL |
| Slash commands | `/help`, `/capabilities`, `/lfg` | Cursor agent discovery + live proof |

## Advertised MCP tools (56)

Canonical catalog: [TOOLS_LIST.md](../../TOOLS_LIST.md) (60 canonical; 56 advertised + 4 GUI-only hidden).

| Category | Tools |
|----------|-------|
| Project & session | `open-project`, `import-binary`, `list-project-files`, `checkout-program`, `checkin-program`, `checkout-status`, `sync-project`, `get-current-program`, `analyze-program`, `change-processor`, `list-processors` |
| Functions | `list-functions`, `get-function`, `get-functions`, `decompile-function`, `rename-function`, `set-function-prototype`, `manage-function`, `manage-function-tags`, `match-function` |
| Symbols & labels | `manage-symbols`, `create-label`, `apply-data-type` |
| Structures & enums | `manage-structures`, `manage-enums`, `manage-data-types` |
| Memory & data | `get-data`, `inspect-memory`, `manage-strings`, `list-strings` |
| Analysis | `get-references`, `list-cross-references`, `get-call-graph`, `gen-callgraph`, `analyze-data-flow`, `analyze-vtables`, `search-everything`, `list-imports`, `list-exports` |
| Annotations | `manage-comments`, `manage-bookmarks` |
| Scripting & export | `execute-script`, `export`, `delete-project-binary`, `remove-program-binary` |
| Discovery | `list-prompts`, `list-tools`, `debug-info`, `suggest` (stub — lists types only) |
| Shared server | `connect-shared-project`, `svr-admin` |

**Hidden by default (full surface only):** workflow routers such as `search-everything` aggregators remain callable; curated surface advertises list/search primitives instead.

**GUI-only (not advertised headless):** `get-current-address`, `get-current-function`, and related GUI coordinate tools.

## MCP prompts (9)

Fetch rendered content with **`prompts/get`** (substitutes active program when `program_path` omitted):

| Prompt | Role |
|--------|------|
| `re-scout-broad-sweep` | Broad symbol/string/xref discovery |
| `re-diver-deep-dive` | Deep decompilation + call chains |
| `re-bottom-up-analyst` | Bottom-up from strings/xrefs |
| `re-top-down-analyst` | Top-down from entry points |
| `re-data-architect` | Structures, enums, data types |
| `re-exhaustive-librarian` | Exhaustive cataloging |
| `re-bridge-builder` | Cross-binary correlation |
| `re-convergence-orchestrator` | Multi-agent synthesis |
| `re-iterative-verifier` | Hypothesis verification loop |

## Environment flags (optional)

| Variable | Effect |
|----------|--------|
| `AGENTDECOMPILE_AUTO_CHECKIN` | Auto check-in/save after mutating tools |
| `AGENTDECOMPILE_AUTO_MATCH_PROPAGATE` | Propagate renames/comments to other open programs |
| `AGENTDECOMPILE_AUTO_MATCH_TARGET_PATHS` | Comma-separated propagation targets |
| `AGENTDECOMPILE_PROJECT_PATH` | Proxy: forward project path header |
| `AGENTDECOMPILE_TOOL_SURFACE` | `full` (default) or `curated` |

## Response context (passive)

Mutating tools and most errors include **`projectContext`**: `mode`, `activeProgram`, `analysisComplete`, `checkoutSummary`, `uiVisibility` / `guiHint`. See [`/help`](./help.md).

## Related

- [Agent-native audit](../../docs/audits/2026-05-24-agent-native-audit.md)
- [Residual tracker](../../docs/residual-review-findings/impl-agent-native-audit-c2bc.md)
- [`/lfg` proof sequence](./lfg.md)
