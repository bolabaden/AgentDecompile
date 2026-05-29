# `/help` — AgentDecompile capability discovery

Quick reference for agents working with the AgentDecompile MCP server.

## Start here

### Tiered analysis (prefer Ghidra only when necessary)

1. **Tier 0 (no Ghidra)** — `file`, `strings`, `readelf`/`objdump`, optional `yara`/`capa` on the raw binary.
2. **Tier 1 (batch)** — `agentdecompile-cli ghidrecomp` or export when offline bulk work is faster.
3. **Tier 2–3 (MCP)** — After the binary is in a project and analyzed:
   - **`open-project`** — Connect to a local `.gpr` or shared Ghidra Server repository.
   - **`analyze-program`** — When `projectContext.analysisComplete` is false.
   - **`list-functions`** / **`search-*`** / **`get-references`** — Discovery (Tier 2).
   - **`decompile-function`** — Deep semantics (Tier 3).

Skill: [.cursor/skills/tiered-re-analysis/SKILL.md](../skills/tiered-re-analysis/SKILL.md) · KB: [tiered-re-analysis-knowledgebase.md](../../docs/solutions/architecture-patterns/tiered-re-analysis-knowledgebase.md)

Multi-agent RE: `.github/agents/re-planner.agent.md` (Planner → Worker → Critic → Aggregator).

Every successful tool response (and most errors when programs are loaded) includes passive **`projectContext`**:

| Field | Meaning |
|-------|---------|
| `mode` | `local` or `shared-server` |
| `activeProgram` | Currently selected program path |
| `openPrograms` | Programs loaded in this session |
| `analysisComplete` | Ghidra auto-analysis finished for active program |
| `analysisByProgram` | Per-program analysis flags when multiple programs are open |
| `checkoutSummary` | Shared mode: checked-out / modified / can-checkin counts |
| `uiVisibility` / `guiHint` | Mutating tools: headless persistence + CodeBrowser reload guidance |
| `projectPath` / `projectName` | Local project location |
| `serverHost` / `serverPort` / `repository` | Shared server connection |

## Tool categories

See [TOOLS_LIST.md](../../TOOLS_LIST.md) for the canonical tool catalog (56 advertised by default; 4 GUI-only hidden).

| Category | Examples |
|----------|----------|
| Project | `open-project`, `checkout-program`, `checkin-program`, `list-project-files` |
| Functions | `list-functions`, `decompile-function`, `rename-function`, `set-function-prototype` |
| Symbols & data | `manage-symbols`, `apply-data-type`, `manage-structures` |
| Analysis | `get-references`, `get-call-graph`, `analyze-data-flow`, `search-everything` |
| Cross-binary | `match-function` (propagate names/comments across related binaries) |

## Session & proxy

- Send **`mcp-session-id`** on every HTTP request after initialize (CLI persists it per backend URL).
- Proxy mode: set `AGENTDECOMPILE_PROJECT_PATH` so the proxy forwards **`X-AgentDecompile-Project-Path`**.

## Proof / validation

- **`/lfg`** — Full live Ghidra Server + MCP proof sequence (see [lfg.md](./lfg.md)).
- Unit tests: `uv run pytest -m unit -q`
- Agent-native audit: [docs/audits/2026-05-24-agent-native-audit.md](../../docs/audits/2026-05-24-agent-native-audit.md)

## Related docs

- [`/capabilities`](./capabilities.md) — Full tool/prompt/env inventory
- [README.md](../../README.md) — User overview
- [AGENTS.md](../../AGENTS.md) — Cloud agent setup
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — Development workflow
