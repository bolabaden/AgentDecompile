# AGENTS.md

See [README.md](README.md) for project overview, [STRATEGY.md](STRATEGY.md) for product direction, [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, and [src/CLAUDE.md](src/CLAUDE.md) for architecture details.

## Documented solutions

`docs/solutions/` — documented solutions to past problems (MCP/Ghidra integration, analysis gate, CLI agents, workflows), organized by category with YAML frontmatter (`module`, `problem_type`, `component`, `tags`). Relevant when implementing or debugging in those areas; search by module or tag before changing `src/agentdecompile_cli/`.

`CONCEPTS.md` — shared domain vocabulary (entities, named processes, status concepts) for this project. Relevant when orienting to the codebase or discussing domain concepts such as substrate vs matching recovery.

**Agent-native audit (2026-05-24):** [docs/audits/2026-05-24-agent-native-audit.md](docs/audits/2026-05-24-agent-native-audit.md) — scored MCP/CLI/GUI parity review; P1 follow-ups in [docs/residual-review-findings/impl-agent-native-audit-c2bc.md](docs/residual-review-findings/impl-agent-native-audit-c2bc.md). Patterns: [docs/solutions/architecture-patterns/agent-native-mcp-patterns.md](docs/solutions/architecture-patterns/agent-native-mcp-patterns.md).

## Recovery integration

This repo is the **only** active recovery cwd. Capabilities from the upstream donor checkout fold in here; do not keep a parallel product surface. See [docs/UPSTREAM_DONOR_ARCHIVE.md](docs/UPSTREAM_DONOR_ARCHIVE.md): the donor checkout is read-only—do not run `source-parity-one-shot` or rematch jobs there.

Package: `src/agentdecompile_recovery/` plus companion scripts under `scripts/`.

Current integrated entrypoints:

- `agentdecompile-recover` → `agentdecompile_recovery.cli:main`
- `agentdecompile-reconstruct` → `agentdecompile_recovery.frontdoor:main`
- `scripts/decomp-cli.sh` → recovery/source-parity helper front door

Fast recovery dump (AgentDecompile only): see [docs/CRITICAL_PATH.md](docs/CRITICAL_PATH.md) — `agentdecompile-reconstruct … --resume --dump-source DIR`. Default reconstruct runs PyGhidra enrich-decompile before source generation (`--skip-enrichment` to opt out). Never claim match without objdiff 0; never promote byte-emitters into `verified/`. Profiles are format/stem-derived (PE vs ELF); do not hardcode product binaries into recovery defaults.

**Source recovery must be self-contained.** A run that is supposed to produce source (decompile, synthesize, match, or dump) should write its own inventory, facts, and match receipts in that execution. Do not skip those stages and point at leftover `target/` files, old dumps, or backfilled JSONL. Flags like `--resume`, match cache, and `--dump-source-only` exist for operators doing incremental work — not for agents to avoid running the pipeline. When the task is to obtain source, run the producing stages (or `--force-rematch` if rematch is the point).

**One-shot perf (U1–U5 done):** [docs/plans/2026-07-24-perf-recovery-one-shot-living-plan.md](docs/plans/2026-07-24-perf-recovery-one-shot-living-plan.md) — backlog only: G14–G16. Update that plan’s progress section after substantial recovery-perf changes.

The imported code expects a repo-root `scripts/` tree and root-relative `target/` outputs. Preserve that layout while the integration is being consolidated; do not silently rename or relocate the script surface without updating `src/agentdecompile_recovery/`.

## Cursor Cloud specific instructions

Environment setup, env-var reference (auto-match-propagate, auto-checkin, max-analysis-tier), local server startup, session/proxy behavior, and lint/test/build commands: see the **agentdecompile-server-env** skill (`.claude/skills/agentdecompile-server-env/SKILL.md`).

## Naming Conventions

When generating or suggesting names for symbols, variables, parameters, fields, types, or constants during reverse engineering work, apply these conventions consistently:

| Identifier kind | Convention | Example |
|---|---|---|
| Local variables | `camelCase` | `itemCount`, `saveBuffer` |
| Global variables | `camelCase` | `gameState`, `playerStats` |
| Function parameters | `camelCase` | `charIndex`, `saveFilePath` |
| Classes and types | `CapitalCase` (PascalCase) | `SaveGameHeader`, `ItemRecord` |
| Structure fields | `snake_case` | `save_version`, `char_name` |
| Enum constants | `COBRA_CASE` (SCREAMING_SNAKE) | `SAVE_SLOT_EMPTY`, `ITEM_TYPE_WEAPON` |

Apply these conventions in:
- Decompiled pseudocode variable and parameter names produced by `decompile-function` or `execute-script`
- Symbol rename suggestions from `rename-function`, `rename-variable`, `rename-data-label`
- Structure and field names in `create-structure` / `edit-structure` tool calls
- Enum members defined via `create-enum` / `edit-enum`
- Documentation, comments, and analysis summaries that reference named symbols

When a name is ambiguous or cannot be inferred, prefer the convention that matches the identifier category above rather than leaving it in a raw mangled/numbered form (e.g., prefer `slotIndex` over `local_8` for a loop counter).

## Learned User Preferences

- Source-producing recovery runs must be self-contained: run decompile/match/synth in the current execution, or use `--force-rematch` when rematch is intended. Do not pass off prior `target/` artifacts or backfilled JSONL as this run's output.
- Prefer implementing and running (config, env, live tests) over returning instructions for the user to run.
- After a merge or vague “continue”, infer the next slice from `STRATEGY.md`, open plans, and `docs/residual-review-findings/`; implement and open the next PR without waiting for a detailed task (see `.cursor/skills/lfg/SKILL.md` step 0).
- Do not block the agent's main shell on long proof drivers (e.g. `scripts/lfg_cmd_sequence.ps1`): start them in a separate process, tee output to `.lfg_run/lfg_cmd_<RunId>/driver.log`, tail logs in parallel, and avoid overlapping runs without stopping the prior driver and its MCP server.
- After fixing an issue, continue with the task without asking; run and verify, and if still broken fix and rerun until functional.
- Fix the underlying behavior so the same user commands work unchanged; do not only improve error messages or documentation.
- Complete implementations without placeholders; for features like export, provide fallbacks so the operation does not error or fail.
- Use the MCP server tools (e.g. user-agdec-http) for agentdecompile workflows rather than the CLI when both are available.
- Default to markdown (not JSON) for tool output; scale output detail by result count (few results = full detail, many = trimmed).
- Prefer supporting Ghidra server auth via headers or CLI args when possible, not only via process environment.
- When removing or renaming tests, update related docs (for example `CONTRIBUTING.md`, `tests/README.md`, `.cursor/plans`), helper scripts, and in-repo references so nothing still points at deleted modules.
- Prefer tests that exercise real `tools/call` handlers and response payloads over tests that only assert `tools/list` advertisement shape.

## Learned Workspace Facts

- When editing video-derived docs (e.g. docs/from_video), keep product names accurate in historical notes, but do not encode those names into recovery pipeline defaults or profile detection.

Ghidra/MCP-server-specific gotchas (session semantics, JPype, tool routing, checkin/conflict flow), modification-conflict handling, tiered RE analysis routing, and MCP server debugging: see [src/agentdecompile_cli/CLAUDE.md](src/agentdecompile_cli/CLAUDE.md) — loads automatically when working in that package.
