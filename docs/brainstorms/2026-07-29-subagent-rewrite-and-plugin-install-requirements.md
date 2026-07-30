# Subagent-fulfilled candidate rewriting + `/plugin install` packaging

## Overview

Two related corrections to work shipped earlier this session:

1. **Remove the direct Anthropic API integration** from challenger-lane mechanism 3 (LLM-based candidate rewriting). Replace the bounded Python API client with a file-queue handoff to a live Claude Code session, which fulfills the rewrite via an `Agent` subagent dispatch — no `ANTHROPIC_API_KEY`, no `anthropic` SDK dependency, no direct API auth anywhere in this repo's Python code.
2. **Package AgentDecompile as an installable Claude Code plugin**, so `/plugin marketplace add` + `/plugin install` is a supported install path alongside the existing manual `uv`-based MCP server setup, modeled on (but deviating from, where justified) `github.com/DietrichGebert/ponytail`.

## Problem Frame

Mechanism 3 was implemented this session (`llm_rewrite_client.py`, plus wiring in `autonomy_budget.py`, `autonomous_policy.py`, `source_plugins.py`, `plugin_pipeline.py`, `source_parity_synthesize.py`) as a headless Python client calling the Anthropic Messages API directly, gated by a new `max_llm_calls_per_function` budget. This requires standing up a separate API credential (`ANTHROPIC_API_KEY`) for a tool that already runs *inside* Claude Code agent sessions via MCP — every `--autonomous` recovery run either already has an agent attached, or is exactly the kind of unattended background job that should not be minting its own API spend independent of the session that launched it.

Separately, AgentDecompile today is a `uv`-managed Python/PyGhidra MCP server with manual setup (`GHIDRA_INSTALL_DIR`, `uv run`, entry points in `pyproject.toml`). There is no `/plugin install` path, even though this repo already ships `.claude/skills/agentdecompile-server-env` — MCP session/env-var guidance that assumes the user has already done the manual setup. Ponytail (researched this session) demonstrates the `.claude-plugin/plugin.json` + `marketplace.json` convention Claude Code's plugin loader expects, though it does not wire an MCP server into that manifest — its MCP server stays a fully separate, manually-run artifact.

## Key Decisions

- **Fulfillment shape: queue + live session, not loop-replaces-Python.** The Python `--autonomous` campaign loop keeps its existing role (near-miss detection via `autonomous_policy.choose_next_action()`, compile+objdiff verification via the existing `attempt_candidate` path). When policy decides a real near-miss has exhausted mechanisms 1+2 and rewrite budget remains, it writes a typed rewrite-request record to a file queue and produces a typed terminal for *that attempt* (the campaign loop does not block waiting on the record — it moves to the next function or campaign, consistent with the existing bounded/non-blocking design). A live Claude Code session, running `/loop`, polls that queue, dispatches an `Agent` subagent per pending request to produce the rewrite, and writes the result back to disk (result file keyed by request id) for the Python side to pick up on a subsequent pass.
- **Loop mechanism: the built-in `/loop` skill**, not the third-party `ralph-loop` plugin. No new plugin dependency; matches the harness already in use.
- **The existing budget/gating/receipt shape carries over, renamed.** `max_llm_calls_per_function` → `max_rewrite_requests_per_function` (or equivalent), `try-llm-rewrite` → `try-rewrite-request`, `llm-unavailable` → `rewrite-unavailable`. The architecture proven this session (opt-in budget field, near-miss + mechanism-1/2-exhaustion gating in `choose_next_action()`, typed non-blocking terminal via `AUTONOMY_STOP_ACTIONS`, receipt recorded in the existing `source-shape-search-msvc/summary.json` trail) is sound and should not be redesigned from scratch — only the fulfillment mechanism changes (queue write + later pickup, instead of a synchronous bounded API call inside `semantic_equivalent_variants()`).
- **Full removal of the Anthropic API path.** Delete `src/agentdecompile_recovery/llm_rewrite_client.py`, the `anthropic` dependency from `pyproject.toml`, the `ANTHROPIC_API_KEY` entry from `.env.example`, and every call site added this session that invoked `request_llm_rewrite()` directly. No fallback path that silently re-adds direct API auth.
- **Plugin packaging deviates from ponytail on one point: wire `mcpServers` into `plugin.json`.** Ponytail's MCP server is optional/secondary to its skill-based value; AgentDecompile's MCP server (PyGhidra tools) *is* the product's core value, so `/plugin install` should launch it, not just install supporting skills. Exact `mcpServers` JSON shape is an implementation-time unknown (Anthropic's plugin schema was not directly verified this session) — flagged for `/ce-plan`.
- **Marketplace shape follows ponytail's precedent:** a `.claude-plugin/marketplace.json` with `source: "./"`, so this repo doubles as both marketplace and plugin (`/plugin marketplace add <org>/agentdecompile` then `/plugin install agentdecompile@agentdecompile`).

## Requirements

- R1. `src/agentdecompile_recovery/llm_rewrite_client.py` and the `anthropic` SDK dependency are removed entirely; no code path in this repo makes a direct outbound call to the Anthropic API.
- R2. Near-miss detection, mechanism-1/2-exhaustion gating, and the opt-in budget field are preserved from this session's work, renamed to reflect queue-based fulfillment rather than direct API calls.
- R3. When policy decides a rewrite request is warranted, a typed record is written to a file-based queue (schema, location TBD in planning) containing enough context for a subagent to act (packaged-source candidate, target byte slice/disassembly reference, objdiff mismatch histogram) — same context payload already designed this session for the (now-removed) direct API prompt.
- R4. A `/loop`-driven polling mechanism (skill, command, or slash-invocable prompt — exact shape TBD in planning) reads pending queue entries, dispatches one `Agent` subagent per entry to produce the rewrite, and writes the result back keyed by request id.
- R5. The Python side picks up completed results on a subsequent campaign pass and feeds the resulting candidate through the *identical* compile+objdiff verification path as every other shape-search variant — this invariant from the original design does not change.
- R6. A `.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` are added, enabling `/plugin marketplace add` + `/plugin install` as a supported install path for AgentDecompile's MCP server and existing skills.
- R7. `plugin.json` wires an `mcpServers` entry launching the existing `mcp-agentdecompile` entry point (or equivalent `uv run` invocation), so `/plugin install` alone is sufficient to get a working MCP connection — not skills-only.
- R8. Existing manual `uv`-based setup docs remain valid and are not removed; `/plugin install` is an additional path, not a replacement requiring migration.

## Scope Boundaries

### Deferred for later
- Exact queue file schema, request-id scheme, and result-polling cadence — implementation detail for `/ce-plan`.
- Exact `/loop` invocation shape (dedicated skill vs. bare `/loop <prompt>`) — implementation detail for `/ce-plan`.
- `mcpServers` manifest field's precise JSON shape — needs direct verification against Anthropic's plugin schema during planning (not confirmed by this session's ponytail research, since ponytail itself doesn't use this field).
- Publishing this repo's plugin to a public/shared marketplace listing beyond `source: "./"` self-hosting.

### Outside this mechanism's identity
- Any design that reintroduces a standalone API credential for autonomous LLM calls independent of a live agent session.
- Claiming subagent-rewritten source as verified without the objdiff gate (unchanged invariant from the original design).

## Dependencies / Assumptions

- Assumes a live Claude Code session (running `/loop`) is available to poll the queue during any `--autonomous` run that enables the rewrite-request budget above 0. Unlike the removed direct-API design, this mechanism cannot run in a truly unattended/headless environment with no agent attached — this is an intentional trade-off (no separate API spend/credential) that changes the mechanism's operational assumptions from this session's original design. Flag for `/ce-plan` to state explicitly, and for the plan to consider what happens to a campaign if no session is polling (should the campaign still terminate cleanly rather than hang — likely yes, via the existing non-blocking typed-terminal pattern).
- Assumes `/plugin install`'s `mcpServers` field can invoke a `uv run`-based Python entry point the same way ponytail's ecosystem invokes `node` scripts — not yet verified against Anthropic's plugin schema docs.

## Outstanding Questions

- Exact queue directory/file layout relative to the existing `work_dir` structure (`state/`, `source-generation/`, etc.) — for `/ce-plan`.
- Whether the subagent dispatch should use a specific `subagent_type` (e.g. a new dedicated agent definition) or the general-purpose agent — for `/ce-plan`.
- Whether `/plugin install` should also expose `agentdecompile-server-env` and other existing skills automatically (Claude Code's directory-convention auto-discovery should cover this, per ponytail's precedent, but worth confirming no manifest wiring is additionally required) — for `/ce-plan`.

## Sources / Research

- This session's mechanism-3 implementation (now being reworked): `src/agentdecompile_recovery/llm_rewrite_client.py`, `autonomy_budget.py`, `autonomous_policy.py`, `source_plugins.py`, `plugin_pipeline.py`, `source_parity_synthesize.py`.
- `github.com/DietrichGebert/ponytail` (external research, this session): `.claude-plugin/plugin.json` (minimal manifest, no `mcpServers`/`commands`/`agents` fields, relies on directory-convention auto-discovery for `skills/`), `.claude-plugin/marketplace.json` (`source: "./"` self-hosting pattern), `hooks/claude-codex-hooks.json` (referenced explicitly since hooks don't live at the default path), install flow (`/plugin marketplace add <owner>/<repo>` then `/plugin install <plugin>@<marketplace>`, must be separate turns).
- `.claude/skills/agentdecompile-server-env` — existing skill this repo already ships, relevant to what `/plugin install` should surface.
- `STRATEGY.md` — proof-gate invariant (objdiff-zero is the sole verification mechanism) unaffected by either change in this doc.
