---
title: Packaging a Python/uv MCP server as an installable Claude Code plugin
date: 2026-07-30
category: tooling-decisions
module: agentdecompile_cli
problem_type: tooling_decision
component: tooling
severity: low
applies_when:
  - "An MCP server already exists as a manually-configured, uv/pip-managed local process"
  - "Deciding whether /plugin install should launch the MCP server automatically or leave it a separate manual step"
tags:
  - claude-code-plugin
  - mcp-server
  - plugin-json
  - marketplace-json
  - distribution
---

# Packaging a Python/uv MCP server as an installable Claude Code plugin

## Context

AgentDecompile shipped only as a manually-configured MCP server (`uv run
agentdecompile-server ...`, documented in
`.claude/skills/agentdecompile-server-env/SKILL.md`) with no `/plugin
install` path, even though the repo already carried a `.claude/skills/`
directory. Researched `github.com/DietrichGebert/ponytail` as prior art for
`.claude-plugin/` packaging conventions — it demonstrates the manifest shape
but deliberately keeps its own MCP server (`ponytail-mcp/`) *outside* the
plugin manifest, as a fully separate, manually-run artifact.

## Guidance

**`.claude-plugin/plugin.json` fields actually verified against official
docs** (not assumed from a single example repo — ponytail's own manifest
omits `mcpServers` entirely, so it could not answer these questions):

- `mcpServers` is a plain object keyed by server name, each value
  `{command, args?, env?}` — the same shape as any MCP client config, not a
  plugin-specific format.
- `${CLAUDE_PLUGIN_ROOT}` resolves to the plugin's install directory and
  substitutes inside `command`/`args`/`env`. It is **not** stable across
  plugin updates (the old directory is kept ~14 days then deleted) — use
  `${CLAUDE_PLUGIN_DATA}` (persists across updates) for anything that needs
  to survive one, e.g. a venv or generated cache.
- There is **no `cwd` field** in the MCP server config schema. To pin a
  command's working directory (e.g. so `uv run` finds `pyproject.toml`),
  either pass `uv run --project ${CLAUDE_PLUGIN_ROOT} <entry-point>` (no cwd
  needed) or point `command` at a wrapper script that `cd`s first.
- `skills/`, `commands/`, `agents/` directories auto-discover with **zero**
  manifest entries when using the default paths — no need to enumerate
  individual skills in `plugin.json`.
- `.claude-plugin/marketplace.json` with a `plugins[].source: "./"` entry
  lets one repo self-host as both marketplace and plugin: `/plugin
  marketplace add <owner>/<repo>` then `/plugin install <plugin>@<marketplace>`
  (as two separate turns/prompts — combining them fails).

**Decision: wire `mcpServers` into the manifest, deviating from the
ponytail precedent.** Ponytail's core value is skill/hook-based instruction
injection, so leaving its MCP server manual is a reasonable default. When the
MCP server itself *is* the product's core value (as here — PyGhidra tools),
`/plugin install` should get the user a working connection in one step, not
just supporting skills.

```json
{
  "name": "agentdecompile",
  "version": "0.1.0",
  "mcpServers": {
    "agentdecompile": {
      "command": "uv",
      "args": ["run", "--project", "${CLAUDE_PLUGIN_ROOT}", "mcp-agentdecompile"]
    }
  }
}
```

**Gitignore trap:** a broad ignore pattern meant for build/output
directories (`agentdecompile*/`, meant to catch things like
`agentdecompile_projects/`) can silently shadow `.claude/skills/` directory
names sharing the same prefix — this repo's pre-existing
`agentdecompile-server-env` skill had *never actually been committed*
because of exactly this collision. Adding new plugin content is a forcing
function to audit `git check-ignore -v` against every new path before
assuming a `git add` succeeded.

## Why This Matters

`/plugin install` unconditionally spawns whatever `mcpServers` declares —
this is real code execution triggered by adding a marketplace source, not a
passive metadata registration. Document the trust assumption explicitly
wherever the install command is described (only add marketplace sources you
trust), since the two-step `/plugin marketplace add` + `/plugin install`
flow makes that spawn easy to trigger without realizing it.

## When to Apply

- Packaging any existing local MCP server (Python/uv, Node, or otherwise)
  for `/plugin install` distribution.
- Any time `.gitignore` patterns are broad glob prefixes (`<name>*/`) in a
  repo that also has `.claude/skills/<name>-*/` directories — check for
  collisions before assuming skill content is tracked.

## Examples

`.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` in this
repo. `.gitignore`'s `!.claude/skills/agentdecompile*/` and
`!.claude/skills/agentdecompile*/**` negation lines are the fix for the
shadowing trap above.

## Related

- `docs/plans/2026-07-29-002-feat-subagent-rewrite-and-plugin-install-plan.md`
  — full design and the external research (Context7 + official Claude Code
  plugin docs) this decision is grounded in.
- `.claude/skills/agentdecompile-server-env/SKILL.md` — documents both the
  manual setup path and the `/plugin install` path side by side.
