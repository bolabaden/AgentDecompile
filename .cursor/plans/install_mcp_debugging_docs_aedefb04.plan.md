---
name: Install MCP debugging docs
overview: Add MCP debugging as a Cursor skill under the canonical project-level skill location (.cursor/skills/), following Cursor docs and plugin layout (SKILL.md + references/), and wire it into AGENTS.md and docs index.
todos: []
isProject: false
---

# Install MCP Debugging Docs (Cursor-idiomatic skill)

## Enhancement Summary

**Deepened on:** 2026-03-11  
**Sections enhanced:** 7 (Why not docs/, Canonical locations, Plugin-style layout, Target structure, Implementation, File summary, Result)  
**Research sources:** Cursor Docs (Agent Skills), MCP official debugging guide, Agent Skills progressive disclosure, MCP Inspector docs.

### Key Improvements

1. **Skill discovery and frontmatter** — Confirmed `name` must match parent folder; `description` is the primary trigger for relevance; optional `compatibility` and `disable-model-invocation` documented.
2. **Progressive disclosure** — References/ pattern aligned with Cursor’s “load on demand” guidance; keep SKILL.md under ~500 lines to reduce token usage.
3. **MCP debugging workflow** — Aligned with official MCP debugging guide: Inspector first, then logs/env, then integration; stderr for server logs, absolute paths for config.
4. **Edge cases** — Working directory and env vars for MCP servers; security (sanitize logs, no secrets); optional scripts/ and assets/ if the skill later adds runnable helpers.

### New Considerations Discovered

- Cursor 2.4+ (Jan 2026) has full Agent Skills support and `/migrate-to-skills`; `.cursor/skills/` is project-level alongside `.agents/skills/`.
- MCP Inspector runs via `npx @modelcontextprotocol/inspector`; default UI port 6274, proxy 6277; supports stdio and remote servers.
- Official MCP debugging best practice: “Test with Inspector first,” then Claude Desktop/logs; use absolute paths and explicit `env` in config.

---

## Why not docs/mcp-debugging/

**docs/mcp-debugging/** is not a canonical or idiomatic location for agent skills. Cursor (and the Agent Skills standard) discover skills only from designated skill directories.

### Canonical skill locations (Cursor docs, 2025–2026)


| Location              | Scope                         |
| --------------------- | ----------------------------- |
| `**.cursor/skills/`** | Project-level (Cursor native) |
| `**.agents/skills/`** | Project-level                 |
| `~/.cursor/skills/`   | User-level (global)           |


Compatibility-only (not preferred for new project skills): `.claude/skills/`, `.codex/skills/`, and their user-level counterparts.

**Source:** [Cursor Docs – Agent Skills](https://cursor.com/docs/skills): *"Skills are automatically loaded from these locations"*; *"Each skill should be a folder containing a SKILL.md file"*; optional `scripts/`, `references/`, `assets/`.

### Repo convention

This repo already uses `**.cursor/`** (plans, hooks, mcp.json, settings). Putting the MCP debugging skill under `**.cursor/skills/`** keeps all Cursor project config in one place and matches Cursor’s native project-level location.

### Research Insights

**Best practices:**

- Cursor loads skills from `.agents/skills/`, `.cursor/skills/`, and `~/.cursor/skills/`; compatibility paths include `.claude/skills/` and `.codex/skills/` but are not preferred for new project skills. ([Cursor Docs – Agent Skills](https://cursor.com/docs/skills))
- Skill folder name should match the `name` in SKILL.md frontmatter (lowercase, numbers, hyphens only) for consistent discovery.

**References:**

- [Agent Skills  Cursor Docs](https://cursor.com/docs/skills) — skill directories, SKILL.md format, optional scripts/references/assets.

---

## Plugin-style layout (aligned with C:\Users\bodencursor\plugins)

Plugins under `C:\Users\boden\.cursor\plugins\cache\cursor-public\`* use:

- **skills/** — one folder per skill: `skills/<skill-name>/SKILL.md`, with optional **references/** (and sometimes scripts/, assets/) beside or under the skill folder.
- **SKILL.md** — entry point with frontmatter (`name`, `description`) and concise body; links to references for detail.
- **references/** — long-form docs loaded on demand (progressive disclosure).

We implement the same pattern in the repo: one skill folder under `.cursor/skills/` with `SKILL.md` and `references/`.

### Research Insights

**Progressive disclosure:**

- Cursor loads resources on demand; keeping SKILL.md focused and moving long-form content to `references/` reduces token usage. (“References/ — Additional documentation loaded on demand.”)
- The **description** field in frontmatter drives relevance; include trigger keywords (e.g. “MCP server issues, timeouts, schema”) so the agent invokes the skill when appropriate without loading full reference content first.

**Optional directories (per Cursor docs):**


| Directory     | Purpose                                   |
| ------------- | ----------------------------------------- |
| `scripts/`    | Executable code agents can run            |
| `references/` | Additional documentation loaded on demand |
| `assets/`     | Static resources (templates, images)      |


**References:**

- [Cursor Docs – Agent Skills](https://cursor.com/docs/skills) — optional directories, progressive loading.
- Progressive disclosure pattern can significantly reduce per-invocation tokens when detail lives in references.

---

## Target structure

```
.cursor/
└── skills/
    └── mcp-debugging/
        ├── SKILL.md              # Entry point (name, description, when to use, links)
        └── references/
            ├── CLIS_AND_META_DEBUG.md   # 5 CLIs + meta-debug loop (ex-SKILLS.md)
            ├── WORKFLOWS.md             # Behavior, workflows, checklists (ex-AGENTS workflow doc)
            └── CLAUDE_MCP_DEBUG.md      # Claude prompts, tool patterns, edge cases (ex-CLAUDE-MCP-DEBUG)
```

- **SKILL.md**: Short description, “when to use,” and links to the three reference files. Frontmatter: `name: mcp-debugging`, `description` with trigger keywords (MCP server issues, timeouts, schema, GUI/coords, sandbox, self-healing).
- **references/**: Use the exact markdown content you provided for each of the three source docs (only filenames normalized: no `docs/mcp-debugging/` path).

### Research Insights

**Frontmatter requirements (Cursor):**

- **name** (required): Skill identifier; lowercase letters, numbers, hyphens only; must match parent folder name (e.g. `mcp-debugging`).
- **description** (required): What the skill does and when to use it; used by the agent to determine relevance. Include trigger phrases: “MCP server issues,” “timeouts,” “schema,” “GUI/coords,” “sandbox,” “self-healing.”
- **Optional:** `compatibility` (environment requirements), `license`, `metadata`, `disable-model-invocation: true` (slash-only, no auto-apply).

**References:**

- [Cursor Docs – SKILL.md file format](https://cursor.com/docs/skills#skillmd-file-format).

---

## Implementation

### 1. Create skill directory and entry point

- **Path:** `.cursor/skills/mcp-debugging/SKILL.md`
- **Content:** YAML frontmatter (name, description) + short body that:
  - States when to use the skill (investigating/fixing MCP server issues: timeouts, schema, GUI/coords, sandbox).
  - Points to the meta-debug loop and the five CLIs (MCP Inspector, mcptools, mcp-debug, mcp-trace, FastMCP CLI).
  - Links to:
    - [references/CLIS_AND_META_DEBUG.md](references/CLIS_AND_META_DEBUG.md)
    - [references/WORKFLOWS.md](references/WORKFLOWS.md)
    - [references/CLAUDE_MCP_DEBUG.md](references/CLAUDE_MCP_DEBUG.md)
- Keep SKILL.md under ~500 lines; no duplicate of the long reference content.

### 2. Create references (exact body text from your three docs)


| File                                                             | Content source                                             |
| ---------------------------------------------------------------- | ---------------------------------------------------------- |
| `.cursor/skills/mcp-debugging/references/CLIS_AND_META_DEBUG.md` | Your SKILLS.md (5 CLIs, meta-debug loop, checklist)        |
| `.cursor/skills/mcp-debugging/references/WORKFLOWS.md`           | Your AGENTS.md (behavior, workflows, checklists)           |
| `.cursor/skills/mcp-debugging/references/CLAUDE_MCP_DEBUG.md`    | Your CLAUDE.md (Claude prompts, tool patterns, edge cases) |


No edits to body text; only path/location change from the original plan.

### 3. Extend root AGENTS.md

Add a section (e.g. after “Learned Workspace Facts” or “Naming Conventions”):

- **Heading:** `## MCP server debugging & self-healing`
- **Body:** When investigating or fixing MCP server issues (timeouts, schema, GUI/coords, sandbox), use the **mcp-debugging** skill: open `.cursor/skills/mcp-debugging/SKILL.md` or invoke `/mcp-debugging` in Agent chat. The skill references the meta-debug loop and the five CLIs (MCP Inspector, mcptools, mcp-debug, mcp-trace, FastMCP CLI).
- **Links:** Point to:
  - `.cursor/skills/mcp-debugging/SKILL.md` (entry point)
  - Optionally list the three reference paths for direct opening.

This keeps a single AGENTS.md while making the skill discoverable from the main agent instructions.

### 4. Update docs/INDEX.md

- Under “Internal and contributor docs” (or a new “Agent skills” / “MCP debugging” block), add:
  - **MCP debugging (agent skill):** `.cursor/skills/mcp-debugging/` — MCP debug CLIs, meta-debug loop, workflows, and Claude-oriented prompts; invoke via `/mcp-debugging` or from AGENTS.md.
- Optional: in “Quick navigation,” one line: “Debugging MCP servers / self-healing: use skill `/mcp-debugging` or open `.cursor/skills/mcp-debugging/`.”

### Research Insights (Implementation)

**MCP debugging workflow (official guidance):**

- Test with **MCP Inspector** first (`npx @modelcontextprotocol/inspector`); default UI port 6274, proxy 6277; supports stdio and remote servers.
- Then use Claude Desktop / Cursor logs; server logs typically on **stderr**; use **absolute paths** and explicit **env** in MCP config to avoid working-directory and env issues.

**Edge cases:**

- Working directory and env vars affect MCP server startup; document in references that config should use absolute paths and explicit `env` where needed.
- Security: sanitize logs before sharing; no secrets in skill content or examples.

**References:**

- [MCP debugging guide](https://modelcontextprotocol.io/docs/concepts/debugging) — Inspector first, then logs and integration.
- Cursor 2.4+ (Jan 2026): full Agent Skills support; `/migrate-to-skills` for migrating from older layouts.

---

## File summary


| Action | Path                                                             |
| ------ | ---------------------------------------------------------------- |
| Create | `.cursor/skills/mcp-debugging/SKILL.md`                          |
| Create | `.cursor/skills/mcp-debugging/references/CLIS_AND_META_DEBUG.md` |
| Create | `.cursor/skills/mcp-debugging/references/WORKFLOWS.md`           |
| Create | `.cursor/skills/mcp-debugging/references/CLAUDE_MCP_DEBUG.md`    |
| Edit   | `AGENTS.md` — add MCP debugging section + link to skill          |
| Edit   | `docs/INDEX.md` — add skill entry + optional quick-nav line      |


**Do not create** `docs/mcp-debugging/`; skills live under `.cursor/skills/` per Cursor and plugin convention.

### Research Insights

**Quality checks:**

- Verify SKILL.md frontmatter `name` matches folder name (`mcp-debugging`); invalid names can prevent discovery.
- After creating files, confirm Cursor shows the skill in the skills list or via `/mcp-debugging` (Cursor 2.4+).

---

## Result

- Cursor discovers the skill automatically from `.cursor/skills/mcp-debugging/`; agents can use it by relevance or via `/mcp-debugging`.
- Structure matches Cursor docs (skill directory + SKILL.md + references/) and plugin layout (skills/…/SKILL.md + references/).
- AGENTS.md and docs/INDEX.md point to the skill; existing AGENTS.md and src/CLAUDE.md remain the single source of project rules and architecture.

### Research Insights

**Success criteria:**

- Skill appears in Cursor’s skill list and is invokable by description match or slash command.
- Reference links from SKILL.md resolve when opened in the editor (relative paths from skill folder).
- No duplicate long-form content in SKILL.md; all detail in `references/` for progressive loading.

---

## Skills applied (mcp-builder, writing-skills, writing-plans, skill-creator)

**mcp-builder:** This plan does not build an MCP server; it installs debugging *documentation* as a skill. When building or shipping MCP servers, use the mcp-builder skill (transport, tools, auth, test with MCP Inspector). The content of this skill aligns with MCP quality practice: “Test with Inspector first,” then logs/env; references document the five CLIs and meta-debug loop.

**writing-skills:** Skill description uses “Use when…” only (triggers/symptoms); no workflow summary in the description so the agent loads and follows the full SKILL.md. Verification: run a pressure scenario (e.g. “MCP tool not found”) without the skill to establish baseline, then with the skill to confirm compliance; refine description or body if the agent skips the skill or the references.

**writing-plans:** Execution is broken into bite-sized tasks below for use with executing-plans. Plan location is `.cursor/plans/` (project convention); writing-plans often uses `docs/plans/`—either is valid. Required execution header and task list added for subagent-driven or parallel execution.

**skill-creator:** Skill uses progressive disclosure (SKILL.md entry point, detail in `references/`); SKILL.md written in imperative/infinitive form; references are the single source of detail (no duplication in SKILL.md). No `scripts/` or `assets/` in this skill; add only if runnable helpers or templates are needed later.

---

## Execution plan (writing-plans format)

> **For Claude:** When implementing or re-executing this plan task-by-task, use **superpowers:executing-plans** (or **subagent-driven-development** in-session).

**Goal:** Add MCP debugging as a Cursor skill under `.cursor/skills/mcp-debugging/` and wire it into AGENTS.md and docs/INDEX.md.

**Architecture:** One skill folder (SKILL.md + references/), no `docs/mcp-debugging/`; Cursor discovers from `.cursor/skills/`.

---

### Task 1: Create skill directory and SKILL.md

**Files:**

- Create: `.cursor/skills/mcp-debugging/SKILL.md`

**Steps:**

1. Create directory `.cursor/skills/mcp-debugging/`.
2. Add SKILL.md with frontmatter `name: mcp-debugging` and description starting with “Use when…” (triggers only; no workflow in description).
3. Add body: When to use, Quick start (3 steps), Reference docs table linking to `references/CLIS_AND_META_DEBUG.md`, `references/WORKFLOWS.md`, `references/CLAUDE_MCP_DEBUG.md`. Keep under ~500 lines.
4. Commit: `git add .cursor/skills/mcp-debugging/SKILL.md && git commit -m "feat(skills): add mcp-debugging skill entry point"`

### Task 2: Create reference files

**Files:**

- Create: `.cursor/skills/mcp-debugging/references/CLIS_AND_META_DEBUG.md`
- Create: `.cursor/skills/mcp-debugging/references/WORKFLOWS.md`
- Create: `.cursor/skills/mcp-debugging/references/CLAUDE_MCP_DEBUG.md`

**Steps:**

1. Populate each file with the planned content (5 CLIs + meta-debug loop; behavior/workflows/checklists; Claude prompts/tool patterns/edge cases).
2. Commit: `git add .cursor/skills/mcp-debugging/references/ && git commit -m "feat(skills): add mcp-debugging reference docs"`

### Task 3: Extend AGENTS.md

**Files:**

- Modify: `AGENTS.md` (add section after “Learned Workspace Facts” or “Naming Conventions”)

**Steps:**

1. Add heading `## MCP server debugging & self-healing`.
2. Add body: when to use the skill, link to `.cursor/skills/mcp-debugging/SKILL.md`, optional links to the three reference paths.
3. Commit: `git add AGENTS.md && git commit -m "docs(AGENTS): add MCP debugging skill section"`

### Task 4: Update docs/INDEX.md

**Files:**

- Modify: `docs/INDEX.md`

**Steps:**

1. Under “Internal and contributor docs,” add “MCP debugging (agent skill)” with path `.cursor/skills/mcp-debugging/` and invoke hint (`/mcp-debugging` or AGENTS.md).
2. Optionally add one line to “Quick navigation” for debugging MCP / self-healing.
3. Commit: `git add docs/INDEX.md && git commit -m "docs(INDEX): add mcp-debugging skill to index"`

---

## References (research used)

- [Cursor Docs – Agent Skills](https://cursor.com/docs/skills): skill directories, SKILL.md format, optional scripts/references/assets.
- Create-agent-skills skill (Compound Engineering): `.claude/skills/` vs commands; SKILL.md frontmatter; progressive disclosure; references one level from SKILL.md.
- Web search: Cursor project-level skills use `.cursor/skills/` or `.agents/skills/`; `.cursor/skills/` recommended for Cursor projects (2025–2026).
- Plugin layout at `C:\Users\boden\.cursor\plugins\cache\cursor-public\`*: skills in `skills/<name>/SKILL.md` with `references/` (e.g. runlayer, compound-engineering, superpowers).
- **Skills applied on this plan:** mcp-builder (scope: docs vs server build; Inspector-first alignment), writing-skills (description = Use when only; verification), writing-plans (execution header + bite-sized tasks), skill-creator (progressive disclosure, imperative body, no duplication).

