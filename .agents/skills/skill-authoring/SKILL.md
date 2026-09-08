---
name: skill-authoring
description: "Use this skill when adding, editing, or reviewing AgentDecompile skills or subagents. Apply even if the user only pastes agentskills.io or says skills feel unused. Follow the whole site, not only the specification page."
license: AGPL-3.0-or-later
metadata:
  author: AgentDecompile
  version: "1.0"
  spec-index: https://agentskills.io/llms.txt
---

# Author AgentDecompile skills

Read [references/SITE.md](references/SITE.md) for every agentskills.io page. Do not stop at the specification.

## Available scripts

- **`scripts/check-evals.py`** — Validate `evals/evals.json` and `evals/triggers.json` (no LLM). `--help` for flags.
- Repo **`scripts/validate-agent-skills.py`** — Frontmatter + directory name + description prefix.

```bash
python3 scripts/check-evals.py
python3 ../../scripts/validate-agent-skills.py
```

Paths in this skill are relative to the skill directory except the repo validator.

## Where skills live

| Path | Why |
|---|---|
| `.agents/skills/<name>/` | VS Code / Copilot default ([quickstart](https://agentskills.io/skill-creation/quickstart.md)); cross-client scan path ([client implementation](https://agentskills.io/client-implementation/adding-skills-support.md)) |
| `skills/<name>/` | Same files; human + git-friendly canonical copy |
| `.cursor/skills/`, `.claude/skills/` | Client-native stubs; same `name`/`description`, then Read the canonical `SKILL.md` |

Project skills override user skills. `name` must match the folder.

## Description (triggering)

From [optimizing descriptions](https://agentskills.io/skill-creation/optimizing-descriptions.md):

1. Imperative: start with `Use this skill when…`
2. User intent, not internals
3. List contexts even when they do not name the domain
4. ≤ 1024 characters; quote the YAML value if it contains `:`
5. Keep `evals/triggers.json` (should_trigger true/false, train vs validation)

Do not pack the whole workflow into the description — the body loads only after activation.

## Body and resources

- Keep `SKILL.md` under ~500 lines / 5k tokens. Point at `references/` and `scripts/` when needed.
- Scripts: no TTY prompts, `--help`, structured stdout, errors on stderr ([using scripts](https://agentskills.io/skill-creation/using-scripts.md)). Prefer `uv run` / existing repo tools.
- Output quality: `evals/evals.json` with prompt, expected_output, assertions ([evaluating skills](https://agentskills.io/skill-creation/evaluating-skills.md)).

## Subagents

Copilot `.github/agents/*.agent.md` may keep Copilot-only keys (`tools`, `agents`). The procedure lives in `skills/re-*/SKILL.md`. Edit the skill; keep the agent as a loader.
