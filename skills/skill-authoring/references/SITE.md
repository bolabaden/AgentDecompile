# agentskills.io pages (all of them)

Index: https://agentskills.io/llms.txt

| Page | URL | What we take from it |
|---|---|---|
| Overview | https://agentskills.io/home.md | Skills are portable folders; progressive disclosure |
| Specification | https://agentskills.io/specification.md | `name`, `description`, optional fields, `scripts/` `references/` `assets/` |
| Clients | https://agentskills.io/clients.md | Cursor, VS Code/Copilot, Claude Code, Gemini CLI, OpenCode, OpenHands, others |
| Quickstart | https://agentskills.io/skill-creation/quickstart.md | VS Code discovers `.agents/skills/<name>/SKILL.md`; `/skills` lists them |
| Best practices | https://agentskills.io/skill-creation/best-practices.md | Project-specific gotchas; defaults not menus; keep lean |
| Optimizing descriptions | https://agentskills.io/skill-creation/optimizing-descriptions.md | `Use this skill when…`; trigger evals; train/validation split |
| Evaluating skills | https://agentskills.io/skill-creation/evaluating-skills.md | `evals/evals.json`; with/without skill; assertions |
| Using scripts | https://agentskills.io/skill-creation/using-scripts.md | Bundled `scripts/`; `--help`; no interactive prompts |
| Client implementation | https://agentskills.io/client-implementation/adding-skills-support.md | Scan `.agents/skills/` + client dirs; catalog name+description only |

Example skills (external): https://github.com/anthropics/skills
