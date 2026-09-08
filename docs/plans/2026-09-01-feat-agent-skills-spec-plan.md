# Align AgentDecompile skills with agentskills.io

**Status:** implemented — spec + other agentskills.io pages (quickstart `.agents/skills/`, description evals, `evals/`)  
**Spec:** [Agent Skills Specification](https://agentskills.io/specification)

## Objective

One portable skill tree (`skills/`) that validates against the spec. Cursor and
Claude keep discovery stubs. GitHub Copilot RE agents become wrappers around
the same role skills so Planner/Worker/Critic/Aggregator do not drift.

```mermaid
flowchart TD
  spec[agentskills.io SKILL.md] --> canon[skills/name/SKILL.md]
  canon --> cursor[.cursor/skills stubs]
  canon --> claude[.claude/skills stubs]
  canon --> roles[re-planner re-worker re-critic re-aggregator]
  roles --> copilot[.github/agents wrappers]
```
