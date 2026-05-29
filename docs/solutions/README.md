# Documented solutions

Searchable institutional learnings from solved problems in AgentDecompile. Each file uses YAML frontmatter (`module`, `problem_type`, `component`, `tags`) for filtering.

## Categories

| Directory | problem_type examples |
|-----------|---------------------|
| `integration-issues/` | MCP session, Ghidra import, tool dispatch |
| `architecture-patterns/` | Coordinators, locking, fail-closed behavior, **tiered RE tool routing**, **capabilities MCP resource** (`capabilities-mcp-resource.md`, `tiered-re-analysis-routing.md`, `tiered-re-analysis-knowledgebase.md`) |
| `developer-experience/` | CLI ergonomics for agents |
| `logic-errors/` | Incorrect flags or state before analysis |
| `workflow-issues/` | LFG, shared Ghidra server, check-in |
| `best-practices/` | Conventions and tooling decisions |

Run `ce-compound` after solving a non-trivial problem to add a learning. Run `ce-compound-refresh` periodically to keep docs aligned with the codebase.

Validate new frontmatter:

```bash
python3 scripts/validate-frontmatter.py docs/solutions/<category>/<file>.md
```
