---
name: mcp-debugging
description: Investigate and fix MCP server issues (timeouts, schema, GUI/coords, sandbox). Use when debugging MCP servers, self-healing, or when the user mentions MCP Inspector, mcptools, mcp-debug, mcp-trace, FastMCP CLI, or MCP tool/schema problems.
---

# MCP server debugging & self-healing

Use this skill when investigating or fixing MCP server issues: timeouts, schema mismatches, GUI/coords, sandbox, or general tool discovery failures. Follow the meta-debug loop and use the five CLIs (MCP Inspector, mcptools, mcp-debug, mcp-trace, FastMCP CLI) as appropriate.

## When to use

- User or agent is debugging an MCP server (this repo’s or any other).
- Timeouts, missing tools, schema mismatches, or “tool not found” errors.
- Questions about MCP self-healing, workflows, or Claude-specific tool patterns.

## Reference docs (load on demand)

Detail lives in the skill’s `references/` folder. Open when you need step-by-step workflows or tool patterns:

| Doc | Purpose |
|-----|--------|
| [references/CLIS_AND_META_DEBUG.md](references/CLIS_AND_META_DEBUG.md) | Five CLIs (MCP Inspector, mcptools, mcp-debug, mcp-trace, FastMCP CLI) and the meta-debug loop checklist. |
| [references/WORKFLOWS.md](references/WORKFLOWS.md) | Agent behavior, workflows, and checklists for MCP debugging. |
| [references/CLAUDE_MCP_DEBUG.md](references/CLAUDE_MCP_DEBUG.md) | Claude-oriented prompts, tool patterns, and edge cases. |

Read the relevant reference when you need procedures or patterns; keep this SKILL.md as the entry point and navigation.
