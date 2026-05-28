---
title: agentdecompile-cli patterns for headless agents
date: 2026-05-24
category: developer-experience
module: agentdecompile_cli.cli
problem_type: developer_experience
component: development_workflow
severity: medium
applies_when:
  - Automating MCP tool calls via agentdecompile-cli
  - Discovering tool names or piping tool sequences
tags:
  - cli
  - agents
  - tool-seq
---

# agentdecompile-cli patterns for headless agents

## Context

Agents need non-interactive discovery, copy-pasteable `--help` examples, JSON tool lists, and stdin-friendly sequences without shell-quoting large JSON blobs.

## Guidance

Prefer these entry points (see `src/agentdecompile_cli/cli_agent_help.py`):

```bash
agentdecompile-cli -f json tool --list-tools
agentdecompile-cli tool list-functions '{"programPath":"/path/to/binary","limit":5}'
echo '[{"name":"list-project-files","arguments":{}}]' | agentdecompile-cli tool-seq --stdin
agentdecompile-cli tool-seq @/tmp/steps.json
```

Usage errors include example invocations (missing `NAME`, invalid JSON, missing steps).

## Why This Matters

Agents retry often; actionable errors and machine-readable `--list-tools` output reduce failed loops. Pipelines avoid embedding JSON in argv.

## When to Apply

- Documenting CLI workflows in plans or CONTRIBUTING.
- Adding new top-level CLI subcommands — include an **Examples** epilog block.

## Examples

Missing tool name:

```bash
agentdecompile-cli tool
# Error includes: agentdecompile-cli tool --list-tools
```

## Related

- Plan: `docs/plans/2026-05-24-cli-agent-friendly-improvements.md` (completed 2026-05-28)
- Tests: `tests/test_cli_agent_help.py` (12 tests; 124 total in full unit suite)
