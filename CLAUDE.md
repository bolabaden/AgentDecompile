# CLAUDE.md

This file provides guidance to Claude, GitHub Copilot, and other AI agents when working with the AgentDecompile codebase.

## Project Overview

**AgentDecompile** is a Ghidra extension that turns Ghidra into an AI-powered reverse engineering platform. It uses the Model Context Protocol (MCP) to let AI models "see" and "control" Ghidra.

## Build and Test Commands

### Java Extension (Ghidra Plugin)
```bash
# Set Ghidra installation directory first
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Build the extension
gradle

# Install directly to Ghidra's extension directory
gradle install

# Java unit tests (no Ghidra environment)
gradle test --info

# Integration tests (require GUI/headed environment, fork=1)
gradle integrationTest --info
```

**Important**: Use gradle directly, NOT gradle wrapper ("./gradlew").

### Python CLI and Tests
```bash
# Setup Python environment with uv
uv sync

# Run all Python tests
uv run pytest
```

## Environment Variables and End-User Behavior

End-user configuration is documented in [README.md](README.md). Summary for context when editing code:

- **Connection/project:** `GHIDRA_INSTALL_DIR`, `AGENT_DECOMPILE_PROJECT_PATH`. For shared projects: `AGENT_DECOMPILE_SERVER_USERNAME`, `AGENT_DECOMPILE_SERVER_PASSWORD`, `AGENT_DECOMPILE_SERVER_HOST`, `AGENT_DECOMPILE_SERVER_PORT`.
- **Intelligent features** (env only, no tool params): `AGENT_DECOMPILE_AUTO_LABEL` (default true), `AGENT_DECOMPILE_AUTO_TAG` (default true), `AGENT_DECOMPILE_AUTO_BOOKMARK_PERCENTILE` (default 97.0, range 95–99). Auto-bookmarking runs from get-functions and manage-comments; auto-tag/label/comment from manage-function, manage-symbols, manage-comments when values are not provided.
- **Project locking:** `AGENT_DECOMPILE_FORCE_IGNORE_LOCK` or `open` tool `forceIgnoreLock`—risky; deletes lock files. User-facing options and error text are in README.
- **Structures:** `manage-structures` `add_field` uses `useReplace` default true and optional `preserveSize`; user-facing options and FAQ in README, implementation in CONTRIBUTING.

## Code Guidelines

- **Package Name**: "agentdecompile" (Python package: `agentdecompile_cli`; Java: `agentdecompile`).
- **Core Logic**: Java in "src/main/java/agentdecompile" (server, headless, tools, resources, plugin, util, ui). Python CLI in "src/agentdecompile_cli" (stdio bridge, launcher, project_manager); entry point `mcp-agentdecompile` proxies stdio to Java MCP server at `http://localhost:{port}/mcp/message`.
- **Testing**: Use "AddressUtil" for address normalization. Always wrap DB changes in transactions.
- **License**: Business Source License 1.1.

## Batch Operation Pattern

Several MCP tools support batch operations to improve efficiency when performing multiple similar actions:

### Tools with Batch Support
- **manage-structures** `add_field` action - Add multiple fields using `fields` array parameter
- **manage-structures** `apply` action - Apply structure to multiple addresses using array in `addressOrSymbol`
- **manage-comments** `set` action - Set multiple comments using `comments` array parameter

### Implementation Pattern
When adding batch support to tools:
1. Accept either single parameter OR array parameter
2. Use `getParameterAsList()` to detect batch mode automatically
3. Process all items in a single transaction for atomicity
4. Return detailed results with per-item status (success/failure counts, results array, errors array)
5. Maintain full backwards compatibility with single-item syntax

Example batch detection:
```java
List<Object> itemsList = getParameterAsList(request.arguments(), "items");
if (!itemsList.isEmpty() && itemsList.get(0) instanceof Map) {
    return handleBatchOperation(program, request, itemsList);
}
// Fall through to single-item mode for backwards compatibility
```

See `StructureToolProvider.handleBatchAddFields()` for a complete implementation example.
