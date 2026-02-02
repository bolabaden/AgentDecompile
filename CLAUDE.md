# CLAUDE.md

This file provides guidance to Claude, GitHub Copilot, and other AI agents when working with the AgentDecompile codebase.

## Project Overview

**AgentDecompile** is a Ghidra extension that turns Ghidra into an AI-powered reverse engineering platform. It uses the Model Context Protocol (MCP) to let AI models "see" and "control" Ghidra.

## Build and Test Commands

### Java Extension (Ghidra Plugin)
`ash
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
`

**Important**: Use gradle directly, NOT gradle wrapper ("./gradlew").

### Python CLI and Tests
`ash
# Setup Python environment with uv
uv sync

# Run all Python tests
uv run pytest
`

## Code Guidelines

- **Package Name**: "agentdecompile" (previously "agentdecompile", being migrated).
- **Core Logic**: Logic resides in "src/main/java/agentdecompile".
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
