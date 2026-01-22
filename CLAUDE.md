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
