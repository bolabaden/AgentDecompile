# AgentDecompile Developer Guide

## Overview

**AgentDecompile** is a Ghidra extension that connects Ghidra to AI models via the Model Context Protocol (MCP). It exposes tools like the decompiler, symbol table, and memory viewer as "tools" that LLMs can call.

Use this guide when writing code for AgentDecompile.

---

## Build & Test

### Building
```bash
# Set Ghidra path
export GHIDRA_INSTALL_DIR=/path/to/ghidra
# Build the extension
gradle
```

### Testing
- **Unit Tests**: `gradle test` (Fast, no Ghidra instance)
- **Integration Tests**: `gradle integrationTest` (Slow, spins up Ghidra)
- **Run All**: `gradle check`

---

## Code Structure

- `src/main/java/agentdecompile/` - Main source
  - `tools/` - The "Skills" given to the AI (Decompiler, Symbol Manager, etc.)
  - `server/` - The MCP Server implementation
  - `plugin/` - Ghidra integration logic
  - `util/` - Helpers for Addresses, Programs, etc.
- `src/test/` - Unit tests
- `src/test.slow/` - Integration tests

---

## Coding Standards

### Java
- **Version**: Java 21
- **Style**: 4 spaces, no tabs.
- **Naming**: `PascalCase` classes, `camelCase` methods.
- **Docs**: Javadoc required on public methods.

### Error Handling
- Never crash the server on bad input.
- Return structured JSON errors: `{"success":false, "error":"message"}`.
- Log stacks to `DebugLogger` for debugging, but don't show stack traces to the LLM unless necessary.

### Best Practices
- **Transactions**: ALWAYS wrap write operations (renaming, commenting) in a Ghidra Transaction.
- **Program Identity**: Use `ProgramLookupUtil` to ensure you're acting on the correct open binary.
- **Addresses**: Use `AddressUtil` to normalize handling of memory addresses.

---

## Testing Guidelines
- **Unit Tests**: Test logic in isolation. Mock Ghidra classes if needed.
- **Integration Tests**: Verify the tool actually changes Ghidra state (e.g., did the variable name actually change in the DB?).
- **Headless**: Integration tests run in headless mode but require a valid display configuration or `java.awt.headless=false`.

---

## Tools & Resources
- **MCP SDK**: We use the official Java MCP SDK.
- **Ghidra API**: Use `FlatProgramAPI` where possible for simplicity.
