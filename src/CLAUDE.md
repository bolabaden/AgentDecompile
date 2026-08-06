# CLAUDE.md - Source Directory Overview

This file provides guidance for Claude Code when working with the AgentDecompile source code. This is the top-level documentation for the `src/` directory structure.

## Quick Reference

| Item | Value |
|------|-------|
| **Implementation Language** | Python 3.10+ |
| **MCP SDK Version** | `mcp>=1.26.0` |
| **PyGhidra Version** | `pyghidra>=3.0.2` |
| **Ghidra Version** | 12.0 or higher |
| **Primary Test Framework** | pytest |
| **Test Command** | `uv run pytest` |
| **Development Setup** | `uv` (Python environment manager) |

## Python Entry Point and Connection Flow

- **Entry point:** `mcp-agentdecompile` → `agentdecompile_cli.__main__:main` (see `pyproject.toml`)
- **Startup:** Initialize PyGhidra, create ProjectManager, setup MCP server
- **Communication:** MCP server exposes tools via stdio or HTTP bridge, depending on connection mode

## Testing Guidelines

### Test Types and Locations

| Test Type | Location | Requirements | Command |
|-----------|----------|--------------|---------|
| Unit Tests | `tests/` (marker: `unit`) | Mocked PyGhidra | `uv run pytest -m unit` |
| Integration Tests | `tests/` (marker: `integration`) | PyGhidra available | `uv run pytest -m integration` |
| E2E Tests | `tests/` (marker: `e2e`) | Full CLI subprocess | `uv run pytest -m e2e` |
| All Tests | `tests/` | Full environment | `uv run pytest` |

### Test Structure

- **conftest.py** - Shared pytest fixtures
- **helpers.py** - Test utility functions
- **test_*.py** - Feature-specific test modules (providers, CLI, workflows, e2e)

### Testing Best Practices

- Always validate actual Ghidra program state changes, not just MCP responses
- Use assertions to verify that operations persisted to the program database
- Clean up temporary projects/files after tests complete
- Mark slow tests with `@pytest.mark.slow` to allow optional skipping

## Troubleshooting

### Common Issues

| Problem | Solution |
|---------|----------|
| PyGhidra import fails | Ensure Ghidra is installed; set `GHIDRA_INSTALL_DIR` |
| Tool not found | Check normalization: `normalize_identifier('tool-name')` should resolve |
| Test failures | Run `uv run pytest -v` for detailed output; check markers |
| Port already in use | Change `port` or kill process on port: `lsof -ti:PORT \| xargs kill` |

## Related Documentation

- [TOOLS_LIST.md](../TOOLS_LIST.md) - Canonical tool specifications
- [vendor/](../vendor/) - Third-party tool source code references
- [../tests/README.md](../tests/README.md) - Testing guide
- [agentdecompile_cli/CLAUDE.md](agentdecompile_cli/CLAUDE.md) - MCP tool-routing/normalization contract, provider authoring rules, and Ghidra/MCP-specific gotchas
