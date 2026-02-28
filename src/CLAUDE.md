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

## Directory Structure

```
src/
├── agentdecompile_cli/              # Python CLI package (authoritative implementation)
│   ├── __init__.py                  # Package initialization, version
│   ├── __main__.py                  # Entry point: `mcp-agentdecompile` command
│   ├── launcher.py                  # Wraps Ghidra/PyGhidra initialization
│   ├── mcp_server/                  # MCP server implementation
│   │   ├── server.py                # MCP server (FastAPI + MCP SDK)
│   │   ├── tool_providers.py        # ToolProvider base class + ToolProviderManager
│   │   └── providers/               # Tool provider implementations (19 files)
│   ├── mcp_utils/                   # Shared utilities for Ghidra API access
│   ├── tools/                       # GhidraTools wrapper class
│   ├── registry.py                  # Tool registry, normalize_identifier()
│   ├── executor.py                  # CLI utilities, DynamicToolExecutor
│   ├── utils.py                     # Re-exports, backward compatibility
│   ├── bridge.py                    # MCP stdio ↔ HTTP bridge
│   ├── stdio_bridge.py              # Standard input/output bridge
│   ├── context.py                   # Session context management
│   ├── mcp_session_patch.py         # Patches for MCP SDK compatibility
│   └── _version.py                  # Version from git tags (setuptools_scm)
└── CLAUDE.md                        # This file
```

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

### Running Tests

```bash
# Run all tests
uv run pytest

# Run only unit tests (no Ghidra required)
uv run pytest -m unit

# Run integration tests
uv run pytest -m integration

# Run with verbose output
uv run pytest -v

# Run specific test file
uv run pytest tests/test_provider_symbols.py

# Run with coverage
uv run pytest --cov=src/agentdecompile_cli
```

### Test Structure

- **conftest.py** - Shared pytest fixtures
- **helpers.py** - Test utility functions
- **test_*.py** - Feature-specific test modules (providers, CLI, workflows, normalization)

### Testing Best Practices

- Always validate actual Ghidra program state changes, not just MCP responses
- Use assertions to verify that operations persisted to the program database
- Clean up temporary projects/files after tests complete
- Mark slow tests with `@pytest.mark.slow` to allow optional skipping

## Key Modules

### `mcp_server/tool_providers.py`

- **ToolProvider** - Base class for all tool implementations
- **ToolProviderManager** - Centralized tool registry and dispatch
- Normalization contract: `normalize_identifier()` accepts any variant (case-insensitive, ignores separators)

### `mcp_server/providers/`

19 tool provider implementations across functional domains:
- **symbols.py** - Symbol management tools
- **functions.py** - Function analysis tools  
- **memory.py** - Memory inspection and data type tools
- **callgraph.py** - Control flow and cross-reference analysis
- **comments.py** - Comments and annotations
- **bookmarks.py** - Bookmarks management
- **project.py** - Project and file management
- And 12 more...

### `tools/wrappers.py`

- **GhidraTools** - Wrapper class providing comprehensive Ghidra API access
- Methods for function analysis, memory access, symbol manipulation, etc.

### `registry.py`

- **normalize_identifier()** - Converts any identifier format to normalized form (alpha-only, lowercase)
- **to_snake_case()** - Converts identifiers to snake_case for display
- Tool registry and canonical tool list

## Normalization Contract

**Advertisement Layer (User-Facing):**
- Tool names: Advertise in `snake_case` (e.g., `manage_symbols`)
- Parameter names: Advertise in `snake_case` (e.g., `program_path`)

**Execution Layer (Internal):**
- Tool and parameter matching: ALWAYS accepts ANY variant as long as alphabetic characters match (case-insensitive)
- Normalization: `normalize_identifier(s)` = `re.sub(r"[^a-z]", "", s.lower().strip())`
- Examples:
  - Tool names: `manage-symbols`, `Manage_Symbols`, `MANAGESYMBOLS`, `@@manage symbols@@` → all resolve to `managesymbols`
  - Arguments: `programPath`, `program_path`, `PROGRAM PATH`, `__program-path__` → all resolve to `programpath`

## Tool Implementation Patterns

### Adding a New Tool

1. Create provider class extending `ToolProvider`
2. Define `HANDLERS` dict mapping normalized tool names to handler functions
3. Use `self._get()` helpers for normalized argument access
4. Return structured responses matching `ToolResponse` schema

### Example Pattern

```python
class MyToolProvider(ToolProvider):
    HANDLERS = {
        'mytool': 'handle_my_tool',
    }
    
    def handle_my_tool(self, args: Dict[str, Any]) -> Dict[str, Any]:
        program = self._get_program(args)
        mode = self._get_optional_string(args, 'mode', 'default')
        count = self._get_optional_int(args, 'count', 10)
        
        # Implementation here
        return self.success({
            'result': 'data',
            'count': count
        })
```

### Using Ghidra APIs

Access Ghidra functionality through `GhidraTools`:

```python
from agentdecompile_cli.tools.wrappers import GhidraTools

tools = GhidraTools(program)
functions = tools.get_functions()
for func in functions:
    print(f"Function: {func.getName()}")
```

## Common Patterns

### Error Handling

```python
try:
    program = self._get_program(args)
    if not program:
        return self.error("Program not found")
    # Process...
    return self.success(result)
except Exception as e:
    return self.error(f"Operation failed: {str(e)}")
```

### Address Formatting

Use consistent address formatting in responses:

```python
address_str = f"0x{address.getOffset():x}"
# Or use helper if available
```

## Command-Line Usage

```bash
# Start MCP server (stdio mode)
mcp-agentdecompile

# Start with custom project path
AGENT_DECOMPILE_PROJECT_PATH=/path/to/project mcp-agentdecompile

# Run tests
uv run pytest

# Build distribution
uv build
```

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
